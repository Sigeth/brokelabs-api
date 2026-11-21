//! Single sign-on with an OpenID Connect provider: authorization code flow
//! with PKCE. Accounts are matched by issuer and subject and created at the
//! first sign-in (D55).

use std::time::{Duration, Instant};

use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::url::form_urlencoded;
use openidconnect::{
    AsyncHttpClient, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, HttpClientError, HttpRequest, HttpResponse, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use tokio::sync::RwLock;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::app::AppState;
use crate::auth::{self, ADMIN_ROLE, STUDENT_ROLE, TEACHER_ROLE};
use crate::config::OidcConfig;
use crate::db;
use crate::error::ApiError;

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(oidc_login))
        .routes(routes!(oidc_callback))
}

/// Path of the callback, under the public URL.
const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";
/// Cookie binding a sign-in to the browser that started it (login CSRF).
/// SameSite=Lax: the provider sends the browser back with a cross-site
/// navigation, which carries Lax cookies but not Strict ones.
const STATE_COOKIE: &str = "brokelabs_oidc";
/// How long a sign-in may take at the provider.
const LOGIN_TTL: time::Duration = time::Duration::minutes(10);
/// Provider metadata and keys are fetched again after this, so rotated
/// signing keys are picked up.
const METADATA_TTL: Duration = Duration::from_secs(600);
/// Longest `next` path kept across a sign-in.
const MAX_NEXT_LENGTH: usize = 512;

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// The configured provider, its metadata fetched on first use.
pub struct Oidc {
    pub config: OidcConfig,
    redirect: RedirectUrl,
    http: ProviderHttp,
    metadata: RwLock<Option<(Instant, CoreProviderMetadata)>>,
}

/// Who the provider says signed in.
#[derive(Debug, PartialEq)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    /// preferred_username, else the email.
    pub username_hint: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
}

impl Oidc {
    pub fn new(config: &OidcConfig, public_url: &str) -> anyhow::Result<Self> {
        // No redirects: the provider's endpoints are used as published (SSRF).
        let mut http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15));
        if let Some(path) = &config.ca_file {
            let pem = std::fs::read(path)
                .with_context(|| format!("reading the OIDC CA file {}", path.display()))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)
                .with_context(|| format!("parsing the OIDC CA file {}", path.display()))?
            {
                http = http.add_root_certificate(cert);
            }
        }
        Ok(Self {
            config: config.clone(),
            redirect: RedirectUrl::new(format!("{public_url}{CALLBACK_PATH}"))?,
            http: ProviderHttp {
                http: http.build()?,
                backchannel: match &config.backchannel_url {
                    None => None,
                    Some(url) => Some((origin(&config.issuer)?, origin(url)?)),
                },
            },
            metadata: RwLock::new(None),
        })
    }

    async fn client(&self) -> anyhow::Result<Client> {
        let cached = self.metadata.read().await.clone();
        let metadata = match cached {
            Some((at, m)) if at.elapsed() < METADATA_TTL => m,
            _ => {
                let issuer = IssuerUrl::new(self.config.issuer.clone())?;
                let m = CoreProviderMetadata::discover_async(issuer, &self.http)
                    .await
                    .with_context(|| format!("discovering {}", self.config.issuer))?;
                *self.metadata.write().await = Some((Instant::now(), m.clone()));
                m
            }
        };
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            self.config.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(self.redirect.clone()))
    }

    /// The provider's authorization URL, with the state, nonce and PKCE
    /// verifier to keep until the callback.
    async fn authorize(&self) -> anyhow::Result<(String, String, String, String)> {
        let client = self.client().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        // "openid" is always requested.
        for scope in self.config.scopes.iter().filter(|s| *s != "openid") {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, state, nonce) = request.url();
        Ok((
            url.to_string(),
            state.secret().clone(),
            nonce.secret().clone(),
            verifier.secret().clone(),
        ))
    }

    /// Exchanges the code and verifies the ID token (signature, issuer,
    /// audience, expiry and nonce).
    async fn identity(&self, code: &str, login: &db::OidcLogin) -> anyhow::Result<Identity> {
        let client = self.client().await?;
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(login.pkce_verifier.clone()))
            .request_async(&self.http)
            .await
            .context("exchanging the authorization code")?;
        let id_token = token
            .id_token()
            .context("the provider returned no ID token")?;
        let claims = id_token
            .claims(
                &client.id_token_verifier(),
                &Nonce::new(login.nonce.clone()),
            )
            .context("verifying the ID token")?;
        // The signature is verified: read the claims the library does not
        // model (groups) from the same token.
        let payload = jwt_payload(&id_token.to_string())?;
        let email = claims.email().map(|e| e.as_str().to_string());
        Ok(Identity {
            issuer: claims.issuer().as_str().to_string(),
            subject: claims.subject().as_str().to_string(),
            username_hint: claims
                .preferred_username()
                .map(|u| u.as_str().to_string())
                .or_else(|| email.clone()),
            name: claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_string()),
            email,
            groups: groups(&payload, &self.config.groups_claim),
        })
    }
}

/// HTTP client of the provider's endpoints, through the back channel when
/// one is configured.
struct ProviderHttp {
    http: reqwest::Client,
    /// Origins (issuer, back channel) when the api reaches the provider at
    /// another address than browsers do.
    backchannel: Option<(String, String)>,
}

impl<'c> AsyncHttpClient<'c> for ProviderHttp {
    type Error = HttpClientError<reqwest::Error>;
    type Future = std::pin::Pin<
        Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>,
    >;

    fn call(&'c self, mut request: HttpRequest) -> Self::Future {
        if let Some((from, to)) = &self.backchannel
            && let Some(uri) = rebase(&request.uri().to_string(), from, to)
            && let Ok(uri) = uri.parse()
        {
            *request.uri_mut() = uri;
        }
        self.http.call(request)
    }
}

/// The origin (scheme, host and port) of a URL.
fn origin(url: &str) -> anyhow::Result<String> {
    let parsed =
        openidconnect::url::Url::parse(url).with_context(|| format!("invalid URL {url:?}"))?;
    match parsed.origin() {
        o @ openidconnect::url::Origin::Tuple(..) => Ok(o.ascii_serialization()),
        _ => anyhow::bail!("{url:?} has no origin"),
    }
}

/// `url` with its origin `from` replaced by `to`, if it has that origin.
fn rebase(url: &str, from: &str, to: &str) -> Option<String> {
    let rest = url.strip_prefix(from)?;
    match rest.is_empty() || rest.starts_with(['/', '?']) {
        true => Some(format!("{to}{rest}")),
        false => None,
    }
}

/// The JSON payload of a compact JWT.
fn jwt_payload(jwt: &str) -> anyhow::Result<serde_json::Value> {
    let part = jwt.split('.').nth(1).context("malformed ID token")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(part.trim_end_matches('='))
        .context("malformed ID token")?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// The groups in a claim (an array of strings, or a single string); dots in
/// the claim name reach nested objects.
fn groups(payload: &serde_json::Value, claim: &str) -> Vec<String> {
    let mut value = payload;
    for key in claim.split('.') {
        match value.get(key) {
            Some(v) => value = v,
            None => return Vec::new(),
        }
    }
    match value {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// The role the provider's groups give, when it manages roles.
pub fn role_for(config: &OidcConfig, groups: &[String]) -> Option<&'static str> {
    if !config.manages_roles() {
        return None;
    }
    let member = |list: &[String]| groups.iter().any(|g| list.contains(g));
    Some(if member(&config.admin_groups) {
        ADMIN_ROLE
    } else if member(&config.teacher_groups) {
        TEACHER_ROLE
    } else {
        STUDENT_ROLE
    })
}

/// A username from the provider's hint, in the local username rules.
fn base_username(hint: Option<&str>) -> String {
    let hint = hint.unwrap_or_default();
    let local = hint.split('@').next().unwrap_or_default().to_lowercase();
    let cleaned: String = local
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '-',
        })
        .collect();
    let trimmed: String = cleaned
        .trim_start_matches(['.', '_', '-'])
        .chars()
        .take(56)
        .collect();
    match trimmed.is_empty() {
        true => "user".into(),
        false => trimmed,
    }
}

/// Where to go after signing in: a local path only (no open redirect).
pub fn safe_next(next: Option<&str>) -> String {
    match next {
        Some(n)
            if n.starts_with('/')
                && !n.starts_with("//")
                && !n.starts_with("/\\")
                && n.len() <= MAX_NEXT_LENGTH
                && !n.chars().any(|c| c.is_control() || c == '\\') =>
        {
            n.to_string()
        }
        _ => "/".into(),
    }
}

/// A page sending the browser to `path` from our own origin. A redirect
/// would keep the provider's cross-site navigation going, and browsers would
/// not send the new SameSite=Strict session cookie with it.
fn continue_page(path: &str) -> String {
    let escaped = path
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&#39;");
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url={escaped}\"><title>Signing in</title></head><body><a href=\"{escaped}\">Continue</a></body></html>"
    )
}

/// Back to the login page with a message.
fn login_error(message: &str) -> Response {
    let query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("error", message)
        .finish();
    let location = format!("/login?{query}");
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(&location).unwrap_or(HeaderValue::from_static("/login")),
        )],
    )
        .into_response()
}

fn state_cookie(value: String, secure: bool, max_age: time::Duration) -> Cookie<'static> {
    Cookie::build((STATE_COOKIE, value))
        .path("/api/v1/auth/oidc")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(max_age)
        .build()
}

#[derive(Deserialize, IntoParams)]
pub struct LoginParams {
    /// Local path to open after signing in (default `/`).
    next: Option<String>,
}

/// Starts a single sign-on: redirects the browser to the provider.
#[utoipa::path(get, path = "/api/v1/auth/oidc/login", tag = "auth", params(LoginParams),
    responses((status = 303, description = "Redirect to the provider"),
              (status = 404, description = "Single sign-on is not configured")))]
async fn oidc_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<LoginParams>,
) -> Result<Response, ApiError> {
    let Some(oidc) = &state.oidc else {
        return Err(ApiError::NotFound(
            "single sign-on is not configured".into(),
        ));
    };
    let (url, csrf, nonce, verifier) = match oidc.authorize().await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = format!("{e:#}"), "OIDC provider unavailable");
            return Ok(login_error(
                "The sign-on provider is unavailable. Try again later.",
            ));
        }
    };
    let next = safe_next(params.next.as_deref());
    db::create_oidc_login(&state.db, &csrf, &nonce, &verifier, &next).await?;
    let jar = jar.add(state_cookie(csrf, state.config.cookie_secure, LOGIN_TTL));
    let location = HeaderValue::from_str(&url).map_err(|e| ApiError::Internal(e.into()))?;
    Ok((jar, (StatusCode::SEE_OTHER, [(header::LOCATION, location)])).into_response())
}

#[derive(Deserialize, IntoParams)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    /// Set by the provider when the sign-in failed or was refused.
    error: Option<String>,
}

/// Where the provider sends the browser back: signs the user in, creating
/// their account at the first sign-in.
#[utoipa::path(get, path = "/api/v1/auth/oidc/callback", tag = "auth", params(CallbackParams),
    responses((status = 200, description = "Signed in: a page continuing to the next path"),
              (status = 303, description = "Back to the login page with an error")))]
async fn oidc_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<CallbackParams>,
) -> Result<Response, ApiError> {
    let Some(oidc) = &state.oidc else {
        return Err(ApiError::NotFound(
            "single sign-on is not configured".into(),
        ));
    };
    let bound = jar.get(STATE_COOKIE).map(|c| c.value().to_string());
    let jar = jar.add(state_cookie(
        String::new(),
        state.config.cookie_secure,
        time::Duration::ZERO,
    ));
    if let Some(error) = params.error {
        tracing::info!(error, "OIDC sign-in refused by the provider");
        return Ok((
            jar,
            login_error("The sign-on provider refused the sign-in."),
        )
            .into_response());
    }
    let (Some(code), Some(csrf)) = (params.code, params.state) else {
        return Ok((jar, login_error("The sign-in is incomplete: start again.")).into_response());
    };
    // The sign-in must come back to the browser that started it.
    if bound.as_deref() != Some(csrf.as_str()) {
        return Ok((
            jar,
            login_error("The sign-in expired or was started elsewhere: start again."),
        )
            .into_response());
    }
    let Some(login) = db::take_oidc_login(&state.db, &csrf).await? else {
        return Ok((jar, login_error("The sign-in expired: start again.")).into_response());
    };
    let identity = match oidc.identity(&code, &login).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = format!("{e:#}"), "OIDC sign-in failed");
            return Ok((
                jar,
                login_error("The sign-in could not be verified: start again."),
            )
                .into_response());
        }
    };
    let user = user_for(&state, oidc, &identity).await?;
    if user.disabled_at.is_some() {
        return Ok((
            jar,
            login_error("This account is disabled: ask an administrator."),
        )
            .into_response());
    }
    let session = auth::login(&state.db, &user, state.config.cookie_secure).await?;
    db::record_login(&state.db, user.id).await?;
    tracing::info!(
        username = user.username,
        role = user.role,
        "signed in with OIDC"
    );
    let page = continue_page(&login.next_path);
    Ok((
        jar.add(session),
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        page,
    )
        .into_response())
}

/// The account of an identity: found by issuer and subject, or created.
async fn user_for(state: &AppState, oidc: &Oidc, id: &Identity) -> Result<db::User, ApiError> {
    let role = role_for(&oidc.config, &id.groups);
    if let Some(user) = db::user_by_oidc(&state.db, &id.issuer, &id.subject).await? {
        return Ok(db::update_oidc_user(&state.db, user.id, id.email.as_deref(), role).await?);
    }
    let base = base_username(id.username_hint.as_deref());
    let display_name: String = id
        .name
        .as_deref()
        .or(id.username_hint.as_deref())
        .unwrap_or(&base)
        .chars()
        .take(100)
        .collect();
    for n in 1..=100 {
        let username = match n {
            1 => base.clone(),
            n => format!("{base}-{n}"),
        };
        let created = db::create_oidc_user(
            &state.db,
            &db::NewOidcUser {
                username: &username,
                display_name: &display_name,
                role: role.unwrap_or(STUDENT_ROLE),
                issuer: &id.issuer,
                subject: &id.subject,
                email: id.email.as_deref(),
            },
        )
        .await;
        match created {
            Ok(user) => {
                tracing::info!(
                    username,
                    role = user.role,
                    "account created at the first OIDC sign-in"
                );
                return Ok(user);
            }
            Err(e) if db::violates(&e, "users_username_key") => continue,
            // Created meanwhile by a concurrent sign-in.
            Err(e) if db::violates(&e, "users_oidc_identity") => {
                return db::user_by_oidc(&state.db, &id.issuer, &id.subject)
                    .await?
                    .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("OIDC user vanished")));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::Conflict(format!("no free username for {base}")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn back_channel() {
        let from = origin("http://localhost:5556/dex").unwrap();
        let to = origin("http://dex.brokelabs-system.svc:5556").unwrap();
        assert_eq!(
            (from.as_str(), to.as_str()),
            (
                "http://localhost:5556",
                "http://dex.brokelabs-system.svc:5556"
            )
        );
        assert_eq!(
            rebase("http://localhost:5556/dex/keys", &from, &to).as_deref(),
            Some("http://dex.brokelabs-system.svc:5556/dex/keys")
        );
        // Other origins (and look-alike hosts) are left alone.
        assert_eq!(rebase("http://localhost:55567/x", &from, &to), None);
        assert_eq!(rebase("https://other.test/x", &from, &to), None);
        assert_eq!(origin("https://sso.test").unwrap(), "https://sso.test");
        assert!(origin("not a url").is_err());
    }

    fn config(admin: &[&str], teacher: &[&str]) -> OidcConfig {
        OidcConfig {
            issuer: "https://sso.test".into(),
            client_id: "c".into(),
            client_secret: None,
            label: "SSO".into(),
            scopes: vec![],
            groups_claim: "groups".into(),
            admin_groups: admin.iter().map(|s| s.to_string()).collect(),
            teacher_groups: teacher.iter().map(|s| s.to_string()).collect(),
            ca_file: None,
            backchannel_url: None,
        }
    }

    #[test]
    fn roles_from_groups() {
        let g = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(role_for(&config(&[], &[]), &g(&["admins"])), None);
        let c = config(&["admins"], &["teachers"]);
        assert_eq!(role_for(&c, &g(&["teachers", "admins"])), Some(ADMIN_ROLE));
        assert_eq!(role_for(&c, &g(&["teachers"])), Some(TEACHER_ROLE));
        assert_eq!(role_for(&c, &g(&["class-1a"])), Some(STUDENT_ROLE));
    }

    #[test]
    fn groups_claims() {
        let p =
            json!({"groups": ["a", 1, "b"], "realm_access": {"roles": ["teacher"]}, "team": "x"});
        assert_eq!(groups(&p, "groups"), ["a", "b"]);
        assert_eq!(groups(&p, "realm_access.roles"), ["teacher"]);
        assert_eq!(groups(&p, "team"), ["x"]);
        assert!(groups(&p, "missing.claim").is_empty());
    }

    #[test]
    fn usernames_from_hints() {
        assert_eq!(
            base_username(Some("Alice.Martin@school.org")),
            "alice.martin"
        );
        assert_eq!(base_username(Some("Zoé Durand")), "zo--durand");
        assert_eq!(base_username(Some("__x")), "x");
        assert_eq!(base_username(Some("@@@")), "user");
        assert_eq!(base_username(None), "user");
    }

    #[test]
    fn next_paths_stay_local() {
        assert_eq!(safe_next(Some("/join/AB12")), "/join/AB12");
        for bad in [
            "https://evil.test",
            "//evil.test",
            "/\\evil.test",
            "join",
            "/a\nb",
        ] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad}");
        }
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn continue_pages_escape_the_path() {
        let page = continue_page("/x?a=1&b=\"<");
        assert!(page.contains("url=/x?a=1&amp;b=&quot;&lt;"));
    }

    #[test]
    fn payloads() {
        let body = URL_SAFE_NO_PAD.encode(br#"{"sub":"1","groups":["g"]}"#);
        let p = jwt_payload(&format!("h.{body}.s")).unwrap();
        assert_eq!(groups(&p, "groups"), ["g"]);
        assert!(jwt_payload("nodots").is_err());
    }
}
