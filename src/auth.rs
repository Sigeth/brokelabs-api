//! Local accounts and cookie sessions.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use crate::app::AppState;
use crate::db::{self, User};
use crate::error::ApiError;

/// Name of the session cookie (host-only, so never sent to env web UIs).
pub const SESSION_COOKIE: &str = "opslab_session";
/// Lifetime of a session.
pub const SESSION_TTL: Duration = Duration::days(7);

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A random secret, URL-safe.
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::fill(&mut buf[..]);
    URL_SAFE_NO_PAD.encode(buf)
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Starts a session and returns its cookie.
pub async fn login(db: &PgPool, user: &User, secure: bool) -> Result<Cookie<'static>, ApiError> {
    let token = random_token(32);
    db::create_session(
        db,
        &token_hash(&token),
        user.id,
        OffsetDateTime::now_utc() + SESSION_TTL,
    )
    .await?;
    Ok(Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(SESSION_TTL)
        .build())
}

/// Ends the session of the request, if any, and returns a removal cookie.
pub async fn logout(db: &PgPool, jar: &CookieJar) -> Result<Cookie<'static>, ApiError> {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        db::delete_session(db, &token_hash(c.value())).await?;
    }
    Ok(Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .max_age(Duration::ZERO)
        .build())
}

/// Creates the solo user on first start, and resets its password to the
/// configured one when there is one.
pub async fn bootstrap_solo(
    db: &PgPool,
    username: &str,
    password: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(user) = db::user_by_name(db, username).await? {
        if let Some(password) = password {
            let current = user.password_hash.as_deref().unwrap_or_default();
            if !verify_password(password, current) {
                db::set_password(db, user.id, &hash_password(password)?).await?;
                tracing::info!(username, "solo user password reset to the configured one");
            }
        }
        return Ok(());
    }
    if db::count_users(db).await? > 0 {
        tracing::info!(username, "users exist: not creating the solo user");
        return Ok(());
    }
    let generated;
    let password = match password {
        Some(p) => p,
        None => {
            generated = random_token(15);
            tracing::warn!(username, password = %generated, "solo user created with a generated password: set OPSLAB_SOLO_PASSWORD_FILE to choose it");
            &generated
        }
    };
    db::create_user(db, username, username, "admin", &hash_password(password)?).await?;
    tracing::info!(username, "solo user created");
    Ok(())
}

/// The signed-in user. Rejects the request with 401 otherwise.
pub struct CurrentUser(pub User);

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let jar = CookieJar::from_headers(&parts.headers);
        let Some(cookie) = jar.get(SESSION_COOKIE) else {
            return Err(ApiError::Unauthorized);
        };
        match db::session_user(&state.db, &token_hash(cookie.value())).await? {
            Some(user) => Ok(CurrentUser(user)),
            None => Err(ApiError::Unauthorized),
        }
    }
}

/// Rejects state-changing requests sent by other origins (CSRF). Pages on
/// `*.inst.<domain>` are same-site with the platform, so SameSite cookies
/// alone do not stop them.
pub async fn check_origin(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe
        && !state.config.allowed_origins.is_empty()
        && let Some(origin) = req.headers().get(header::ORIGIN)
    {
        let origin = origin.to_str().unwrap_or_default();
        if !state.config.allowed_origins.iter().any(|o| o == origin) {
            tracing::info!(origin, "rejected cross-origin request");
            return ApiError::Forbidden("cross-origin request".into()).into_response();
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords() {
        let hash = hash_password("correct horse").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("x", "not a hash"));
    }

    #[test]
    fn tokens_are_random() {
        assert_ne!(random_token(32), random_token(32));
        assert_eq!(random_token(32).len(), 43);
    }
}
