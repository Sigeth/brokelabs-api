//! HTTP routes.

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use brokelabs_auth::Signer;
use serde::Serialize;
use sqlx::PgPool;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::cluster::Cluster;
use crate::config::Config;
use crate::events::{self, Hub};

/// Shared state of the handlers.
#[derive(Clone)]
pub struct AppState {
    pub signer: Arc<Signer>,
    pub db: PgPool,
    pub cluster: Arc<dyn Cluster>,
    pub hub: Hub,
    pub config: Arc<Config>,
}

#[derive(OpenApi)]
#[openapi(
    info(title = "brokelabs api", description = "Platform API of BrokeLabs."),
    components(schemas(crate::views::Event))
)]
struct ApiDoc;

/// The OpenAPI document of the API, the source of the web UI's TypeScript client.
pub fn openapi() -> utoipa::openapi::OpenApi {
    api_router().split_for_parts().1
}

fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(version))
        .routes(routes!(events::events))
        .merge(crate::routes::router())
}

/// Builds the application. When `web_dir` is set, every path that is not an
/// API route serves the web UI (single-page app: unknown paths get index.html).
pub fn router(state: AppState, web_dir: Option<&Path>) -> Router {
    let (api, spec) = api_router().split_for_parts();
    let spec = Arc::new(spec);
    let app = api
        .route("/healthz", get(|| async { "ok" }))
        .route("/.well-known/jwks.json", get(jwks))
        .route(
            "/api/openapi.json",
            get(move || async move { Json(spec.as_ref().clone()) }),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::check_origin,
        ))
        .with_state(state);
    let app = match web_dir {
        Some(dir) => app
            .fallback_service(ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")))),
        None => app.fallback(|| async { (StatusCode::NOT_FOUND, "not found") }),
    };
    app.layer(TraceLayer::new_for_http())
}

/// Version of the running api.
#[derive(Serialize, ToSchema)]
struct VersionInfo {
    /// Project name.
    name: &'static str,
    /// Semantic version of the api.
    version: &'static str,
}

/// Returns the version of the api.
#[utoipa::path(get, path = "/api/v1/version", tag = "meta",
    responses((status = 200, description = "Version of the api", body = VersionInfo)))]
async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        name: brokelabs_auth::ISSUER.trim_end_matches("-api"),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Public keys verifying access tokens, fetched by the gateway.
async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.signer.jwks())
}

/// State for handler tests.
#[cfg(test)]
pub fn test_state(db: PgPool, cluster: Arc<dyn Cluster>) -> AppState {
    let config = Config::from_env_map(&[
        ("BROKELABS_DATABASE_URL", "postgres://localhost/unused"),
        ("BROKELABS_GATEWAY_URL", "http://gw.test"),
        ("BROKELABS_ALLOWED_ORIGINS", "http://brokelabs.test"),
    ])
    .unwrap();
    AppState {
        signer: Arc::new(Signer::generate().unwrap()),
        db,
        cluster,
        hub: Hub::default(),
        config: Arc::new(config),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn state() -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        test_state(db, Arc::new(crate::cluster::fake::FakeCluster::default()))
    }

    #[tokio::test]
    async fn api_routes_need_a_session() {
        let (status, body) = get(router(state(), None), "/api/v1/me").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    async fn get(app: Router, uri: &str) -> (StatusCode, String) {
        let res = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn health_and_version() {
        let (status, body) = get(router(state(), None), "/healthz").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "ok"));

        let (status, body) = get(router(state(), None), "/api/v1/version").await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["name"], "brokelabs");
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn jwks_publishes_the_signing_key() {
        let state = state();
        let kid = state.signer.key_id().to_string();
        let (status, body) = get(router(state, None), "/.well-known/jwks.json").await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["keys"][0]["kid"], kid);
        assert_eq!(v["keys"][0]["crv"], "Ed25519");
    }

    #[tokio::test]
    async fn openapi_lists_api_routes() {
        let (status, body) = get(router(state(), None), "/api/openapi.json").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("/api/v1/version"));
        assert_eq!(
            serde_json::to_value(openapi()).unwrap(),
            serde_json::from_str::<serde_json::Value>(&body).unwrap()
        );
    }

    #[tokio::test]
    async fn serves_the_web_ui_as_a_single_page_app() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html>brokelabs</html>").unwrap();
        std::fs::write(dir.path().join("app.js"), "console.log(1)").unwrap();

        let (status, body) = get(router(state(), Some(dir.path())), "/app.js").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "console.log(1)"));
        // Client-side routes fall back to index.html.
        let (status, body) = get(router(state(), Some(dir.path())), "/challenges/ssh-101").await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "<html>brokelabs</html>")
        );
        // API routes still win.
        let (_, body) = get(router(state(), Some(dir.path())), "/healthz").await;
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn unknown_paths_are_not_found_without_web_ui() {
        let (status, _) = get(router(state(), None), "/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
