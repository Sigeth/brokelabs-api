//! Errors returned by handlers, as JSON `{"error": "..."}`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("sign in first")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl From<kube::Error> for ApiError {
    fn from(e: kube::Error) -> Self {
        Self::Internal(e.into())
    }
}

/// Body of every error response.
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    /// What went wrong, for humans.
    pub error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal(e) => {
                tracing::error!(error = format!("{e:#}"), "request failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let error = match self {
            Self::Internal(_) => "internal error".to_string(),
            other => other.to_string(),
        };
        (status, Json(ErrorBody { error })).into_response()
    }
}
