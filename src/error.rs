use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found")]
    NotFound,

    #[allow(dead_code)]
    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limit exceeded")]
    RateLimited,

    // 403 with emoji sequence for approval_required keys
    #[error("pending approval")]
    PendingApproval(String),

    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let AppError::PendingApproval(emoji) = &self {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "pending approval", "confirm": emoji })),
            )
                .into_response();
        }

        let (status, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".to_string()),
            AppError::PendingApproval(_) => unreachable!(),
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
