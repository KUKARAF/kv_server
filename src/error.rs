use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Placed in response extensions by `AppError::Unauthorized` so that
/// `rate_limit::layer` can detect auth failures independently of HTTP status.
#[derive(Clone)]
pub struct AuthFailed;

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

    #[error("key conflict")]
    KeyConflict(Vec<String>),

    #[error("rate limit exceeded")]
    RateLimited,

    // 403 with emoji sequence for approval_required keys
    #[error("pending approval")]
    PendingApproval {
        confirm: String,
        approver: Option<String>,
    },

    // 403 for zero_trust entries — client must complete WebAuthn ceremony
    #[error("zero trust required")]
    ZeroTrustRequired,

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
        if let AppError::PendingApproval { confirm, approver } = &self {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "pending approval", "confirm": confirm, "approver": approver })),
            )
                .into_response();
        }

        if matches!(self, AppError::RateLimited) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "rate limit exceeded" })),
            )
                .into_response();
        }

        if matches!(self, AppError::Unauthorized) {
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            )
                .into_response();
            response.extensions_mut().insert(AuthFailed);
            return response;
        }

        if let AppError::KeyConflict(keys) = &self {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "key already in use", "keys": keys })),
            )
                .into_response();
        }

        if matches!(self, AppError::ZeroTrustRequired) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "zero_trust_required" })),
            )
                .into_response();
        }

        if let AppError::Forbidden(msg) = &self {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": msg }))).into_response();
        }

        let (status, message) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::RateLimited
            | AppError::Unauthorized
            | AppError::Forbidden(_)
            | AppError::PendingApproval { .. }
            | AppError::ZeroTrustRequired
            | AppError::KeyConflict(_) => unreachable!(),
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                return Redirect::to("https://static.osmosis.page/osmosis/500.html")
                    .into_response();
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
