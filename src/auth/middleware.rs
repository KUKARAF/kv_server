use crate::{auth::session::{validate_session, SessionClaims}, error::AppError, middleware::ip_block::{record_auth_failure, ClientIp}, state::AppState};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use std::sync::Arc;

pub struct AdminAuth(pub SessionClaims);

fn extract_token(parts: &Parts) -> Option<String> {
    // 1. Authorization: Bearer <token>
    if let Some(token) = parts
        .headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(token.to_string());
    }

    // 2. HttpOnly session cookie
    let cookie_header = parts.headers.get("Cookie")?.to_str().ok()?;
    cookie_header
        .split(';')
        .map(|s| s.trim())
        .find_map(|pair| pair.strip_prefix("session_token="))
        .map(|v| v.to_string())
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if state.config.dev_mode {
            return Ok(AdminAuth(SessionClaims {
                id: "dev".to_string(),
                oidc_subject: "dev".to_string(),
                email: "dev@localhost".to_string(),
            }));
        }

        let token = extract_token(parts).ok_or(AppError::Unauthorized)?;
        match validate_session(&state.pool, &token).await {
            Ok(claims) => Ok(AdminAuth(claims)),
            Err(e) => {
                if let Some(ip) = parts.extensions.get::<ClientIp>().map(|c| c.0) {
                    let pool = state.pool.clone();
                    let threshold = state.config.auth_failure_threshold;
                    tokio::spawn(async move { record_auth_failure(&pool, ip, threshold).await });
                }
                Err(e)
            }
        }
    }
}
