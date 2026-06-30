use crate::{error::AppError, keys::generate::hash_key, state::AppState};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SessionClaims {
    pub oidc_subject: String,
    pub email: Option<String>,
}

pub struct AdminAuth(pub SessionClaims);

fn extract_token(parts: &Parts) -> Option<String> {
    // 1. Authorization: Bearer ***
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
                oidc_subject: "dev".to_string(),
                email: Some("dev@localhost".to_string()),
            }));
        }

        let token = extract_token(parts).ok_or(AppError::Unauthorized)?;

        // Validate session via api_keys table with type='session'
        let key_hash = hash_key(&token);

        let row = sqlx::query!(
            "SELECT owner_id, label
             FROM api_keys
             WHERE key_hash = ? AND type IN ('session', 'approval') AND status = 'active'
               AND (expires_at IS NULL OR expires_at > datetime('now'))",
            key_hash
        )
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

        Ok(AdminAuth(SessionClaims {
            oidc_subject: row.owner_id,
            email: Some(row.label),
        }))
    }
}
