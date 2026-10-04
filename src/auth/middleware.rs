use crate::{
    device_policy::enforce::ensure_not_banned, error::AppError, keys::generate::hash_key,
    middleware::ip_block::ClientIp, state::AppState,
};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone)]
pub struct SessionClaims {
    pub oidc_subject: String,
    pub email: Option<String>,
    /// Some only for a session token minted via session_request approval — lets a device
    /// ask "who am I" (see admin::handlers::whoami). None for OIDC cookies and other
    /// non-device-bound credentials.
    pub device_id: Option<String>,
    /// `api_keys.id` of the presented session/approval token. None in dev mode. Lets a
    /// restricted device's logout revoke only its own token.
    pub api_key_id: Option<String>,
    /// Resolved client IP (from ip_block's `ClientIp` extension), recorded on device bans.
    pub client_ip: Option<IpAddr>,
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
                device_id: None,
                api_key_id: None,
                client_ip: parts.extensions.get::<ClientIp>().map(|c| c.0),
            }));
        }

        let token = extract_token(parts).ok_or(AppError::Unauthorized)?;

        // Validate session via api_keys table with type='session'
        let key_hash = hash_key(&token);

        // Fetch without an expiry filter so an expired-but-known cookie is
        // distinguishable from a genuinely unknown token: the former is a benign
        // re-auth (SessionExpired, uncounted), the latter a real failure.
        let row = sqlx::query!(
            "SELECT id, owner_id, label, expires_at, device_id
             FROM api_keys
             WHERE key_hash = ? AND type IN ('session', 'approval') AND status = 'active'",
            key_hash
        )
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

        if let Some(ref exp) = row.expires_at {
            let expired: bool = sqlx::query_scalar!("SELECT datetime(?) <= datetime('now')", exp)
                .fetch_one(&state.pool)
                .await?
                != 0;
            if expired {
                return Err(AppError::SessionExpired);
            }
        }

        // A banned device is rejected before any handler logic runs. DeviceBanned carries
        // no AuthFailed marker: a ban is a policy consequence, not an auth failure.
        if let Some(ref device_id) = row.device_id {
            ensure_not_banned(&state.pool, device_id).await?;
        }

        Ok(AdminAuth(SessionClaims {
            oidc_subject: row.owner_id,
            email: Some(row.label),
            device_id: row.device_id,
            api_key_id: Some(row.id),
            client_ip: parts.extensions.get::<ClientIp>().map(|c| c.0),
        }))
    }
}
