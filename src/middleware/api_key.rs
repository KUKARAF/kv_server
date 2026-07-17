use crate::{
    error::AppError,
    middleware::ip_block::{record_auth_failure, reset_failures_on_success, ClientIp},
    notify,
    state::AppState,
};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, Method},
};
use sqlx::SqlitePool;
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Read,
    Write,
    Delete,
    List,
}

impl Op {
    pub fn as_str(&self) -> &str {
        match self {
            Op::Read => "read",
            Op::Write => "write",
            Op::Delete => "delete",
            Op::List => "list",
        }
    }

    fn from_request(parts: &Parts) -> Self {
        // axum's nest("/kv", ...) strips the prefix, so the path arriving here
        // is the remainder: "/" or "" for the list endpoint, "/foo" for a key.
        let path = parts.uri.path().trim_start_matches('/');
        let is_list = parts.method == Method::GET && path.is_empty();
        if is_list {
            return Op::List;
        }
        match parts.method {
            Method::GET => Op::Read,
            Method::PUT | Method::POST => Op::Write,
            Method::DELETE => Op::Delete,
            _ => Op::Read,
        }
    }
}

pub struct ApiKeyAuth {
    pub owner_id: Option<String>, // None only for open-access reads
    pub api_key_id: Option<String>,
    pub op: Op,
    /// None = session token = full access to all keys.
    /// Some(keys) = manual token restricted to the listed KV key names.
    pub allowed_keys: Option<Vec<String>>,
}

/// Check whether an authenticated token is allowed to access a specific KV key.
/// `None` means session-level (full access); `Some(keys)` means restricted.
pub fn check_kv_access(allowed_keys: &Option<Vec<String>>, kv_key: &str) -> Result<(), AppError> {
    if let Some(keys) = allowed_keys {
        if !keys.contains(&kv_key.to_string()) {
            return Err(AppError::Forbidden("insufficient access".to_string()));
        }
    }
    Ok(())
}

// ── Header extraction helpers ────────────────────────────────────────────────

fn extract_bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn extract_x_api_key(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_kv_key(parts: &Parts) -> String {
    parts.uri.path().trim_start_matches('/').to_string()
}

fn fire_record_failure(
    pool: SqlitePool,
    ip: IpAddr,
    threshold: u32,
    base_secs: u64,
    reason: &'static str,
) {
    tokio::spawn(async move {
        record_auth_failure(&pool, ip, threshold, base_secs, reason).await;
    });
}

// ── Session Bearer token path ────────────────────────────────────────────────

async fn auth_session_bearer(
    state: &Arc<AppState>,
    token: &str,
    op: Op,
    client_ip: Option<IpAddr>,
) -> Result<ApiKeyAuth, AppError> {
    let key_hash = crate::keys::generate::hash_key(token);

    let api_key = sqlx::query!(
        "SELECT id, status, expires_at, owner_id
         FROM api_keys
         WHERE key_hash = ? AND type = 'session'",
        key_hash
    )
    .fetch_optional(&state.pool)
    .await?;

    let api_key = match api_key {
        Some(k) => k,
        // Bearer provided but not a session key — not an attack, no failure recorded.
        None => return Err(AppError::Unauthorized),
    };

    if api_key.status == "revoked" || api_key.status == "used" {
        notify::send(
            state.pool.clone(),
            format!(
                "Auth failure: {} key used ({})",
                api_key.status,
                &api_key.id[..8]
            ),
            "medium",
        );
        if let Some(ip) = client_ip {
            fire_record_failure(
                state.pool.clone(),
                ip,
                state.config.auth_failure_threshold,
                state.config.auth_block_base_secs,
                "revoked or used session key",
            );
        }
        return Err(AppError::Unauthorized);
    }

    if let Some(ref exp) = api_key.expires_at {
        let expired: bool = sqlx::query_scalar!("SELECT datetime(?) <= datetime('now')", exp)
            .fetch_one(&state.pool)
            .await?
            != 0;

        if expired {
            tracing::debug!(key_id = %api_key.id, "session key expired — triggering re-auth");
            return Err(AppError::SessionExpired);
        }
    }

    // Spawn last_used_at update and failure-counter reset.
    let id = api_key.id.clone();
    let pool = state.pool.clone();
    tokio::spawn(async move {
        let _ = sqlx::query!(
            "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
            id
        )
        .execute(&pool)
        .await;
        if let Some(ip) = client_ip {
            reset_failures_on_success(&pool, ip).await;
        }
    });

    Ok(ApiKeyAuth {
        owner_id: Some(api_key.owner_id),
        api_key_id: Some(api_key.id),
        op,
        allowed_keys: None,
    })
}

// ── Open-access check ────────────────────────────────────────────────────────

async fn is_open_access(pool: &SqlitePool, kv_key: &str) -> Result<bool, AppError> {
    let open = sqlx::query_scalar!(
        "SELECT open_access FROM kv_entries
         WHERE key = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
         LIMIT 1",
        kv_key
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or(0);

    Ok(open != 0)
}

// ── Manual X-Api-Key path ────────────────────────────────────────────────────

async fn fetch_allowed_keys(pool: &SqlitePool, api_key_id: &str) -> Result<Vec<String>, AppError> {
    let keys = sqlx::query_scalar!(
        "SELECT kv_key FROM api_key_allowed_keys WHERE api_key_id = ?",
        api_key_id
    )
    .fetch_all(pool)
    .await?;

    Ok(keys)
}

async fn auth_manual_key(
    state: &Arc<AppState>,
    raw_key: &str,
    op: Op,
    client_ip: Option<IpAddr>,
) -> Result<ApiKeyAuth, AppError> {
    let key_hash = crate::keys::generate::hash_key(raw_key);

    let api_key = sqlx::query!(
        "SELECT id, type as key_type, status, expires_at, owner_id
         FROM api_keys
         WHERE key_hash = ? AND type NOT IN ('session', 'Bearer')",
        key_hash
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        if let Some(ip) = client_ip {
            fire_record_failure(
                state.pool.clone(),
                ip,
                state.config.auth_failure_threshold,
                state.config.auth_block_base_secs,
                "unknown API key",
            );
        }
        AppError::Unauthorized
    })?;

    if api_key.status == "revoked" || api_key.status == "used" {
        notify::send(
            state.pool.clone(),
            format!(
                "Auth failure: {} key used ({})",
                api_key.status,
                &api_key.id[..8]
            ),
            "medium",
        );
        if let Some(ip) = client_ip {
            fire_record_failure(
                state.pool.clone(),
                ip,
                state.config.auth_failure_threshold,
                state.config.auth_block_base_secs,
                "revoked or used API key",
            );
        }
        return Err(AppError::Unauthorized);
    }

    if let Some(ref exp) = api_key.expires_at {
        let expired: bool = sqlx::query_scalar!("SELECT datetime(?) <= datetime('now')", exp)
            .fetch_one(&state.pool)
            .await?
            != 0;

        if expired {
            notify::send(
                state.pool.clone(),
                format!("Auth failure: expired key used ({})", &api_key.id[..8]),
                "medium",
            );
            if let Some(ip) = client_ip {
                fire_record_failure(
                    state.pool.clone(),
                    ip,
                    state.config.auth_failure_threshold,
                    state.config.auth_block_base_secs,
                    "expired API key",
                );
            }
            return Err(AppError::Unauthorized);
        }
    }

    // Type-specific status checks (one_time consumption happens after allowlist fetch)
    match api_key.key_type.as_str() {
        "zero_trust" => {
            if api_key.status != "active" {
                return Err(AppError::Unauthorized);
            }
        }
        "approval_required" => {
            if api_key.status != "active" {
                let emoji = sqlx::query_scalar!(
                    "SELECT emoji_sequence FROM approval_requests
                     WHERE api_key_id = ? AND status = 'pending'
                       AND expires_at > datetime('now')
                     ORDER BY requested_at DESC LIMIT 1",
                    api_key.id
                )
                .fetch_optional(&state.pool)
                .await?;

                return Err(AppError::PendingApproval {
                    confirm: emoji.unwrap_or_else(|| "pending approval".to_string()),
                    approver: None,
                });
            }
        }
        _ => {
            if api_key.status != "active" {
                return Err(AppError::Unauthorized);
            }
        }
    }

    let allowed_keys = fetch_allowed_keys(&state.pool, &api_key.id).await?;

    // Consume one-time key after allowlist is confirmed fetchable.
    if api_key.key_type == "one_time" {
        let result = sqlx::query!(
            "UPDATE api_keys
             SET status = 'used', last_used_at = datetime('now')
             WHERE id = ? AND status = 'active' AND type = 'one_time'",
            api_key.id
        )
        .execute(&state.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::Forbidden("one-time key already used".to_string()));
        }
    } else {
        // Fire-and-forget last_used_at for non-one-time keys.
        let id = api_key.id.clone();
        let pool = state.pool.clone();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
                id
            )
            .execute(&pool)
            .await;
        });
    }

    Ok(ApiKeyAuth {
        owner_id: Some(api_key.owner_id),
        api_key_id: Some(api_key.id),
        op,
        allowed_keys: Some(allowed_keys),
    })
}

// ── Extractor impl ───────────────────────────────────────────────────────────

#[async_trait]
impl FromRequestParts<Arc<AppState>> for ApiKeyAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let op = Op::from_request(parts);
        let client_ip = parts.extensions.get::<ClientIp>().map(|c| c.0);

        // 1. Bearer token → session key path
        if let Some(token) = extract_bearer(parts) {
            return auth_session_bearer(state, token, op, client_ip).await;
        }

        // 2. Determine KV key from path (used for open-access check)
        let kv_key = extract_kv_key(parts);
        let raw_key = extract_x_api_key(parts);

        // 3. Open-access bypass: unauthenticated reads on flagged entries
        if raw_key.is_none()
            && op == Op::Read
            && !kv_key.is_empty()
            && is_open_access(&state.pool, &kv_key).await?
        {
            return Ok(ApiKeyAuth {
                owner_id: None,
                api_key_id: None,
                op,
                allowed_keys: None,
            });
        }

        // 4. Manual X-Api-Key path
        let raw_key = raw_key.ok_or_else(|| {
            if let Some(ip) = client_ip {
                fire_record_failure(
                    state.pool.clone(),
                    ip,
                    state.config.auth_failure_threshold,
                    state.config.auth_block_base_secs,
                    "missing X-Api-Key header",
                );
            }
            AppError::Unauthorized
        })?;

        auth_manual_key(state, &raw_key, op, client_ip).await
    }
}
