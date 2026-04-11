use crate::{
    error::AppError,
    keys::generate::{generate_emoji_sequence, hash_key},
    kv::model::{compute_expires_at, KvMetaResponse, KvUpsertRequest},
    middleware::api_key::ApiKeyAuth,
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Serialize)]
pub struct RequestAccessResponse {
    pub confirm: String,
}

/// Called by the unauthenticated share-link user to initiate an approval request.
/// Cancels any prior pending request for this key, generates 3 fresh emojis, and
/// returns them for the user to relay to the key owner.
pub async fn request_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RequestAccessResponse>, AppError> {
    let raw_key = headers
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let key_hash = hash_key(raw_key);

    let api_key = sqlx::query!(
        "SELECT id, type as key_type, status FROM api_keys WHERE key_hash = ?",
        key_hash
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if api_key.key_type != "approval_required" || api_key.status != "pending_approval" {
        return Err(AppError::Forbidden("key is not awaiting approval".to_string()));
    }

    // Cancel any existing pending requests so admin only sees the latest
    sqlx::query!(
        "UPDATE approval_requests SET status = 'expired'
         WHERE api_key_id = ? AND status = 'pending'",
        api_key.id
    )
    .execute(&state.pool)
    .await?;

    let emoji = generate_emoji_sequence();
    let emoji_hash = bcrypt::hash(&emoji, 6)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt error: {e}")))?;
    let id = Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO approval_requests (id, api_key_id, emoji_sequence, expires_at)
         VALUES (?, ?, ?, datetime('now', '+10 minutes'))",
        id, api_key.id, emoji_hash
    )
    .execute(&state.pool)
    .await?;

    Ok(Json(RequestAccessResponse { confirm: emoji }))
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub prefix: Option<String>,
}

pub async fn get_entry(
    State(state): State<Arc<AppState>>,
    auth: ApiKeyAuth,
    Path(key): Path<String>,
) -> Result<String, AppError> {
    let (value, ttl_hours, ttl_sliding, expires_at) = if let Some(ref oid) = auth.owner_id {
        let row = sqlx::query!(
            "SELECT value, ttl_hours, ttl_sliding, expires_at
             FROM kv_entries
             WHERE key = ? AND owner_id = ?
               AND (expires_at IS NULL OR expires_at > datetime('now'))",
            key, oid
        )
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
        (row.value, row.ttl_hours, row.ttl_sliding, row.expires_at)
    } else {
        // Open-access path — no owner filter
        let row = sqlx::query!(
            "SELECT value, ttl_hours, ttl_sliding, expires_at
             FROM kv_entries
             WHERE key = ? AND open_access = 1
               AND (expires_at IS NULL OR expires_at > datetime('now'))
             LIMIT 1",
            key
        )
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::NotFound)?;
        (row.value, row.ttl_hours, row.ttl_sliding, row.expires_at)
    };

    // Update sliding TTL if applicable (only for authenticated reads)
    if ttl_sliding != 0 {
        if let (Some(ttl_hours), Some(ref oid)) = (ttl_hours, auth.owner_id) {
            let new_expires = compute_expires_at(Some(ttl_hours));
            sqlx::query!(
                "UPDATE kv_entries SET expires_at = ? WHERE key = ? AND owner_id = ?",
                new_expires, key, oid
            )
            .execute(&state.pool)
            .await?;
        }
    }

    let _ = expires_at; // consumed above
    Ok(value)
}

pub async fn upsert_entry(
    State(state): State<Arc<AppState>>,
    auth: ApiKeyAuth,
    Path(key): Path<String>,
    Json(body): Json<KvUpsertRequest>,
) -> Result<StatusCode, AppError> {
    let owner_id = auth.owner_id.ok_or(AppError::Unauthorized)?;
    let expires_at = compute_expires_at(body.ttl_hours);
    let ttl_sliding = body.ttl_sliding as i64;
    let open_access = body.open_access as i64;

    sqlx::query!(
        "INSERT INTO kv_entries (key, owner_id, value, ttl_hours, ttl_sliding, expires_at, open_access)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(key, owner_id) DO UPDATE SET
             value       = excluded.value,
             ttl_hours   = excluded.ttl_hours,
             ttl_sliding = excluded.ttl_sliding,
             expires_at  = excluded.expires_at,
             open_access = excluded.open_access",
        key, owner_id, body.value, body.ttl_hours, ttl_sliding, expires_at, open_access
    )
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    auth: ApiKeyAuth,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner_id = auth.owner_id.ok_or(AppError::Unauthorized)?;

    let result = sqlx::query!(
        "DELETE FROM kv_entries WHERE key = ? AND owner_id = ?",
        key, owner_id
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_entries(
    State(state): State<Arc<AppState>>,
    auth: ApiKeyAuth,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<KvMetaResponse>>, AppError> {
    let owner_id = auth.owner_id.ok_or(AppError::Unauthorized)?;

    let rows = match q.prefix {
        Some(prefix) => {
            let pattern = format!("{}%", prefix);
            sqlx::query_as!(
                KvMetaResponse,
                r#"SELECT key, scope, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE key LIKE ? AND owner_id = ?
                   AND (expires_at IS NULL OR expires_at > datetime('now'))
                 ORDER BY key"#,
                pattern, owner_id
            )
            .fetch_all(&state.pool)
            .await?
        }
        None => {
            sqlx::query_as!(
                KvMetaResponse,
                r#"SELECT key, scope, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE owner_id = ?
                   AND (expires_at IS NULL OR expires_at > datetime('now'))
                 ORDER BY key"#,
                owner_id
            )
            .fetch_all(&state.pool)
            .await?
        }
    };

    Ok(Json(rows))
}
