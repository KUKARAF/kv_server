use crate::{
    error::AppError,
    kv::model::{compute_expires_at, KvMetaResponse, KvResponse, KvUpsertRequest},
    middleware::api_key::ApiKeyAuth,
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub prefix: Option<String>,
}

pub async fn get_entry(
    State(state): State<Arc<AppState>>,
    _auth: ApiKeyAuth, // open-access bypass handled inside the extractor
    Path(key): Path<String>,
) -> Result<Json<KvResponse>, AppError> {
    let row = sqlx::query!(
        "SELECT key, value, ttl_hours, ttl_sliding, expires_at
         FROM kv_entries
         WHERE key = ?
           AND (expires_at IS NULL OR expires_at > datetime('now'))",
        key
    )
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or(AppError::NotFound)?;

    // Update sliding TTL if applicable
    if row.ttl_sliding != 0 {
        if let Some(ttl_hours) = row.ttl_hours {
            let new_expires = compute_expires_at(Some(ttl_hours));
            sqlx::query!(
                "UPDATE kv_entries SET expires_at = ? WHERE key = ?",
                new_expires,
                key
            )
            .execute(&state.pool)
            .await?;
        }
    }

    Ok(Json(KvResponse {
        key: row.key,
        value: row.value,
    }))
}

pub async fn upsert_entry(
    State(state): State<Arc<AppState>>,
    _auth: ApiKeyAuth,
    Path(key): Path<String>,
    Json(body): Json<KvUpsertRequest>,
) -> Result<StatusCode, AppError> {
    let expires_at = compute_expires_at(body.ttl_hours);
    let ttl_sliding = body.ttl_sliding as i64;
    let open_access = body.open_access as i64;

    sqlx::query!(
        "INSERT INTO kv_entries (key, value, ttl_hours, ttl_sliding, expires_at, open_access)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
             value       = excluded.value,
             ttl_hours   = excluded.ttl_hours,
             ttl_sliding = excluded.ttl_sliding,
             expires_at  = excluded.expires_at,
             open_access = excluded.open_access",
        key,
        body.value,
        body.ttl_hours,
        ttl_sliding,
        expires_at,
        open_access
    )
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    _auth: ApiKeyAuth,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query!(
        "DELETE FROM kv_entries WHERE key = ?",
        key
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
    _auth: ApiKeyAuth,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<KvMetaResponse>>, AppError> {
    let rows = match q.prefix {
        Some(prefix) => {
            let pattern = format!("{}%", prefix);
            sqlx::query_as!(
                KvMetaResponse,
                r#"SELECT key, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE key LIKE ?
                   AND (expires_at IS NULL OR expires_at > datetime('now'))
                 ORDER BY key"#,
                pattern
            )
            .fetch_all(&state.pool)
            .await?
        }
        None => {
            sqlx::query_as!(
                KvMetaResponse,
                r#"SELECT key, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE expires_at IS NULL OR expires_at > datetime('now')
                 ORDER BY key"#
            )
            .fetch_all(&state.pool)
            .await?
        }
    };

    Ok(Json(rows))
}
