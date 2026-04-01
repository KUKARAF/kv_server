use crate::{
    admin::model::*,
    auth::middleware::AdminAuth,
    error::AppError,
    keys::generate::{generate_api_key, generate_emoji_sequence},
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

// ── API Keys ────────────────────────────────────────────────────────────────

pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Result<Json<Vec<ApiKeyWithScopes>>, AppError> {
    let keys = sqlx::query_as!(
        ApiKeyRow,
        r#"SELECT id, label, type as "key_type", status, expires_at, created_at, last_used_at
           FROM api_keys ORDER BY created_at DESC"#
    )
    .fetch_all(&state.pool)
    .await?;

    let mut result = Vec::with_capacity(keys.len());
    for key in keys {
        let scopes = sqlx::query_as!(
            ScopeRow,
            "SELECT id, api_key_id, key_pattern, ops FROM api_key_scopes WHERE api_key_id = ?",
            key.id
        )
        .fetch_all(&state.pool)
        .await?;
        result.push(ApiKeyWithScopes { key, scopes });
    }

    Ok(Json(result))
}

pub async fn create_key(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Json(body): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), AppError> {
    let valid_types = ["standard", "one_time", "approval_required"];
    if !valid_types.contains(&body.key_type.as_str()) {
        return Err(AppError::Forbidden(format!(
            "invalid key type: {}",
            body.key_type
        )));
    }

    let (plaintext, key_hash) = generate_api_key();
    let id = Uuid::new_v4().to_string();

    // approval_required keys start as pending_approval
    let status = if body.key_type == "approval_required" {
        "pending_approval"
    } else {
        "active"
    };

    sqlx::query!(
        "INSERT INTO api_keys (id, key_hash, label, type, status, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        id,
        key_hash,
        body.label,
        body.key_type,
        status,
        body.expires_at
    )
    .execute(&state.pool)
    .await?;

    // Insert scope rules
    for scope in &body.scopes {
        let scope_id = Uuid::new_v4().to_string();
        sqlx::query!(
            "INSERT INTO api_key_scopes (id, api_key_id, key_pattern, ops) VALUES (?, ?, ?, ?)",
            scope_id,
            id,
            scope.key_pattern,
            scope.ops
        )
        .execute(&state.pool)
        .await?;
    }

    Ok((StatusCode::CREATED, Json(CreateKeyResponse { id, key: plaintext })))
}

pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query!(
        "UPDATE api_keys SET status = 'revoked' WHERE id = ?",
        key_id
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Approvals ───────────────────────────────────────────────────────────────

pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Result<Json<Vec<ApprovalRow>>, AppError> {
    let rows = sqlx::query_as!(
        ApprovalRow,
        r#"SELECT ar.id, ar.api_key_id,
                  ak.label as "api_key_label",
                  ar.emoji_sequence, ar.status,
                  ar.requested_at, ar.expires_at
           FROM approval_requests ar
           JOIN api_keys ak ON ak.id = ar.api_key_id
           WHERE ar.status = 'pending' AND ar.expires_at > datetime('now')
           ORDER BY ar.requested_at DESC"#
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}

pub async fn approve_request(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(request_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let row = sqlx::query!(
        "SELECT api_key_id FROM approval_requests
         WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')",
        request_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let mut tx = state.pool.begin().await?;

    sqlx::query!(
        "UPDATE approval_requests SET status = 'approved' WHERE id = ?",
        request_id
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "UPDATE api_keys SET status = 'active' WHERE id = ?",
        row.api_key_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reject_request(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(request_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query!(
        "UPDATE approval_requests SET status = 'rejected'
         WHERE id = ? AND status = 'pending'",
        request_id
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Called by a client holding an approval_required key to trigger the approval flow.
/// Generates an emoji sequence, creates an approval_request, returns 403 with the emoji.
pub async fn request_approval(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AppError> {
    // Verify key exists and is pending_approval
    let key = sqlx::query!(
        "SELECT id FROM api_keys WHERE id = ? AND status = 'pending_approval' AND type = 'approval_required'",
        key_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let emoji = generate_emoji_sequence();
    let id = Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO approval_requests (id, api_key_id, emoji_sequence, expires_at)
         VALUES (?, ?, ?, datetime('now', '+10 minutes'))",
        id,
        key.id,
        emoji
    )
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::CREATED)
}

// ── KV (admin view — metadata only, no values) ──────────────────────────────

pub async fn list_kv_entries(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Query(q): Query<crate::kv::handlers::ListQuery>,
) -> Result<Json<Vec<crate::kv::model::KvMetaResponse>>, AppError> {
    let rows = match q.prefix {
        Some(prefix) => {
            let pattern = format!("{}%", prefix);
            sqlx::query_as!(
                crate::kv::model::KvMetaResponse,
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
                crate::kv::model::KvMetaResponse,
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

// ── Session ─────────────────────────────────────────────────────────────────

pub async fn get_session(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<SessionRow>, AppError> {
    let row = sqlx::query_as!(
        SessionRow,
        "SELECT id, email, oidc_subject, expires_at, created_at
         FROM session_tokens WHERE oidc_subject = ? ORDER BY created_at DESC LIMIT 1",
        auth.0.oidc_subject
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(row))
}
