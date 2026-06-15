use crate::{
    auth::middleware::AdminAuth,
    error::AppError,
    keys::generate::generate_api_key,
    session_request::model::*,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

pub async fn create_request(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateSessionRequestBody>,
) -> Result<(StatusCode, Json<CreateSessionRequestResponse>), AppError> {
    let id = Uuid::new_v4().to_string();
    let expires_at = sqlx::query_scalar!("SELECT datetime('now', '+15 minutes')")
        .fetch_one(&state.pool)
        .await?
        .unwrap_or_default();

    sqlx::query!(
        "INSERT INTO session_requests (id, label, expires_at) VALUES (?, ?, ?)",
        id,
        body.label,
        expires_at
    )
    .execute(&state.pool)
    .await?;

    let url = format!("{}/admin/session-request.html?id={}", state.config.public_base_url, id);

    Ok((
        StatusCode::CREATED,
        Json(CreateSessionRequestResponse { id, url, expires_at }),
    ))
}

pub async fn poll_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<PollStatusResponse>, AppError> {
    let row = sqlx::query!(
        "SELECT status, plaintext_token FROM session_requests WHERE id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    if row.status != "approved" {
        return Ok(Json(PollStatusResponse {
            status: row.status,
            session_token: None,
        }));
    }

    // Atomically claim the token: transition approved → delivered and clear plaintext
    let updated = sqlx::query!(
        "UPDATE session_requests
         SET status = 'delivered', plaintext_token = NULL
         WHERE id = ? AND status = 'approved'",
        id
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if updated == 0 {
        return Ok(Json(PollStatusResponse {
            status: "delivered".to_string(),
            session_token: None,
        }));
    }

    Ok(Json(PollStatusResponse {
        status: "approved".to_string(),
        session_token: row.plaintext_token,
    }))
}

pub async fn list_pending(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Result<Json<Vec<SessionRequestRow>>, AppError> {
    let rows = sqlx::query_as!(
        SessionRequestRow,
        "SELECT id, label, status, requested_at, expires_at
         FROM session_requests
         WHERE status = 'pending' AND expires_at > datetime('now')
         ORDER BY requested_at DESC"
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}

pub async fn get_request(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<SessionRequestRow>, AppError> {
    let row = sqlx::query_as!(
        SessionRequestRow,
        "SELECT id, label, status, requested_at, expires_at
         FROM session_requests WHERE id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(row))
}

pub async fn approve(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let (plaintext, key_hash) = generate_api_key();
    let key_id = Uuid::new_v4().to_string();

    let mut tx = state.pool.begin().await?;

    let exists = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM session_requests
           WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')"#,
        id
    )
    .fetch_optional(&mut *tx)
    .await?;

    if exists.is_none() {
        return Err(AppError::NotFound);
    }

    sqlx::query!(
        "INSERT INTO api_keys (id, key_hash, label, type, status, expires_at, owner_id)
         VALUES (?, ?, 'session', 'session', 'active', datetime('now', '+15 hours'), ?)",
        key_id,
        key_hash,
        owner
    )
    .execute(&mut *tx)
    .await?;

    let scope_id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO api_key_scopes (id, api_key_id, scope, ops, deny)
         VALUES (?, ?, '*', 'read,write,delete,list', 0)",
        scope_id,
        key_id
    )
    .execute(&mut *tx)
    .await?;

    let updated = sqlx::query!(
        "UPDATE session_requests
         SET status = 'approved',
             plaintext_token = ?,
             session_key_id = ?,
             approved_by = ?,
             approved_at = datetime('now')
         WHERE id = ? AND status = 'pending'",
        plaintext,
        key_id,
        owner,
        id
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if updated == 0 {
        return Err(AppError::NotFound);
    }

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reject(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let updated = sqlx::query!(
        "UPDATE session_requests
         SET status = 'rejected', rejected_at = datetime('now')
         WHERE id = ? AND status = 'pending'",
        id
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if updated == 0 {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
