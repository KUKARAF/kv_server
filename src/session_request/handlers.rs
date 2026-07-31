use crate::{
    auth::middleware::AdminAuth,
    error::AppError,
    keys::generate::{generate_api_key, generate_emoji_sequence, hash_key},
    session_request::model::*,
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
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
    // Separate poll secret held only by the requester; stored hashed.
    let (poll_secret, poll_secret_hash) = generate_api_key();
    // Human-verifiable code the requester relays to the admin out-of-band; the admin
    // must submit it back at approval time so approving is bound to a secret only the
    // real requester holds, not just to whichever pending row gets clicked.
    let confirm_code = generate_emoji_sequence();
    let confirm_code_hash = bcrypt::hash(&confirm_code, 6)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt error: {e}")))?;
    let expires_at = sqlx::query_scalar!("SELECT datetime('now', '+15 minutes')")
        .fetch_one(&state.pool)
        .await?
        .unwrap_or_default();

    sqlx::query!(
        "INSERT INTO session_requests (id, label, expires_at, requested_duration_hours, poll_secret, confirm_code_hash) VALUES (?, ?, ?, ?, ?, ?)",
        id,
        body.label,
        expires_at,
        body.requested_duration_hours,
        poll_secret_hash,
        confirm_code_hash
    )
    .execute(&state.pool)
    .await?;

    let url = format!(
        "{}/admin/session-request.html?id={}",
        state.config.public_base_url, id
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateSessionRequestResponse {
            id,
            url,
            expires_at,
            poll_secret,
            confirm_code,
        }),
    ))
}

pub async fn poll_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<PollQuery>,
) -> Result<Json<PollStatusResponse>, AppError> {
    let row = sqlx::query!(
        "SELECT status, plaintext_token, poll_secret FROM session_requests WHERE id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    // Require the requester's poll secret. Compare hashes (constant-length hex) and return
    // NotFound on mismatch so the endpoint is not a token oracle for anyone holding only the id.
    let provided_hash = hash_key(&q.secret);
    match &row.poll_secret {
        Some(stored) if *stored == provided_hash => {}
        _ => return Err(AppError::NotFound),
    }

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
        "SELECT id, label, status, requested_at, expires_at, requested_duration_hours
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
        "SELECT id, label, status, requested_at, expires_at, requested_duration_hours
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
    Json(body): Json<ApproveSessionRequestBody>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let (plaintext, key_hash) = generate_api_key();
    let key_id = Uuid::new_v4().to_string();
    let duration_hours = body.approved_duration_hours.unwrap_or(24);

    let mut tx = state.pool.begin().await?;

    let row = sqlx::query!(
        "SELECT confirm_code_hash FROM session_requests
         WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')",
        id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    // Require proof that the approving admin actually confirmed the code with the
    // real requester — without this, approval is bound only to a click on a
    // self-reported label, which an unauthenticated attacker can spoof.
    let confirm_hash = row.confirm_code_hash.ok_or(AppError::NotFound)?;
    let matches = bcrypt::verify(&body.confirm_code, &confirm_hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt error: {e}")))?;
    if !matches {
        return Err(AppError::Forbidden(
            "confirm code does not match".to_string(),
        ));
    }

    let expires_offset = format!("+{} hours", duration_hours);
    sqlx::query!(
        "INSERT INTO api_keys (id, key_hash, label, type, status, expires_at, owner_id)
         VALUES (?, ?, 'session', 'session', 'active', datetime('now', ?), ?)",
        key_id,
        key_hash,
        expires_offset,
        owner
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
