use crate::{
    auth::middleware::AdminAuth,
    error::AppError,
    keys::generate::{generate_api_key, hash_key},
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

/// Issue a device-bound challenge: mint a random nonce, ECDH-wrap it to the device's public
/// key, and store only its hash. The caller must decrypt the envelope with the device's
/// private key and submit the plaintext back to `create_request` — proving possession
/// before a pending request (and therefore an admin-visible approval prompt) is ever
/// created. Without this, anyone who merely knew a device_id (leaked log, screenshot,
/// whatever) could spam legitimate-looking approval requests for a real device forever.
pub async fn create_challenge(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateChallengeBody>,
) -> Result<(StatusCode, Json<CreateChallengeResponse>), AppError> {
    let device = sqlx::query!(
        "SELECT key_type, public_key FROM devices WHERE id = ?",
        body.device_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let challenge_id = Uuid::new_v4().to_string();
    let (nonce, nonce_hash) = generate_api_key();

    let envelope = crate::crypto::wrap_for_device(
        &device.key_type,
        &device.public_key,
        &challenge_id,
        nonce.as_bytes(),
    )?;

    let expires_at = sqlx::query_scalar!("SELECT datetime('now', '+2 minutes')")
        .fetch_one(&state.pool)
        .await?
        .unwrap_or_default();

    sqlx::query!(
        "INSERT INTO session_request_challenges (id, device_id, nonce_hash, expires_at) VALUES (?, ?, ?, ?)",
        challenge_id,
        body.device_id,
        nonce_hash,
        expires_at,
    )
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateChallengeResponse {
            challenge_id,
            envelope: envelope.into(),
            expires_at,
        }),
    ))
}

pub async fn create_request(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateSessionRequestBody>,
) -> Result<(StatusCode, Json<CreateSessionRequestResponse>), AppError> {
    let id = Uuid::new_v4().to_string();
    // Separate poll secret held only by the requester; stored hashed.
    let (poll_secret, poll_secret_hash) = generate_api_key();
    // Token required to approve — held only by the requester, never exposed to the admin
    // except via the link/QR the requester itself displays.
    let (approve_token, approve_token_hash) = generate_api_key();

    let mut tx = state.pool.begin().await?;

    // The challenge proves possession of the device's private key — the caller no longer
    // gets to assert which device it's requesting for via the request body; the device is
    // whichever one the already-verified challenge was issued for. NotFound (not Forbidden)
    // for every failure mode here so an attacker can't distinguish "wrong nonce" from
    // "unknown/expired challenge".
    let challenge = sqlx::query!(
        "SELECT device_id, nonce_hash FROM session_request_challenges
         WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')",
        body.challenge_id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    if hash_key(&body.nonce) != challenge.nonce_hash {
        return Err(AppError::NotFound);
    }

    // Atomically consume: a decrypted nonce can only ever create one pending request.
    let consumed = sqlx::query!(
        "UPDATE session_request_challenges SET status = 'consumed'
         WHERE id = ? AND status = 'pending'",
        body.challenge_id
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if consumed == 0 {
        return Err(AppError::NotFound);
    }

    let expires_at = sqlx::query_scalar!("SELECT datetime('now', '+15 minutes')")
        .fetch_one(&mut *tx)
        .await?
        .unwrap_or_default();

    sqlx::query!(
        "INSERT INTO session_requests (id, label, expires_at, requested_duration_hours, poll_secret, device_id, approve_token_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
        id,
        body.label,
        expires_at,
        body.requested_duration_hours,
        poll_secret_hash,
        challenge.device_id,
        approve_token_hash,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let url = format!(
        "{}/admin/session-request.html?id={}&token={}",
        state.config.public_base_url, id, approve_token
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateSessionRequestResponse {
            id,
            url,
            expires_at,
            poll_secret,
            approve_token,
        }),
    ))
}

pub async fn poll_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<PollQuery>,
) -> Result<Json<PollStatusResponse>, AppError> {
    let row = sqlx::query!(
        "SELECT status, poll_secret,
                wrap_key_type, wrap_nonce, wrap_ciphertext, wrap_aad,
                wrap_ephemeral_pub, wrap_dek_nonce, wrap_encrypted_dek
         FROM session_requests WHERE id = ?",
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
            envelope: None,
        }));
    }

    // Atomically claim the token: transition approved → delivered and clear the wrapped
    // envelope so it can only be read once.
    let updated = sqlx::query!(
        "UPDATE session_requests
         SET status = 'delivered',
             wrap_key_type = NULL, wrap_nonce = NULL, wrap_ciphertext = NULL, wrap_aad = NULL,
             wrap_ephemeral_pub = NULL, wrap_dek_nonce = NULL, wrap_encrypted_dek = NULL
         WHERE id = ? AND status = 'approved'",
        id
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if updated == 0 {
        return Ok(Json(PollStatusResponse {
            status: "delivered".to_string(),
            envelope: None,
        }));
    }

    // We won the claim, so this poller gets the one-time envelope. All wrap_* columns are
    // written together at approval, so if one is present they all are.
    let envelope = match (
        row.wrap_key_type,
        row.wrap_nonce,
        row.wrap_ciphertext,
        row.wrap_aad,
        row.wrap_ephemeral_pub,
        row.wrap_dek_nonce,
        row.wrap_encrypted_dek,
    ) {
        (
            Some(key_type),
            Some(nonce),
            Some(ciphertext),
            Some(aad),
            Some(ephemeral_pub),
            Some(dek_nonce),
            Some(encrypted_dek),
        ) => Some(SessionEnvelope {
            nonce,
            ciphertext,
            aad,
            recipient: EnvelopeRecipient {
                key_type,
                ephemeral_pub,
                dek_nonce,
                encrypted_dek,
            },
        }),
        _ => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "approved session_request {id} missing wrap columns"
            )))
        }
    };

    Ok(Json(PollStatusResponse {
        status: "approved".to_string(),
        envelope,
    }))
}

pub async fn list_pending(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<SessionRequestRow>>, AppError> {
    let owner = &auth.0.oidc_subject;
    let rows = sqlx::query!(
        "SELECT sr.id, sr.label, sr.status, sr.requested_at, sr.expires_at,
                sr.requested_duration_hours, d.name AS device_name
         FROM session_requests sr
         LEFT JOIN devices d ON d.id = sr.device_id
         WHERE sr.status = 'pending' AND sr.expires_at > datetime('now') AND d.owner_id = ?
         ORDER BY sr.requested_at DESC",
        owner
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|r| SessionRequestRow {
        id: r.id,
        label: r.label,
        status: r.status,
        requested_at: r.requested_at,
        expires_at: r.expires_at,
        requested_duration_hours: r.requested_duration_hours,
        device_name: Some(r.device_name),
        is_own_device: true,
    })
    .collect();

    Ok(Json(rows))
}

pub async fn get_request(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<Json<SessionRequestRow>, AppError> {
    let owner = &auth.0.oidc_subject;
    let row = sqlx::query!(
        "SELECT sr.id, sr.label, sr.status, sr.requested_at, sr.expires_at,
                sr.requested_duration_hours, d.name AS device_name, d.owner_id AS device_owner_id
         FROM session_requests sr
         LEFT JOIN devices d ON d.id = sr.device_id
         WHERE sr.id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let is_own_device = row.device_owner_id.as_deref() == Some(owner.as_str());

    Ok(Json(SessionRequestRow {
        id: row.id,
        label: row.label,
        status: row.status,
        requested_at: row.requested_at,
        expires_at: row.expires_at,
        requested_duration_hours: row.requested_duration_hours,
        device_name: row.device_name,
        is_own_device,
    }))
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
        "SELECT device_id, approve_token_hash FROM session_requests
         WHERE id = ? AND status = 'pending' AND expires_at > datetime('now')",
        id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    // The token is held only by the requester and delivered to the admin exclusively via the
    // requesting device's own link/QR — never via the dashboard toast or any id-only surface.
    // Without this, a valid admin session + the request id (visible from a bare notification)
    // would be sufficient to approve, which is exactly the "click notification, click
    // approve" gap this closes.
    if hash_key(&body.token) != row.approve_token_hash {
        return Err(AppError::NotFound);
    }

    // Wrap the freshly minted token to the request's device public key, so the delivered
    // token is unusable without that device's private key. The device is captured at create
    // time; if it's gone (deleted between request and approval) we can't deliver securely.
    let device_id = row.device_id.ok_or(AppError::NotFound)?;
    let device = sqlx::query!(
        "SELECT key_type, public_key, owner_id FROM devices WHERE id = ?",
        device_id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    // Only the device's own owner may approve a session request for it — the admin's decision
    // is grounded in the device's real, immutable registered identity, not a self-reported
    // label an unauthenticated caller could spoof.
    if device.owner_id != *owner {
        return Err(AppError::Forbidden(
            "you do not own this request's device".to_string(),
        ));
    }

    let envelope = crate::crypto::wrap_for_device(
        &device.key_type,
        &device.public_key,
        &id,
        plaintext.as_bytes(),
    )?;

    let expires_offset = format!("+{} hours", duration_hours);
    sqlx::query!(
        "INSERT INTO api_keys (id, key_hash, label, type, status, expires_at, owner_id, device_id)
         VALUES (?, ?, 'session', 'session', 'active', datetime('now', ?), ?, ?)",
        key_id,
        key_hash,
        expires_offset,
        owner,
        device_id
    )
    .execute(&mut *tx)
    .await?;

    let updated = sqlx::query!(
        "UPDATE session_requests
         SET status = 'approved',
             session_key_id = ?,
             approved_by = ?,
             approved_at = datetime('now'),
             wrap_key_type = ?, wrap_nonce = ?, wrap_ciphertext = ?, wrap_aad = ?,
             wrap_ephemeral_pub = ?, wrap_dek_nonce = ?, wrap_encrypted_dek = ?
         WHERE id = ? AND status = 'pending'",
        key_id,
        owner,
        envelope.key_type,
        envelope.nonce,
        envelope.ciphertext,
        envelope.aad,
        envelope.ephemeral_pub,
        envelope.dek_nonce,
        envelope.encrypted_dek,
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
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;

    // Same ownership check as `approve` — an admin may only reject requests targeting a
    // device they themselves own, not any pending request on the server.
    let device_owner = sqlx::query_scalar!(
        "SELECT d.owner_id FROM session_requests sr
         JOIN devices d ON d.id = sr.device_id
         WHERE sr.id = ? AND sr.status = 'pending'",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    if device_owner != *owner {
        return Err(AppError::Forbidden(
            "you do not own this request's device".to_string(),
        ));
    }

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
