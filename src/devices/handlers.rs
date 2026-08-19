use crate::{
    auth::middleware::AdminAuth,
    devices::model::*,
    error::AppError,
    keys::generate::{generate_api_key, hash_key},
    state::{AppState, DeviceRegChallengeEntry},
    webauthn::handlers::load_passkeys_for_owner,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

fn webauthn_unavailable() -> AppError {
    AppError::Internal(anyhow::anyhow!(
        "WebAuthn not configured (check WEBAUTHN_RP_ID/WEBAUTHN_RP_ORIGIN)"
    ))
}

/// Step 1 of device enrolment: return a WebAuthn authentication challenge and stash the
/// pending device fields. Requires the owner to already have a registered hardware key —
/// enrolling a device (the trust root for device-bound sessions) must be a physical key
/// touch, so a stolen OIDC session alone can't add an attacker device.
pub async fn register_begin(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceBeginResponse>, AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(webauthn_unavailable)?;
    let owner_id = &auth.0.oidc_subject;

    // Fail fast on duplicate name (re-checked at finish under the transaction).
    let exists = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM devices WHERE owner_id = ? AND name = ?"#,
        owner_id,
        body.name,
    )
    .fetch_optional(&state.pool)
    .await?;
    if exists.is_some() {
        return Err(AppError::Conflict(format!(
            "device '{}' already exists",
            body.name
        )));
    }

    let passkeys = load_passkeys_for_owner(&state, owner_id, None).await?;
    if passkeys.is_empty() {
        return Err(AppError::Forbidden(
            "register a hardware key first (Zero Trust → Register key) before enrolling a device"
                .to_string(),
        ));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn auth begin: {e}")))?;

    let challenge_id = Uuid::new_v4().to_string();
    state.device_reg_challenges.insert(
        challenge_id.clone(),
        DeviceRegChallengeEntry {
            state: auth_state,
            owner_id: owner_id.clone(),
            name: body.name,
            public_key: body.public_key,
            key_type: body.key_type,
        },
    );

    let options = serde_json::to_value(&rcr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize options: {e}")))?;

    Ok(Json(RegisterDeviceBeginResponse {
        challenge_id,
        options,
    }))
}

/// Step 2: verify the signed assertion server-side and only then insert the device.
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<RegisterDeviceFinishRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(webauthn_unavailable)?;
    let owner_id = &auth.0.oidc_subject;

    let entry = state
        .device_reg_challenges
        .remove(&body.challenge_id)
        .ok_or_else(|| AppError::Forbidden("unknown or expired enrolment challenge".to_string()))?
        .1;

    // The challenge is bound to the owner who began it; a different admin can't complete it.
    if entry.owner_id != *owner_id {
        return Err(AppError::Forbidden(
            "enrolment challenge belongs to another account".to_string(),
        ));
    }

    webauthn
        .finish_passkey_authentication(&body.assertion, &entry.state)
        .map_err(|e| AppError::Forbidden(format!("WebAuthn verification failed: {e}")))?;

    let id = Uuid::new_v4().to_string();
    let exists = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM devices WHERE owner_id = ? AND name = ?"#,
        owner_id,
        entry.name,
    )
    .fetch_optional(&state.pool)
    .await?;
    if exists.is_some() {
        return Err(AppError::Conflict(format!(
            "device '{}' already exists",
            entry.name
        )));
    }

    sqlx::query!(
        "INSERT INTO devices (id, owner_id, name, public_key, key_type) VALUES (?, ?, ?, ?, ?)",
        id,
        owner_id,
        entry.name,
        entry.public_key,
        entry.key_type,
    )
    .execute(&state.pool)
    .await?;

    tracing::info!(owner_id = %owner_id, device_id = %id, name = %entry.name, key_type = %entry.key_type, "device registered (webauthn-gated)");

    Ok((StatusCode::CREATED, Json(RegisterDeviceResponse { id })))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<DeviceRow>>, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let rows = sqlx::query!(
        "SELECT id, name, key_type, public_key, created_at, last_seen_at FROM devices WHERE owner_id = ? ORDER BY created_at DESC",
        owner_id
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|r| DeviceRow {
        id: r.id.unwrap_or_default(),
        name: r.name,
        key_type: r.key_type,
        public_key: r.public_key,
        created_at: r.created_at,
        last_seen_at: r.last_seen_at,
    })
    .collect();
    Ok(Json(rows))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let affected = sqlx::query!(
        "DELETE FROM devices WHERE id = ? AND owner_id = ?",
        id,
        owner_id
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Self-service enrollment step 1 (unauthenticated, mirrors session_request::create_request):
/// a headless client generates its own keypair and proposes itself, so a human never has to
/// manually copy the public key into the web panel. Nothing is trusted yet — an admin must
/// still confirm via the real WebAuthn ceremony (`register_begin`/`register_finish`) below.
pub async fn propose(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ProposeDeviceBody>,
) -> Result<(StatusCode, Json<ProposeDeviceResponse>), AppError> {
    let id = Uuid::new_v4().to_string();
    let (poll_secret, poll_secret_hash) = generate_api_key();
    // Token required to load/link this proposal — held only by the proposer, never exposed
    // to the admin except via the link/QR the proposer itself displays.
    let (confirm_token, confirm_token_hash) = generate_api_key();

    let expires_at = sqlx::query_scalar!("SELECT datetime('now', '+30 minutes')")
        .fetch_one(&state.pool)
        .await?
        .unwrap_or_default();

    sqlx::query!(
        "INSERT INTO device_proposals (id, name, public_key, key_type, poll_secret_hash, expires_at, confirm_token_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        id,
        body.name,
        body.public_key,
        body.key_type,
        poll_secret_hash,
        expires_at,
        confirm_token_hash,
    )
    .execute(&state.pool)
    .await?;

    let url = format!(
        "{}/admin/device-proposal.html?id={}&token={}",
        state.config.public_base_url, id, confirm_token
    );

    Ok((
        StatusCode::CREATED,
        Json(ProposeDeviceResponse {
            id,
            url,
            expires_at,
            poll_secret,
            confirm_token,
        }),
    ))
}

/// Self-service enrollment step 2: the proposer polls for the device_id an admin assigned
/// by confirming. Not a secret capability (knowing your own device_id grants nothing), so
/// unlike session-token delivery this can be polled idempotently after confirmation.
pub async fn poll_proposal_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<ProposalPollQuery>,
) -> Result<Json<ProposalPollResponse>, AppError> {
    let row = sqlx::query!(
        "SELECT status, poll_secret_hash, resulting_device_id FROM device_proposals WHERE id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    if hash_key(&q.secret) != row.poll_secret_hash {
        return Err(AppError::NotFound);
    }

    Ok(Json(ProposalPollResponse {
        status: row.status,
        device_id: row.resulting_device_id,
    }))
}

/// Admin-facing: list pending proposals. Deliberately owner-agnostic — no device row (and
/// therefore no owner_id) exists yet at proposal time, unlike session_requests which can
/// join through an already-registered device. Any logged-in admin sees all pending
/// proposals; acceptable for this single/small-user deployment (see plan notes) — revisit
/// if this ever grows beyond that.
pub async fn list_proposals(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Result<Json<Vec<DeviceProposalRow>>, AppError> {
    let rows = sqlx::query_as!(
        DeviceProposalRow,
        "SELECT id, name, public_key, key_type, requested_at, expires_at
         FROM device_proposals
         WHERE status = 'pending' AND expires_at > datetime('now')
         ORDER BY requested_at DESC"
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}

/// Requires the proposer's own `confirm_token` (never seen by the admin dashboard) because
/// this response feeds directly into the real WebAuthn `enrolDevice()` call on the review
/// page — gating only `link_proposal` would still let an admin do a genuine passkey touch
/// against an attacker-controlled public key if they reached this page via a bare id (e.g. a
/// same-named proposal racing the real one on the dashboard toast).
pub async fn get_proposal(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(id): Path<String>,
    Query(q): Query<ProposalTokenQuery>,
) -> Result<Json<DeviceProposalRow>, AppError> {
    let row = sqlx::query!(
        "SELECT id, name, public_key, key_type, requested_at, expires_at, confirm_token_hash
         FROM device_proposals WHERE id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    if hash_key(&q.token) != row.confirm_token_hash {
        return Err(AppError::NotFound);
    }

    Ok(Json(DeviceProposalRow {
        id: row.id,
        name: row.name,
        public_key: row.public_key,
        key_type: row.key_type,
        requested_at: row.requested_at,
        expires_at: row.expires_at,
    }))
}

/// Links a confirmed proposal to the device row `register_finish` just created (the
/// WebAuthn ceremony itself is unchanged — this is a small bookkeeping step run right
/// after, from the same admin page). Single-use: a proposal can only ever be linked once.
pub async fn link_proposal(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<LinkProposalBody>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;

    let proposal = sqlx::query!(
        "SELECT confirm_token_hash FROM device_proposals WHERE id = ? AND status = 'pending'",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    if hash_key(&body.token) != proposal.confirm_token_hash {
        return Err(AppError::NotFound);
    }

    let updated = sqlx::query!(
        "UPDATE device_proposals
         SET status = 'confirmed', resulting_device_id = ?, confirmed_at = datetime('now'), confirmed_by = ?
         WHERE id = ? AND status = 'pending'",
        body.device_id,
        owner_id,
        id,
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if updated == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reject_proposal(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let updated = sqlx::query!(
        "UPDATE device_proposals SET status = 'rejected' WHERE id = ? AND status = 'pending'",
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

/// Device-authenticated: returns the encrypted body + this device's DEK wrap.
/// Auth: Bearer <approval-type token> accepted by AdminAuth.
pub async fn get_device_kv(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path((device_id, kv_key)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_id = &auth.0.oidc_subject;

    // Verify device belongs to authenticated owner
    let device_exists = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM devices WHERE id = ? AND owner_id = ?"#,
        device_id,
        owner_id,
    )
    .fetch_optional(&state.pool)
    .await?;

    if device_exists.is_none() {
        return Err(AppError::NotFound);
    }

    let body = sqlx::query!(
        "SELECT nonce, ciphertext, aad FROM device_kv_bodies WHERE kv_key = ? AND owner_id = ?",
        kv_key,
        owner_id,
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let recipient = sqlx::query!(
        "SELECT key_type, ephemeral_pub, dek_nonce, encrypted_dek
         FROM device_kv_recipients
         WHERE device_id = ? AND kv_key = ? AND owner_id = ?",
        device_id,
        kv_key,
        owner_id,
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    // Touch last_seen_at
    let _ = sqlx::query!(
        "UPDATE devices SET last_seen_at = datetime('now') WHERE id = ?",
        device_id
    )
    .execute(&state.pool)
    .await;

    Ok(Json(serde_json::json!({
        "nonce": body.nonce,
        "ciphertext": body.ciphertext,
        "aad": body.aad,
        "recipient": {
            "key_type": recipient.key_type,
            "ephemeral_pub": recipient.ephemeral_pub,
            "dek_nonce": recipient.dek_nonce,
            "encrypted_dek": recipient.encrypted_dek,
        }
    })))
}
