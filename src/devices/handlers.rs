use crate::{
    auth::middleware::AdminAuth,
    devices::model::*,
    error::AppError,
    state::{AppState, DeviceRegChallengeEntry},
    webauthn::handlers::load_passkeys_for_owner,
};
use axum::{
    extract::{Path, State},
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
