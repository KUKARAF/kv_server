use crate::{auth::middleware::AdminAuth, devices::model::*, error::AppError, state::AppState};
use axum::{extract::{Path, State}, http::StatusCode, Json};
use std::sync::Arc;
use uuid::Uuid;

pub async fn register(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    let id = Uuid::new_v4().to_string();
    let owner_id = &auth.0.oidc_subject;

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

    sqlx::query!(
        "INSERT INTO devices (id, owner_id, name, public_key, key_type) VALUES (?, ?, ?, ?, ?)",
        id,
        owner_id,
        body.name,
        body.public_key,
        body.key_type,
    )
    .execute(&state.pool)
    .await?;

    tracing::info!(owner_id = %owner_id, device_id = %id, name = %body.name, key_type = %body.key_type, "device registered");

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
