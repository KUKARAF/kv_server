use crate::{
    auth::middleware::AdminAuth, error::AppError, management_keys::model::*, state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

// ── Management keys ─────────────────────────────────────────────────────────

pub async fn create_management_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<CreateManagementKeyRequest>,
) -> Result<(StatusCode, Json<CreateManagementKeyResponse>), AppError> {
    let owner_id = &auth.0.oidc_subject;

    if body.recipients.is_empty() {
        return Err(AppError::Forbidden(
            "at least one recipient is required".to_string(),
        ));
    }
    validate_limit_reset(&body.default_limit_reset)?;

    let id = Uuid::new_v4().to_string();
    let mut tx = state.pool.begin().await?;

    sqlx::query!(
        "INSERT INTO management_keys (id, owner_id, provider, label, default_limit, default_limit_reset)
         VALUES (?, ?, ?, ?, ?, ?)",
        id,
        owner_id,
        body.provider,
        body.label,
        body.default_limit,
        body.default_limit_reset,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO management_key_bodies (management_key_id, nonce, ciphertext, aad)
         VALUES (?, ?, ?, ?)",
        id,
        body.nonce,
        body.ciphertext,
        body.aad,
    )
    .execute(&mut *tx)
    .await?;

    for r in &body.recipients {
        let rid = Uuid::new_v4().to_string();
        sqlx::query!(
            "INSERT INTO management_key_recipients
                 (id, management_key_id, device_id, key_type, ephemeral_pub, dek_nonce, encrypted_dek)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            rid, id, r.device_id, r.key_type, r.ephemeral_pub, r.dek_nonce, r.encrypted_dek
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(owner_id = %owner_id, management_key_id = %id, provider = %body.provider, "management key created");
    Ok((
        StatusCode::CREATED,
        Json(CreateManagementKeyResponse { id }),
    ))
}

pub async fn list_management_keys(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<ManagementKeyRow>>, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let rows = sqlx::query!(
        "SELECT id, provider, label, status, created_at, last_used_at, default_limit, default_limit_reset
         FROM management_keys WHERE owner_id = ? ORDER BY created_at DESC",
        owner_id
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|r| ManagementKeyRow {
        id: r.id.unwrap_or_default(),
        provider: r.provider,
        label: r.label,
        status: r.status,
        created_at: r.created_at,
        last_used_at: r.last_used_at,
        default_limit: r.default_limit,
        default_limit_reset: r.default_limit_reset,
    })
    .collect();
    Ok(Json(rows))
}

fn validate_limit_reset(value: &Option<String>) -> Result<(), AppError> {
    match value.as_deref() {
        None | Some("daily") | Some("weekly") | Some("monthly") => Ok(()),
        Some(other) => Err(AppError::Forbidden(format!(
            "invalid default_limit_reset: {other}"
        ))),
    }
}

pub async fn update_management_key_defaults(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
    Json(body): Json<UpdateManagementKeyDefaultsRequest>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;
    validate_limit_reset(&body.default_limit_reset)?;

    let affected = sqlx::query!(
        "UPDATE management_keys SET default_limit = ?, default_limit_reset = ?
         WHERE id = ? AND owner_id = ?",
        body.default_limit,
        body.default_limit_reset,
        id,
        owner_id,
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
pub async fn get_management_key_envelope(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path((id, device_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_id = &auth.0.oidc_subject;

    let owned = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM management_keys WHERE id = ? AND owner_id = ?"#,
        id,
        owner_id,
    )
    .fetch_optional(&state.pool)
    .await?;
    if owned.is_none() {
        return Err(AppError::NotFound);
    }

    let body = sqlx::query!(
        "SELECT nonce, ciphertext, aad FROM management_key_bodies WHERE management_key_id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let recipient = sqlx::query!(
        "SELECT key_type, ephemeral_pub, dek_nonce, encrypted_dek
         FROM management_key_recipients WHERE management_key_id = ? AND device_id = ?",
        id,
        device_id,
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let _ = sqlx::query!(
        "UPDATE management_keys SET last_used_at = datetime('now') WHERE id = ?",
        id
    )
    .execute(&state.pool)
    .await;
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

pub async fn revoke_management_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let affected = sqlx::query!(
        "UPDATE management_keys SET status = 'revoked' WHERE id = ? AND owner_id = ? AND status = 'active'",
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

// ── Provisioned keys ─────────────────────────────────────────────────────────

async fn require_owned_management_key(
    state: &AppState,
    id: &str,
    owner_id: &str,
) -> Result<(), AppError> {
    let owned = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM management_keys WHERE id = ? AND owner_id = ?"#,
        id,
        owner_id,
    )
    .fetch_optional(&state.pool)
    .await?;
    if owned.is_none() {
        return Err(AppError::NotFound);
    }
    Ok(())
}

pub async fn create_provisioned_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(management_key_id): Path<String>,
    Json(body): Json<CreateProvisionedKeyRequest>,
) -> Result<(StatusCode, Json<CreateProvisionedKeyResponse>), AppError> {
    let owner_id = &auth.0.oidc_subject;
    require_owned_management_key(&state, &management_key_id, owner_id).await?;

    if body.recipients.is_empty() {
        return Err(AppError::Forbidden(
            "at least one recipient is required".to_string(),
        ));
    }

    let provider = sqlx::query_scalar!(
        "SELECT provider FROM management_keys WHERE id = ?",
        management_key_id
    )
    .fetch_one(&state.pool)
    .await?;

    let id = Uuid::new_v4().to_string();
    let mut tx = state.pool.begin().await?;

    sqlx::query!(
        "INSERT INTO provisioned_keys (id, management_key_id, provider, provider_key_id, label)
         VALUES (?, ?, ?, ?, ?)",
        id,
        management_key_id,
        provider,
        body.provider_key_id,
        body.label,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO provisioned_key_bodies (provisioned_key_id, nonce, ciphertext, aad)
         VALUES (?, ?, ?, ?)",
        id,
        body.nonce,
        body.ciphertext,
        body.aad,
    )
    .execute(&mut *tx)
    .await?;

    for r in &body.recipients {
        let rid = Uuid::new_v4().to_string();
        sqlx::query!(
            "INSERT INTO provisioned_key_recipients
                 (id, provisioned_key_id, device_id, key_type, ephemeral_pub, dek_nonce, encrypted_dek)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            rid, id, r.device_id, r.key_type, r.ephemeral_pub, r.dek_nonce, r.encrypted_dek
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(owner_id = %owner_id, management_key_id = %management_key_id, provisioned_key_id = %id, "provisioned key stored");
    Ok((
        StatusCode::CREATED,
        Json(CreateProvisionedKeyResponse { id }),
    ))
}

pub async fn list_provisioned_keys(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(management_key_id): Path<String>,
) -> Result<Json<Vec<ProvisionedKeyRow>>, AppError> {
    let owner_id = &auth.0.oidc_subject;
    require_owned_management_key(&state, &management_key_id, owner_id).await?;

    let rows = sqlx::query!(
        "SELECT id, provider, provider_key_id, label, status, created_at, revoked_at
         FROM provisioned_keys WHERE management_key_id = ? ORDER BY created_at DESC",
        management_key_id
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|r| ProvisionedKeyRow {
        id: r.id.unwrap_or_default(),
        provider: r.provider,
        provider_key_id: r.provider_key_id,
        label: r.label,
        status: r.status,
        created_at: r.created_at,
        revoked_at: r.revoked_at,
    })
    .collect();
    Ok(Json(rows))
}

pub async fn get_provisioned_key_envelope(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path((management_key_id, provisioned_key_id, device_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_id = &auth.0.oidc_subject;
    require_owned_management_key(&state, &management_key_id, owner_id).await?;

    let body = sqlx::query!(
        "SELECT b.nonce, b.ciphertext, b.aad
         FROM provisioned_key_bodies b
         JOIN provisioned_keys k ON k.id = b.provisioned_key_id
         WHERE b.provisioned_key_id = ? AND k.management_key_id = ?",
        provisioned_key_id,
        management_key_id,
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let recipient = sqlx::query!(
        "SELECT key_type, ephemeral_pub, dek_nonce, encrypted_dek
         FROM provisioned_key_recipients WHERE provisioned_key_id = ? AND device_id = ?",
        provisioned_key_id,
        device_id,
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

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

/// Hard delete — called after the caller has already deleted the key on the provider,
/// so the stored encrypted copy is no longer recoverable-but-useless; bodies/recipients
/// cascade via ON DELETE CASCADE.
pub async fn delete_provisioned_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path((management_key_id, provisioned_key_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;
    require_owned_management_key(&state, &management_key_id, owner_id).await?;

    let affected = sqlx::query!(
        "DELETE FROM provisioned_keys WHERE id = ? AND management_key_id = ?",
        provisioned_key_id,
        management_key_id,
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
