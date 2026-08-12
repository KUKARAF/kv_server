use crate::{
    auth::middleware::AdminAuth,
    error::AppError,
    keys::generate::{generate_emoji_sequence, hash_key},
    kv::model::{compute_expires_at, DeviceKvWriteRequest, KvMetaResponse, KvUpsertRequest},
    middleware::{
        api_key::{check_kv_access, ApiKeyAuth},
        rate_limit::extract_real_ip,
    },
    state::{AccessLogEntry, AppState, ACCESS_LOG_CAP},
};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use uuid::Uuid;

fn log_access(
    state: &AppState,
    headers: &HeaderMap,
    addr: SocketAddr,
    auth: &ApiKeyAuth,
    key: &str,
) {
    let ip = extract_real_ip(headers, addr.ip(), state.config.trust_proxy_headers).to_string();
    let entry = AccessLogEntry {
        ip,
        api_key_id: auth.api_key_id.clone(),
        key: key.to_string(),
        op: auth.op.as_str().to_string(),
        ts: chrono::Utc::now(),
    };
    if let Ok(mut log) = state.access_log.lock() {
        if log.len() >= ACCESS_LOG_CAP {
            log.pop_front();
        }
        log.push_back(entry);
    }
}

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
        return Err(AppError::Forbidden(
            "key is not awaiting approval".to_string(),
        ));
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
        id,
        api_key.id,
        emoji_hash
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: ApiKeyAuth,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<String, AppError> {
    check_kv_access(&auth.allowed_keys, &key)?;
    log_access(&state, &headers, addr, &auth, &key);
    let (value, ttl_hours, ttl_sliding, expires_at, zt_ciphertext, device_encrypted) =
        if let Some(ref oid) = auth.owner_id {
            let row = sqlx::query!(
                r#"SELECT value, ttl_hours, ttl_sliding, expires_at, zt_ciphertext,
                      device_encrypted as "device_encrypted: bool"
               FROM kv_entries
               WHERE key = ? AND owner_id = ?
                 AND (expires_at IS NULL OR expires_at > datetime('now'))"#,
                key,
                oid
            )
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?;
            (
                row.value,
                row.ttl_hours,
                row.ttl_sliding,
                row.expires_at,
                row.zt_ciphertext,
                row.device_encrypted,
            )
        } else {
            // Open-access path — no owner filter
            let row = sqlx::query!(
                r#"SELECT value, ttl_hours, ttl_sliding, expires_at, zt_ciphertext,
                      device_encrypted as "device_encrypted: bool"
               FROM kv_entries
               WHERE key = ? AND open_access = 1
                 AND (expires_at IS NULL OR expires_at > datetime('now'))
               LIMIT 1"#,
                key
            )
            .fetch_optional(&state.pool)
            .await?
            .ok_or(AppError::NotFound)?;
            (
                row.value,
                row.ttl_hours,
                row.ttl_sliding,
                row.expires_at,
                row.zt_ciphertext,
                row.device_encrypted,
            )
        };

    if device_encrypted {
        return Err(AppError::Forbidden(
            "device-encrypted: fetch via /api/devices/<id>/kv/<key>".to_string(),
        ));
    }

    // Zero Trust entries: plaintext never stored — client must use the WebAuthn flow.
    if zt_ciphertext.is_some() {
        return Err(AppError::ZeroTrustRequired);
    }

    // Update sliding TTL if applicable (only for authenticated reads)
    if ttl_sliding != 0 {
        if let (Some(ttl_hours), Some(ref oid)) = (ttl_hours, auth.owner_id) {
            let new_expires = compute_expires_at(Some(ttl_hours));
            sqlx::query!(
                "UPDATE kv_entries SET expires_at = ? WHERE key = ? AND owner_id = ?",
                new_expires,
                key,
                oid
            )
            .execute(&state.pool)
            .await?;
        }
    }

    let _ = expires_at;
    Ok(value)
}

pub async fn upsert_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: ApiKeyAuth,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<KvUpsertRequest>,
) -> Result<StatusCode, AppError> {
    check_kv_access(&auth.allowed_keys, &key)?;
    log_access(&state, &headers, addr, &auth, &key);
    let owner_id = auth.owner_id.ok_or(AppError::Unauthorized)?;

    // Reserved key: only the hardcoded admin may set NOTIFY_API_KEY (defense-in-depth;
    // the notify read is already admin-scoped).
    if key == "NOTIFY_API_KEY" {
        let admin = crate::notify::admin_owner_id(&state.pool)
            .await
            .ok_or_else(|| AppError::Forbidden("reserved key".to_string()))?;
        if owner_id != admin {
            return Err(AppError::Forbidden("reserved key".to_string()));
        }
    }

    // Validate ZT fields: either all required ZT fields present, or none.
    let is_zt = body.zt_ciphertext.is_some()
        || body.zt_wrapped_dek.is_some()
        || body.zt_nonce.is_some()
        || body.zt_aad.is_some()
        || body.zt_prf_salt.is_some()
        || body.zt_credential_id.is_some();

    if is_zt {
        let required = [
            ("zt_ciphertext", &body.zt_ciphertext),
            ("zt_wrapped_dek", &body.zt_wrapped_dek),
            ("zt_nonce", &body.zt_nonce),
            ("zt_aad", &body.zt_aad),
            ("zt_prf_salt", &body.zt_prf_salt),
            ("zt_credential_id", &body.zt_credential_id),
        ];
        for (name, field) in &required {
            if field.is_none() {
                return Err(AppError::Forbidden(format!(
                    "missing zero trust field: {name}"
                )));
            }
        }
    }

    let expires_at = compute_expires_at(body.ttl_hours);
    let ttl_sliding = body.ttl_sliding as i64;
    let open_access = body.open_access as i64;

    sqlx::query!(
        "INSERT INTO kv_entries
             (key, owner_id, value, ttl_hours, ttl_sliding, expires_at, open_access,
              zt_ciphertext, zt_wrapped_dek, zt_nonce, zt_aad, zt_prf_salt, zt_credential_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(key, owner_id) DO UPDATE SET
             value          = excluded.value,
             ttl_hours      = excluded.ttl_hours,
             ttl_sliding    = excluded.ttl_sliding,
             expires_at     = excluded.expires_at,
             open_access    = excluded.open_access,
             zt_ciphertext  = excluded.zt_ciphertext,
             zt_wrapped_dek = excluded.zt_wrapped_dek,
             zt_nonce       = excluded.zt_nonce,
             zt_aad         = excluded.zt_aad,
             zt_prf_salt    = excluded.zt_prf_salt,
             zt_credential_id = excluded.zt_credential_id",
        key,
        owner_id,
        body.value,
        body.ttl_hours,
        ttl_sliding,
        expires_at,
        open_access,
        body.zt_ciphertext,
        body.zt_wrapped_dek,
        body.zt_nonce,
        body.zt_aad,
        body.zt_prf_salt,
        body.zt_credential_id
    )
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: ApiKeyAuth,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    check_kv_access(&auth.allowed_keys, &key)?;
    log_access(&state, &headers, addr, &auth, &key);
    let owner_id = auth.owner_id.ok_or(AppError::Unauthorized)?;

    let result = sqlx::query!(
        "DELETE FROM kv_entries WHERE key = ? AND owner_id = ?",
        key,
        owner_id
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: ApiKeyAuth,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<KvMetaResponse>>, AppError> {
    log_access(&state, &headers, addr, &auth, "");
    let owner_id = auth.owner_id.ok_or(AppError::Unauthorized)?;

    let rows: Vec<KvMetaResponse> = match q.prefix {
        Some(prefix) => {
            let pattern = format!("{}%", prefix);
            sqlx::query!(
                r#"SELECT key, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE key LIKE ? AND owner_id = ?
                   AND (expires_at IS NULL OR expires_at > datetime('now'))
                 ORDER BY key"#,
                pattern,
                owner_id
            )
            .fetch_all(&state.pool)
            .await?
            .into_iter()
            .map(|r| KvMetaResponse {
                key: r.key,
                ttl_hours: r.ttl_hours,
                ttl_sliding: r.ttl_sliding,
                expires_at: r.expires_at,
                open_access: r.open_access,
                created_at: r.created_at,
                device_encrypted: None,
                recipient_device_ids: None,
                source_management_key_id: None,
                source_provider_key_id: None,
            })
            .collect()
        }
        None => sqlx::query!(
            r#"SELECT key, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE owner_id = ?
                   AND (expires_at IS NULL OR expires_at > datetime('now'))
                 ORDER BY key"#,
            owner_id
        )
        .fetch_all(&state.pool)
        .await?
        .into_iter()
        .map(|r| KvMetaResponse {
            key: r.key,
            ttl_hours: r.ttl_hours,
            ttl_sliding: r.ttl_sliding,
            expires_at: r.expires_at,
            open_access: r.open_access,
            created_at: r.created_at,
            device_encrypted: None,
            recipient_device_ids: None,
            source_management_key_id: None,
            source_provider_key_id: None,
        })
        .collect(),
    };

    let rows = if let Some(ref keys) = auth.allowed_keys {
        rows.into_iter().filter(|e| keys.contains(&e.key)).collect()
    } else {
        rows
    };

    Ok(Json(rows))
}

// ── Zero Trust payload retrieval ─────────────────────────────────────────────

/// Claims embedded in the short-lived ZT JWT issued after a successful WebAuthn assertion.
#[derive(Debug, Serialize, Deserialize)]
pub struct ZtClaims {
    pub sub: String,    // owner_id
    pub kv_key: String, // the KV key this token is scoped to
    pub jti: String,    // unique token ID (for single-use enforcement)
    pub exp: usize,     // Unix timestamp expiry
}

#[derive(Serialize)]
pub struct ZtPayloadResponse {
    pub zt_ciphertext: String,
    pub zt_wrapped_dek: String,
    pub zt_nonce: String,
    pub zt_aad: String,
    pub zt_prf_salt: String,
}

/// Returns the encrypted ZT payload to a browser that has completed a WebAuthn ceremony.
/// Protected by a short-lived single-use JWT scoped to this specific key.
pub async fn get_zt_payload(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ZtPayloadResponse>, AppError> {
    // Extract and validate ZT JWT from Authorization: Bearer <token>
    let raw_token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let signing_key = state.config.session_signing_key.as_bytes();
    let token_data = decode::<ZtClaims>(
        raw_token,
        &DecodingKey::from_secret(signing_key),
        &Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized)?;

    let claims = token_data.claims;

    // Enforce: token must be scoped to exactly this key
    if claims.kv_key != key {
        return Err(AppError::Forbidden(
            "token scoped to a different key".to_string(),
        ));
    }

    // Enforce single-use: reject if jti already consumed
    let already_used: bool = sqlx::query_scalar!(
        "SELECT COUNT(*) > 0 FROM zt_used_tokens WHERE jti = ?",
        claims.jti
    )
    .fetch_one(&state.pool)
    .await?
        != 0;

    if already_used {
        return Err(AppError::Forbidden("token already used".to_string()));
    }

    // Mark token as consumed (store jti with expiry timestamp for cleanup)
    let exp_str = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "1970-01-01 00:00:00".to_string());
    sqlx::query!(
        "INSERT OR IGNORE INTO zt_used_tokens (jti, expires_at) VALUES (?, ?)",
        claims.jti,
        exp_str
    )
    .execute(&state.pool)
    .await?;

    // Fetch ZT payload — owner scoped, entry must exist and not be expired
    let row = sqlx::query!(
        "SELECT zt_ciphertext, zt_wrapped_dek, zt_nonce, zt_aad, zt_prf_salt
         FROM kv_entries
         WHERE key = ? AND owner_id = ?
           AND zt_ciphertext IS NOT NULL
           AND (expires_at IS NULL OR expires_at > datetime('now'))",
        key,
        claims.sub
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(ZtPayloadResponse {
        zt_ciphertext: row.zt_ciphertext.unwrap_or_default(),
        zt_wrapped_dek: row.zt_wrapped_dek.unwrap_or_default(),
        zt_nonce: row.zt_nonce.unwrap_or_default(),
        zt_aad: row.zt_aad.unwrap_or_default(),
        zt_prf_salt: row.zt_prf_salt.unwrap_or_default(),
    }))
}

// ── Device-encrypted KV ─────────────────────────────────────────────────────

/// Admin writes a device-encrypted KV entry. The value is pre-encrypted client-side
/// with a random DEK; this endpoint stores the body ciphertext + per-device DEK wraps.
pub async fn write_device_kv(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<DeviceKvWriteRequest>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;

    if body.recipients.is_empty() {
        return Err(AppError::Forbidden(
            "at least one recipient is required".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await?;

    // Upsert the body ciphertext
    sqlx::query!(
        "INSERT INTO device_kv_bodies (kv_key, owner_id, nonce, ciphertext, aad)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(kv_key, owner_id) DO UPDATE SET
             nonce      = excluded.nonce,
             ciphertext = excluded.ciphertext,
             aad        = excluded.aad,
             created_at = datetime('now')",
        body.key,
        owner_id,
        body.nonce,
        body.ciphertext,
        body.aad
    )
    .execute(&mut *tx)
    .await?;

    // Remove existing recipients for this key (re-encrypt replaces all)
    sqlx::query!(
        "DELETE FROM device_kv_recipients WHERE kv_key = ? AND owner_id = ?",
        body.key,
        owner_id
    )
    .execute(&mut *tx)
    .await?;

    for r in &body.recipients {
        let rid = uuid::Uuid::new_v4().to_string();
        sqlx::query!(
            "INSERT INTO device_kv_recipients
                 (id, kv_key, owner_id, device_id, key_type, ephemeral_pub, dek_nonce, encrypted_dek)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rid, body.key, owner_id, r.device_id, r.key_type,
            r.ephemeral_pub, r.dek_nonce, r.encrypted_dek
        )
        .execute(&mut *tx)
        .await?;
    }

    // Mark kv_entries row as device-encrypted (create if missing)
    sqlx::query!(
        "INSERT INTO kv_entries (key, owner_id, value, device_encrypted)
         VALUES (?, ?, '', 1)
         ON CONFLICT(key, owner_id) DO UPDATE SET
             device_encrypted = 1",
        body.key,
        owner_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(owner_id = %owner_id, key = %body.key, recipients = body.recipients.len(), "device-encrypted KV written");
    Ok(StatusCode::CREATED)
}
