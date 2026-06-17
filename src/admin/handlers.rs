use crate::{
    admin::model::*,
    auth::middleware::AdminAuth,
    error::AppError,
    keys::generate::{generate_api_key, generate_emoji_sequence},
    kv::model::compute_expires_at,
    state::AppState,
};
use serde_json;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use std::sync::Arc;
use uuid::Uuid;

// ── API Keys ────────────────────────────────────────────────────────────────

pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<ApiKeyWithScopes>>, AppError> {
    let owner = &auth.0.oidc_subject;
    let keys = sqlx::query_as!(
        ApiKeyRow,
        r#"SELECT id, label, type as "key_type", status, expires_at, created_at, last_used_at
           FROM api_keys WHERE owner_id = ? ORDER BY created_at DESC"#,
        owner
    )
    .fetch_all(&state.pool)
    .await?;

    let mut result = Vec::with_capacity(keys.len());
    for key in keys {
        let scopes = sqlx::query_as!(
            ScopeRow,
            "SELECT id, api_key_id, scope, ops, deny as \"deny: bool\" FROM api_key_scopes WHERE api_key_id = ?",
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
    auth: AdminAuth,
    Json(body): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), AppError> {
    let valid_types = ["standard", "one_time", "approval_required", "zero_trust", "shareable"];
    if !valid_types.contains(&body.key_type.as_str()) {
        return Err(AppError::Forbidden(format!(
            "invalid key type: {}",
            body.key_type
        )));
    }

    // For one-time and shareable keys with entry_scope, allow empty scopes array and generate scope automatically
    let mut scopes = body.scopes.clone();
    let is_one_time_with_entry_scope = body.key_type == "one_time" && body.entry_scope.is_some();
    let is_shareable_with_entry_scope = body.key_type == "shareable" && body.entry_scope.is_some();
    
    if is_one_time_with_entry_scope || is_shareable_with_entry_scope {
        // One-time or shareable key tied to a specific entry scope
        let entry_scope = body.entry_scope.as_ref().unwrap();
        scopes.push(CreateScopeRequest {
            scope: entry_scope.clone(),
            ops: "read".to_string(), // Read-only by default
            deny: false,
        });
    }

    // For one-time/shareable keys with entry_scope, we auto-generate the scope
    // For all other key types, require at least one scope
    let allow_empty_scopes = is_one_time_with_entry_scope || is_shareable_with_entry_scope;
    if scopes.is_empty() && !allow_empty_scopes {
        return Err(AppError::Forbidden(
            "at least one scope is required (or provide entry_scope for one-time/shareable keys)".to_string(),
        ));
    }

    // Validate each scope has at least one operation
    for scope in &scopes {
        if scope.ops.is_empty() {
            return Err(AppError::Forbidden(
                "each scope must have at least one operation (read, write, delete, list)".to_string(),
            ));
        }
    }

    let owner = &auth.0.oidc_subject;
    let (plaintext, key_hash) = generate_api_key();
    let id = Uuid::new_v4().to_string();

    // approval_required keys start as pending_approval
    let status = if body.key_type == "approval_required" {
        "pending_approval"
    } else {
        "active"
    };

    sqlx::query!(
        "INSERT INTO api_keys (id, key_hash, label, type, status, expires_at, owner_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        id, key_hash, body.label, body.key_type, status, body.expires_at, owner
    )
    .execute(&state.pool)
    .await?;

    for scope in &scopes {
        let scope_id = Uuid::new_v4().to_string();
        sqlx::query!(
            "INSERT INTO api_key_scopes (id, api_key_id, scope, ops, deny) VALUES (?, ?, ?, ?, ?)",
            scope_id, id, scope.scope, scope.ops, scope.deny
        )
        .execute(&state.pool)
        .await?;
    }

    Ok((StatusCode::CREATED, Json(CreateKeyResponse { id, key: plaintext })))
}

pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "UPDATE api_keys SET status = 'revoked' WHERE id = ? AND owner_id = ? AND status IN ('active', 'pending_approval')",
        key_id, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_revoked_sessions(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "DELETE FROM api_keys WHERE owner_id = ? AND type = 'session' AND status = 'revoked'",
        owner
    )
    .execute(&state.pool)
    .await?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "deleted": result.rows_affected() }))))
}

pub async fn delete_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(key_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "DELETE FROM api_keys WHERE id = ? AND owner_id = ? AND status IN ('revoked', 'used')",
        key_id, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Session Keys ─────────────────────────────────────────────────────────────

/// Create a session key for the authenticated admin.
/// Auto-revokes any existing active session key for this owner.
pub async fn create_session_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<(StatusCode, Json<CreateKeyResponse>), AppError> {
    let owner = &auth.0.oidc_subject;
    
    // Only revoke previous CLI session tokens (label = 'session'), not the web session
    sqlx::query!(
        "UPDATE api_keys SET status = 'revoked' WHERE owner_id = ? AND type = 'session' AND status = 'active' AND label = 'session'",
        owner
    )
    .execute(&state.pool)
    .await?;

    // Create new session key with 15 hour TTL
    let (plaintext, key_hash) = generate_api_key();
    let id = Uuid::new_v4().to_string();
    
    sqlx::query!(
        "INSERT INTO api_keys (id, key_hash, label, type, status, expires_at, owner_id)
         VALUES (?, ?, 'session', 'session', 'active', datetime('now', '+15 hours'), ?)",
        id, key_hash, owner
    )
    .execute(&state.pool)
    .await?;

    let scope_id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO api_key_scopes (id, api_key_id, scope, ops, deny)
         VALUES (?, ?, '*', 'read,write,delete,list', 0)",
        scope_id, id
    )
    .execute(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(CreateKeyResponse { id, key: plaintext })))
}

/// Get the current active session key info for this owner (id only, not the key itself)
pub async fn get_session_key(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Option<SessionKeyInfo>>, AppError> {
    let owner = &auth.0.oidc_subject;
    
    let row = sqlx::query!(
        "SELECT id, expires_at FROM api_keys 
         WHERE owner_id = ? AND type = 'session' AND status = 'active' 
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY created_at DESC LIMIT 1",
        owner
    )
    .fetch_optional(&state.pool)
    .await?;
    
    Ok(Json(row.map(|r| SessionKeyInfo {
        id: r.id,
        expires_at: r.expires_at,
    })))
}

/// Revoke the current session key and clear the cookie
pub async fn logout(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    auth: AdminAuth,
) -> Result<Response, AppError> {
    let owner = &auth.0.oidc_subject;
    
    // Revoke all active session keys for this owner
    sqlx::query!(
        "UPDATE api_keys SET status = 'revoked' WHERE owner_id = ? AND type = 'session' AND status = 'active'",
        owner
    )
    .execute(&state.pool)
    .await?;
    
    let clear = Cookie::build(("session_token", ""))
        .http_only(true)
        .secure(true)
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();
    Ok((jar.remove(clear), Redirect::to("/auth/login")).into_response())
}

/// GET /api/admin/session — current session info (email, expiry, etc.)
pub async fn get_session_info(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<SessionInfo>, AppError> {
    let owner = &auth.0.oidc_subject;
    let row = sqlx::query!(
        "SELECT label, expires_at, created_at FROM api_keys
         WHERE owner_id = ? AND type = 'session' AND status = 'active'
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY created_at DESC LIMIT 1",
        owner
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    Ok(Json(SessionInfo {
        email: auth.0.email.unwrap_or_else(|| owner.clone()),
        oidc_subject: owner.clone(),
        expires_at: row.expires_at,
        created_at: row.created_at,
    }))
}

/// GET /api/admin/session/token — returns the plaintext session token from the cookie.
/// Used by the dashboard "copy session token" button for use in scripts.
pub async fn get_session_token(
    jar: CookieJar,
    _auth: AdminAuth,
) -> Result<Json<String>, AppError> {
    let token = jar
        .get("session_token")
        .map(|c| c.value().to_string())
        .ok_or(AppError::Unauthorized)?;
    Ok(Json(token))
}

/// POST /api/admin/session/device-token — creates a 180-day api_key for the KV Approver app.
pub async fn create_device_token(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<String>, AppError> {
    let owner = &auth.0.oidc_subject;
    let (plaintext, key_hash) = generate_api_key();
    let id = Uuid::new_v4().to_string();

    let mut tx = state.pool.begin().await?;

    sqlx::query!(
        "INSERT INTO api_keys (id, key_hash, label, type, status, expires_at, owner_id)
         VALUES (?, ?, 'kv-approver device', 'approval', 'active', datetime('now', '+180 days'), ?)",
        id, key_hash, owner
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Json(plaintext))
}

// ── Approvals ───────────────────────────────────────────────────────────────

pub async fn list_approvals(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<ApprovalRow>>, AppError> {
    let owner = &auth.0.oidc_subject;
    let rows = sqlx::query_as!(
        ApprovalRow,
        r#"SELECT ar.id, ar.api_key_id,
                  ak.label as "api_key_label",
                  ar.emoji_sequence, ar.status,
                  ar.requested_at, ar.expires_at
           FROM approval_requests ar
           JOIN api_keys ak ON ak.id = ar.api_key_id
           WHERE ar.status = 'pending' AND ar.expires_at > datetime('now')
             AND ak.owner_id = ?
           ORDER BY ar.requested_at DESC"#,
        owner
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}

pub async fn approve_request(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(request_id): Path<String>,
    Json(body): Json<ApproveRequest>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let row = sqlx::query!(
        "SELECT ar.api_key_id, ar.emoji_sequence
         FROM approval_requests ar
         JOIN api_keys ak ON ak.id = ar.api_key_id
         WHERE ar.id = ? AND ar.status = 'pending' AND ar.expires_at > datetime('now')
           AND ak.owner_id = ?",
        request_id, owner
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let matches = bcrypt::verify(&body.confirm, &row.emoji_sequence)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt error: {e}")))?;
    if !matches {
        return Err(AppError::Forbidden("emoji sequence does not match".to_string()));
    }

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
    auth: AdminAuth,
    Path(request_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "UPDATE approval_requests SET status = 'rejected'
         WHERE id = ? AND status = 'pending'
           AND api_key_id IN (SELECT id FROM api_keys WHERE owner_id = ?)",
        request_id, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Called by a client holding an approval_required key to trigger the approval flow.
/// Generates an emoji sequence, creates an approval_request, returns the emoji for display.
pub async fn request_approval(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
) -> Result<(StatusCode, Json<RequestApprovalResponse>), AppError> {
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
        id, key.id, emoji
    )
    .execute(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(RequestApprovalResponse { confirm: emoji })))
}

// ── KV (admin view) ──────────────────────────────────────────────────────────

pub async fn list_kv_entries(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Query(q): Query<crate::kv::handlers::ListQuery>,
) -> Result<Json<Vec<crate::kv::model::KvMetaResponse>>, AppError> {
    let owner = &auth.0.oidc_subject;
    let rows = match q.prefix {
        Some(prefix) => {
            let pattern = format!("{}%", prefix);
            sqlx::query_as!(
                crate::kv::model::KvMetaResponse,
                r#"SELECT key, scope, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE key LIKE ? AND owner_id = ?
                   AND (expires_at IS NULL OR expires_at > datetime('now'))
                 ORDER BY key"#,
                pattern, owner
            )
            .fetch_all(&state.pool)
            .await?
        }
        None => {
            sqlx::query_as!(
                crate::kv::model::KvMetaResponse,
                r#"SELECT key, scope, ttl_hours, ttl_sliding as "ttl_sliding: bool",
                        expires_at, open_access as "open_access: bool", created_at
                 FROM kv_entries
                 WHERE owner_id = ?
                   AND (expires_at IS NULL OR expires_at > datetime('now'))
                 ORDER BY key"#,
                owner
            )
            .fetch_all(&state.pool)
            .await?
        }
    };
    Ok(Json(rows))
}

pub async fn list_scopes(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<String>>, AppError> {
    let owner = &auth.0.oidc_subject;
    let scopes = sqlx::query_scalar!(
        "SELECT DISTINCT scope FROM kv_entries
         WHERE owner_id = ? AND scope IS NOT NULL AND scope != ''
           AND (expires_at IS NULL OR expires_at > datetime('now'))
         ORDER BY scope",
        owner
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .flatten()
    .collect();
    Ok(Json(scopes))
}

// ── Admin KV write / import / patch / delete ─────────────────────────────────

pub async fn admin_write_kv(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<AdminKvWriteRequest>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;

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
                return Err(AppError::Forbidden(format!("missing zero trust field: {name}")));
            }
        }
    }

    let expires_at = compute_expires_at(body.ttl_hours);
    let ttl_sliding = body.ttl_sliding as i64;
    let open_access = body.open_access as i64;

    sqlx::query!(
        "INSERT INTO kv_entries
             (key, owner_id, value, scope, ttl_hours, ttl_sliding, expires_at, open_access,
              zt_ciphertext, zt_wrapped_dek, zt_nonce, zt_aad, zt_prf_salt, zt_credential_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(key, owner_id) DO UPDATE SET
             value          = excluded.value,
             scope          = excluded.scope,
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
        body.key, owner, body.value, body.scope, body.ttl_hours, ttl_sliding, expires_at, open_access,
        body.zt_ciphertext, body.zt_wrapped_dek, body.zt_nonce, body.zt_aad,
        body.zt_prf_salt, body.zt_credential_id
    )
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn admin_delete_kv(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "DELETE FROM kv_entries WHERE key = ? AND owner_id = ?",
        key, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn admin_patch_kv(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(key): Path<String>,
    Json(body): Json<AdminKvPatchRequest>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "UPDATE kv_entries SET scope = ? WHERE key = ? AND owner_id = ?",
        body.scope, key, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn admin_import_kv(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<AdminKvImportRequest>,
) -> Result<Json<AdminKvImportResponse>, AppError> {
    let owner = &auth.0.oidc_subject;
    let prefix = body.prefix.as_deref().unwrap_or("");
    let ttl_sliding = body.ttl_sliding as i64;
    let open_access = body.open_access as i64;

    let mut imported = 0usize;
    let mut skipped = 0usize;

    for line in body.content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            skipped += 1;
            continue;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            skipped += 1;
            continue;
        };
        let key = format!("{}{}", prefix, raw_key.trim());
        let value = unquote(raw_value.trim());
        let expires_at = compute_expires_at(body.ttl_hours);

        sqlx::query!(
            "INSERT INTO kv_entries (key, owner_id, value, scope, ttl_hours, ttl_sliding, expires_at, open_access)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(key, owner_id) DO UPDATE SET
                 value       = excluded.value,
                 scope       = excluded.scope,
                 ttl_hours   = excluded.ttl_hours,
                 ttl_sliding = excluded.ttl_sliding,
                 expires_at  = excluded.expires_at,
                 open_access = excluded.open_access",
            key, owner, value, body.scope, body.ttl_hours, ttl_sliding, expires_at, open_access
        )
        .execute(&state.pool)
        .await?;

        imported += 1;
    }

    Ok(Json(AdminKvImportResponse { imported, skipped }))
}

/// Strip surrounding single or double quotes from a .env value.
fn unquote(s: &str) -> String {
    if (s.starts_with('"') && s.ends_with('"'))
        || (s.starts_with('\'') && s.ends_with('\''))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

// ── Access log ───────────────────────────────────────────────────────────────

pub async fn list_access_log(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Json<Vec<serde_json::Value>> {
    let entries = state
        .access_log
        .lock()
        .map(|log| log.iter().rev().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    Json(
        entries
            .into_iter()
            .map(|e| serde_json::json!({
                "ip": e.ip,
                "api_key_id": e.api_key_id,
                "key": e.key,
                "op": e.op,
                "ts": e.ts.to_rfc3339(),
            }))
            .collect(),
    )
}

// ── Blocked IPs ──────────────────────────────────────────────────────────────

pub async fn list_blocked_ips(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Result<Json<Vec<crate::admin::model::BlockedIpRow>>, AppError> {
    let rows = sqlx::query_as!(
        crate::admin::model::BlockedIpRow,
        "SELECT ip, failed_count, blocked_at, last_failure
         FROM blocked_ips ORDER BY failed_count DESC"
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

pub async fn unblock_ip(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(ip): Path<String>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query!("DELETE FROM blocked_ips WHERE ip = ?", ip)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Rate limits ──────────────────────────────────────────────────────────────

pub async fn list_rate_counters(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Json<Vec<serde_json::Value>> {
    let mut entries: Vec<(String, u32)> = state
        .rate_counters
        .iter()
        .map(|e| (e.key().to_string(), *e.value()))
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    Json(
        entries
            .into_iter()
            .map(|(ip, count)| serde_json::json!({ "ip": ip, "count": count }))
            .collect(),
    )
}

// ── Secret request links ─────────────────────────────────────────────────────

pub async fn create_secret_request(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<CreateSecretRequestBody>,
) -> Result<(StatusCode, Json<CreateSecretRequestResponse>), AppError> {
    let owner = &auth.0.oidc_subject;
    let email = auth.0.email.as_deref().unwrap_or(owner);
    let id = Uuid::new_v4().to_string();

    let required_keys_json: Option<String> = body
        .required_keys
        .as_ref()
        .filter(|v| !v.is_empty())
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    sqlx::query!(
        "INSERT INTO secret_requests (id, owner_id, owner_label, description, scope, key_prefix, required_keys)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        id, owner, email, body.description, body.scope, body.key_prefix, required_keys_json
    )
    .execute(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(CreateSecretRequestResponse { id })))
}

pub async fn list_secret_requests(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<SecretRequestRow>>, AppError> {
    let owner = &auth.0.oidc_subject;
    let rows = sqlx::query_as!(
        SecretRequestRow,
        "SELECT id, owner_label, description, scope, key_prefix, required_keys, status, created_at, fulfilled_at
         FROM secret_requests WHERE owner_id = ? ORDER BY created_at DESC",
        owner
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

pub async fn revoke_secret_request(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "UPDATE secret_requests SET status = 'revoked'
         WHERE id = ? AND owner_id = ? AND status = 'pending'",
        id, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_secret_request(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "DELETE FROM secret_requests WHERE id = ? AND owner_id = ?",
        id, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Public — no admin auth. Returns minimal metadata to render the collect page.
pub async fn get_secret_request_public(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SecretRequestPublic>, AppError> {
    let row = sqlx::query!(
        "SELECT owner_label, description, status, key_prefix, required_keys FROM secret_requests WHERE id = ?",
        id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let required_keys: Vec<String> = row
        .required_keys
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    Ok(Json(SecretRequestPublic {
        owner_label: row.owner_label,
        description: row.description,
        status: row.status,
        key_prefix: row.key_prefix,
        required_keys,
    }))
}

/// Public — no admin auth. Inserts submitted entries into the owner's KV store,
/// then marks the request as fulfilled (one-time use).
pub async fn submit_secret_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<SubmitSecretRequestBody>,
) -> Result<StatusCode, AppError> {
    let mut tx = state.pool.begin().await?;

    let row = sqlx::query!(
        "SELECT owner_id, scope, status, key_prefix, required_keys FROM secret_requests WHERE id = ?",
        id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    if row.status != "pending" {
        return Err(AppError::Forbidden(
            "this request link has already been used or revoked".to_string(),
        ));
    }

    let owner_id = row.owner_id;
    let scope = row.scope;
    let prefix = row.key_prefix.as_deref().unwrap_or("").to_string();

    let required: Vec<String> = row
        .required_keys
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let empty_bypasses = vec![];
    let bypasses = body.bypasses.as_deref().unwrap_or(&empty_bypasses);
    let bypass_keys: std::collections::HashSet<&str> =
        bypasses.iter().map(|b| b.key.as_str()).collect();

    // Ensure every required key is either provided with a value or explicitly bypassed.
    for req in &required {
        let has_value = body
            .entries
            .iter()
            .any(|e| e.key.trim() == req.as_str() && !e.value.is_empty());
        if !has_value && !bypass_keys.contains(req.as_str()) {
            return Err(AppError::Forbidden(format!(
                "required key '{}' was not provided",
                req
            )));
        }
    }

    // Build (final_key, value) pairs: apply prefix, skip bypassed keys.
    let entries_to_insert: Vec<(String, String)> = body
        .entries
        .iter()
        .filter_map(|e| {
            let bare = e.key.trim().to_string();
            if bare.is_empty() { return None; }
            if bypass_keys.contains(bare.as_str()) { return None; }
            Some((format!("{}{}", prefix, bare), e.value.clone()))
        })
        .collect();

    // Check for existing keys before touching anything.
    let mut conflicts = Vec::new();
    for (final_key, _) in &entries_to_insert {
        let exists = sqlx::query_scalar!(
            r#"SELECT 1 as "x: i32" FROM kv_entries WHERE key = ? AND owner_id = ?
             AND (expires_at IS NULL OR expires_at > datetime('now'))"#,
            final_key, owner_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_some() {
            conflicts.push(final_key.clone());
        }
    }
    if !conflicts.is_empty() {
        return Err(AppError::KeyConflict(conflicts));
    }

    sqlx::query!(
        "UPDATE secret_requests SET status = 'fulfilled', fulfilled_at = datetime('now') WHERE id = ?",
        id
    )
    .execute(&mut *tx)
    .await?;

    for (final_key, value) in &entries_to_insert {
        sqlx::query!(
            "INSERT INTO kv_entries (key, owner_id, value, scope) VALUES (?, ?, ?, ?)",
            final_key, owner_id, value, scope
        )
        .execute(&mut *tx)
        .await?;
    }

    // Create faux approval notices for every bypassed required key.
    for bypass in bypasses {
        if required.contains(&bypass.key) {
            let fa_id = Uuid::new_v4().to_string();
            let msg = if bypass.note.trim().is_empty() {
                format!("Recipient bypassed required key '{}'", bypass.key)
            } else {
                format!(
                    "Recipient bypassed required key '{}' — note: \"{}\"",
                    bypass.key,
                    bypass.note.trim()
                )
            };
            sqlx::query!(
                "INSERT INTO faux_approvals (id, owner_id, secret_request_id, message)
                 VALUES (?, ?, ?, ?)",
                fa_id, owner_id, id, msg
            )
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
// ── Faux approvals ──────────────────────────────────────────────────────────

pub async fn list_faux_approvals(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<FauxApprovalRow>>, AppError> {
    let owner = &auth.0.oidc_subject;
    let rows = sqlx::query_as!(
        FauxApprovalRow,
        "SELECT id, message, created_at, secret_request_id
         FROM faux_approvals WHERE owner_id = ? ORDER BY created_at DESC",
        owner
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

pub async fn dismiss_faux_approval(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "DELETE FROM faux_approvals WHERE id = ? AND owner_id = ?",
        id, owner
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
