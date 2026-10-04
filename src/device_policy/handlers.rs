use crate::{
    auth::middleware::AdminAuth,
    device_policy::{
        enforce::compile_pattern,
        model::{
            ActiveBanRow, BanInfo, DevicePolicyRow, PolicyMode, UpdatePolicyRequest, MAX_KEYS,
            MAX_KEY_LEN,
        },
    },
    error::AppError,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::{collections::HashMap, sync::Arc};

/// Device-bound sessions are full admin sessions for their owner, but must never manage
/// device policies — otherwise a device could relax its own policy or lift its own ban.
fn require_non_device(auth: &AdminAuth) -> Result<&str, AppError> {
    if auth.0.device_id.is_some() {
        return Err(AppError::Forbidden(
            "device-bound sessions cannot manage device policies".to_string(),
        ));
    }
    Ok(&auth.0.oidc_subject)
}

/// Loads every device of `owner` with its policy and ban, optionally limited to one device.
async fn load_rows(
    state: &AppState,
    owner: &str,
    only_device: Option<&str>,
) -> Result<Vec<DevicePolicyRow>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT d.id as "device_id!: String", d.name as "device_name!: String",
                  p.mode as "mode?: String", p.pattern as "pattern?: String",
                  b.banned_at as "banned_at?: String", b.unban_at as "unban_at?: String",
                  b.ban_count as "ban_count?: i64", b.last_key as "last_key?: String",
                  (b.banned_at IS NOT NULL AND b.unban_at IS NOT NULL
                   AND b.unban_at > datetime('now')) as "ban_active?: bool"
           FROM devices d
           LEFT JOIN device_policies p ON p.device_id = d.id
           LEFT JOIN device_bans b ON b.device_id = d.id
           WHERE d.owner_id = ? AND (? IS NULL OR d.id = ?)
           ORDER BY d.name, d.id"#,
        owner,
        only_device,
        only_device
    )
    .fetch_all(&state.pool)
    .await?;

    let key_rows = sqlx::query!(
        r#"SELECT k.device_id as "device_id!: String", k.kv_key as "kv_key!: String"
           FROM device_policy_keys k
           JOIN devices d ON d.id = k.device_id
           WHERE d.owner_id = ? AND (? IS NULL OR d.id = ?)
           ORDER BY k.kv_key"#,
        owner,
        only_device,
        only_device
    )
    .fetch_all(&state.pool)
    .await?;

    let mut keys_by_device: HashMap<String, Vec<String>> = HashMap::new();
    for k in key_rows {
        keys_by_device
            .entry(k.device_id)
            .or_default()
            .push(k.kv_key);
    }

    Ok(rows
        .into_iter()
        .map(|r| {
            let mode = r
                .mode
                .as_deref()
                .and_then(PolicyMode::parse)
                .unwrap_or(PolicyMode::AllowAll);
            let keys = match mode {
                PolicyMode::AllowList | PolicyMode::DenyList => {
                    keys_by_device.remove(&r.device_id).unwrap_or_default()
                }
                PolicyMode::AllowAll | PolicyMode::Regex => Vec::new(),
            };
            let pattern = match mode {
                PolicyMode::Regex => r.pattern,
                _ => None,
            };
            // A device that has never been banned has no ban object.
            let ban = r.ban_count.filter(|c| *c > 0).map(|ban_count| BanInfo {
                banned_at: r.banned_at,
                unban_at: r.unban_at,
                ban_count,
                last_key: r.last_key,
                active: r.ban_active.unwrap_or(false),
            });
            DevicePolicyRow {
                device_id: r.device_id,
                device_name: r.device_name,
                mode: mode.as_str().to_string(),
                keys,
                pattern,
                ban,
            }
        })
        .collect())
}

/// GET /api/admin/device-policies — one row per registered device of this owner.
pub async fn list(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<DevicePolicyRow>>, AppError> {
    let owner = require_non_device(&auth)?;
    Ok(Json(load_rows(&state, owner, None).await?))
}

/// Validates and normalises an update request into (mode, keys, pattern).
fn validate(
    body: UpdatePolicyRequest,
) -> Result<(PolicyMode, Vec<String>, Option<String>), AppError> {
    let mode = PolicyMode::parse(&body.mode)
        .ok_or_else(|| AppError::BadRequest("unknown mode".to_string()))?;

    match mode {
        PolicyMode::AllowAll => Ok((mode, Vec::new(), None)),
        PolicyMode::AllowList | PolicyMode::DenyList => {
            if body.keys.len() > MAX_KEYS {
                return Err(AppError::BadRequest(format!(
                    "at most {MAX_KEYS} keys allowed"
                )));
            }
            let mut keys: Vec<String> = Vec::with_capacity(body.keys.len());
            for k in body.keys {
                let k = k.trim();
                if k.is_empty() {
                    continue;
                }
                if k.chars().count() > MAX_KEY_LEN {
                    return Err(AppError::BadRequest(format!(
                        "key names must be at most {MAX_KEY_LEN} characters"
                    )));
                }
                if !keys.iter().any(|existing| existing == k) {
                    keys.push(k.to_string());
                }
            }
            if keys.is_empty() {
                return Err(AppError::BadRequest(
                    "keys must not be empty for this mode".to_string(),
                ));
            }
            Ok((mode, keys, None))
        }
        PolicyMode::Regex => {
            let pattern = body
                .pattern
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| AppError::BadRequest("pattern is required".to_string()))?;
            compile_pattern(&pattern).map_err(AppError::BadRequest)?;
            Ok((mode, Vec::new(), Some(pattern)))
        }
    }
}

/// PUT /api/admin/device-policies/:device_id
pub async fn update(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(device_id): Path<String>,
    Json(body): Json<UpdatePolicyRequest>,
) -> Result<Json<DevicePolicyRow>, AppError> {
    let owner = require_non_device(&auth)?;

    let owned = sqlx::query_scalar!(
        r#"SELECT 1 as "x: i32" FROM devices WHERE id = ? AND owner_id = ?"#,
        device_id,
        owner
    )
    .fetch_optional(&state.pool)
    .await?;
    if owned.is_none() {
        return Err(AppError::NotFound);
    }

    let (mode, keys, pattern) = validate(body)?;
    let mode_str = mode.as_str();

    let mut tx = state.pool.begin().await?;
    sqlx::query!(
        "INSERT INTO device_policies (device_id, owner_id, mode, pattern, updated_at)
         VALUES (?, ?, ?, ?, datetime('now'))
         ON CONFLICT(device_id) DO UPDATE SET
             owner_id   = excluded.owner_id,
             mode       = excluded.mode,
             pattern    = excluded.pattern,
             updated_at = excluded.updated_at",
        device_id,
        owner,
        mode_str,
        pattern
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "DELETE FROM device_policy_keys WHERE device_id = ?",
        device_id
    )
    .execute(&mut *tx)
    .await?;
    for k in &keys {
        sqlx::query!(
            "INSERT INTO device_policy_keys (device_id, kv_key) VALUES (?, ?)",
            device_id,
            k
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    tracing::info!(owner_id = %owner, device_id = %device_id, mode = mode_str, keys = keys.len(), "device policy updated");

    load_rows(&state, owner, Some(&device_id))
        .await?
        .into_iter()
        .next()
        .map(Json)
        .ok_or(AppError::NotFound)
}

/// DELETE /api/admin/device-policies/:device_id/ban — lifts an active ban but keeps
/// ban_count so the next violation escalates.
pub async fn unban(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(device_id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = require_non_device(&auth)?;

    let affected = sqlx::query!(
        "UPDATE device_bans SET banned_at = NULL, unban_at = NULL
         WHERE device_id = ?
           AND device_id IN (SELECT id FROM devices WHERE owner_id = ?)
           AND banned_at IS NOT NULL AND unban_at IS NOT NULL
           AND unban_at > datetime('now')",
        device_id,
        owner
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound);
    }
    tracing::info!(owner_id = %owner, device_id = %device_id, "device ban lifted");
    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/admin/device-policies/bans — active bans only.
pub async fn list_bans(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<ActiveBanRow>>, AppError> {
    let owner = require_non_device(&auth)?;

    let rows = sqlx::query!(
        r#"SELECT b.device_id as "device_id!: String", d.name as "device_name!: String",
                  b.banned_at, b.unban_at, b.ban_count, b.last_key
           FROM device_bans b
           JOIN devices d ON d.id = b.device_id
           WHERE d.owner_id = ?
             AND b.banned_at IS NOT NULL AND b.unban_at IS NOT NULL
             AND b.unban_at > datetime('now')
           ORDER BY b.unban_at DESC"#,
        owner
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|r| ActiveBanRow {
        device_id: r.device_id,
        device_name: r.device_name,
        ban: BanInfo {
            banned_at: r.banned_at,
            unban_at: r.unban_at,
            ban_count: r.ban_count,
            last_key: r.last_key,
            active: true,
        },
    })
    .collect();

    Ok(Json(rows))
}
