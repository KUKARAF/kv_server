use crate::{auth::session::validate_session, error::AppError, keys::scope::{check_scope, ScopeRule}, notify, state::AppState};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, Method},
};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Read,
    Write,
    Delete,
    List,
}

impl Op {
    pub fn as_str(&self) -> &str {
        match self {
            Op::Read => "read",
            Op::Write => "write",
            Op::Delete => "delete",
            Op::List => "list",
        }
    }

    fn from_request(parts: &Parts) -> Self {
        // axum's nest("/kv", ...) strips the prefix, so the path arriving here
        // is the remainder: "/" or "" for the list endpoint, "/foo" for a key.
        let path = parts.uri.path().trim_start_matches('/');
        let is_list = parts.method == Method::GET && path.is_empty();
        if is_list {
            return Op::List;
        }
        match parts.method {
            Method::GET => Op::Read,
            Method::PUT | Method::POST => Op::Write,
            Method::DELETE => Op::Delete,
            _ => Op::Read,
        }
    }
}

#[allow(dead_code)]
pub struct ApiKeyAuth {
    pub owner_id: Option<String>,  // None only for open-access reads
    pub api_key_id: Option<String>,
    pub op: Op,
    pub allowed_scopes: Vec<ScopeRule>, // populated for API key auth; empty for session tokens
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for ApiKeyAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let op = Op::from_request(parts);

        // Session token (Authorization: Bearer) grants full access, same as admin.
        if let Some(token) = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            match validate_session(&state.pool, token).await {
                Ok(claims) => return Ok(ApiKeyAuth {
                    owner_id: Some(claims.oidc_subject),
                    api_key_id: None,
                    op,
                    allowed_scopes: vec![],
                }),
                Err(_) => return Err(AppError::Unauthorized),
            }
        }

        // axum nest strips "/kv" so the path is e.g. "/my-key"; strip the slash.
        let kv_key = parts
            .uri
            .path()
            .trim_start_matches('/')
            .to_string();

        let raw_key = parts
            .headers
            .get("X-Api-Key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Open-access bypass: only for reads on a specific key
        if raw_key.is_none() && op == Op::Read && !kv_key.is_empty() {
            let open = sqlx::query_scalar!(
                "SELECT open_access FROM kv_entries
                 WHERE key = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
                 LIMIT 1",
                kv_key
            )
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or(0);

            if open != 0 {
                return Ok(ApiKeyAuth { owner_id: None, api_key_id: None, op, allowed_scopes: vec![] });
            }
        }

        let raw_key = raw_key.ok_or(AppError::Unauthorized)?;
        let key_hash = crate::keys::generate::hash_key(&raw_key);

        let api_key = sqlx::query!(
            "SELECT id, type as key_type, status, expires_at, owner_id
             FROM api_keys
             WHERE key_hash = ?",
            key_hash
        )
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

        // Reject revoked/used keys immediately
        if api_key.status == "revoked" || api_key.status == "used" {
            notify::send(
                state.pool.clone(),
                format!("Auth failure: {} key used ({})", api_key.status, &api_key.id[..8]),
                "medium",
            );
            return Err(AppError::Unauthorized);
        }

        // Check expiry
        if let Some(ref exp) = api_key.expires_at {
            let expired: bool = sqlx::query_scalar!(
                "SELECT datetime(?) <= datetime('now')",
                exp
            )
            .fetch_one(&state.pool)
            .await? != 0;

            if expired {
                notify::send(
                    state.pool.clone(),
                    format!("Auth failure: expired key used ({})", &api_key.id[..8]),
                    "medium",
                );
                return Err(AppError::Unauthorized);
            }
        }

        // Type-specific checks (status only — one_time consumption happens after scope check)
        match api_key.key_type.as_str() {
            "zero_trust" => {
                // zero_trust keys must be active; the actual secret access
                // requires a WebAuthn ceremony and a short-lived ZT JWT.
                if api_key.status != "active" {
                    return Err(AppError::Unauthorized);
                }
            }
            "approval_required" => {
                if api_key.status != "active" {
                    let emoji = sqlx::query_scalar!(
                        "SELECT emoji_sequence FROM approval_requests
                         WHERE api_key_id = ? AND status = 'pending'
                           AND expires_at > datetime('now')
                         ORDER BY requested_at DESC LIMIT 1",
                        api_key.id
                    )
                    .fetch_optional(&state.pool)
                    .await?;

                    let approver = sqlx::query_scalar!(
                        "SELECT email FROM session_tokens
                         WHERE expires_at > datetime('now')
                           AND oidc_subject = ?
                         ORDER BY created_at DESC LIMIT 1",
                        api_key.owner_id
                    )
                    .fetch_optional(&state.pool)
                    .await
                    .ok()
                    .flatten();

                    return Err(AppError::PendingApproval {
                        confirm: emoji.unwrap_or_else(|| "pending approval".to_string()),
                        approver,
                    });
                }
            }
            "shareable" => {
                // shareable keys must be active; they can be used multiple times
                // and are scoped to a single entry via entry_scope
                if api_key.status != "active" {
                    return Err(AppError::Unauthorized);
                }
            }
            _ => {
                if api_key.status != "active" {
                    return Err(AppError::Unauthorized);
                }
            }
        }

        // Scope check
        let scopes = sqlx::query_as!(
            ScopeRule,
            "SELECT scope, ops FROM api_key_scopes WHERE api_key_id = ?",
            api_key.id
        )
        .fetch_all(&state.pool)
        .await?;

        // For reads/writes/deletes on a specific key, fetch the entry's scope to check
        // hierarchical access. For list, we pass None and let the handler filter by scope.
        let entry_scope: Option<String> = if op != Op::List && !kv_key.is_empty() {
            sqlx::query_scalar!(
                "SELECT scope FROM kv_entries WHERE key = ? AND owner_id = ?
                 AND (expires_at IS NULL OR expires_at > datetime('now'))
                 LIMIT 1",
                kv_key, api_key.owner_id
            )
            .fetch_optional(&state.pool)
            .await?
            .flatten()
        } else {
            None
        };

        let check_scope_val = if op == Op::List { None } else { entry_scope.as_deref() };
        if !check_scope(&scopes, check_scope_val, op.as_str()) {
            notify::send(
                state.pool.clone(),
                format!("Auth failure: scope denied for key {} on '{kv_key}'", &api_key.id[..8]),
                "medium",
            );
            return Err(AppError::Forbidden("insufficient scope".to_string()));
        }

        // Consume one-time key only after scope check passes
        if api_key.key_type == "one_time" {
            let result = sqlx::query!(
                    "UPDATE api_keys
                     SET status = 'used', last_used_at = datetime('now')
                     WHERE id = ? AND status = 'active' AND type = 'one_time'",
                    api_key.id
            )
            .execute(&state.pool)
            .await?;

            if result.rows_affected() == 0 {
                return Err(AppError::Forbidden("one-time key already used".to_string()));
            }
        }
        
        // Note: 'shareable' keys are NOT consumed; they can be used multiple times

        // Update last_used_at (fire and forget, only for non-one-time)
        if api_key.key_type != "one_time" {
            let id = api_key.id.clone();
            let pool = state.pool.clone();
            tokio::spawn(async move {
                let _ = sqlx::query!(
                    "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
                    id
                )
                .execute(&pool)
                .await;
            });
        }

        Ok(ApiKeyAuth {
            owner_id: Some(api_key.owner_id),
            api_key_id: Some(api_key.id),
            op,
            allowed_scopes: scopes,
        })
    }
}
