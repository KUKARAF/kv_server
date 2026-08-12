use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// priority-notify base URL (same host used for both sending and token management).
const NOTIFY_BASE_URL: &str = "https://notifications.osmosis.page";

/// Reserved KV entries that only the admin owner may write — both are priority-notify
/// credentials. `NOTIFY_API_KEY` is the `write`-scope send token used by `send`;
/// `NOTIFY_MANAGEMENT_KEY` is the provisioning credential used to rotate/revoke send tokens.
pub(crate) const RESERVED_ADMIN_KEYS: &[&str] = &["NOTIFY_API_KEY", "NOTIFY_MANAGEMENT_KEY"];

/// Fire-and-forget: look up NOTIFY_API_KEY from the KV store and POST a notification.
/// Does nothing if the key is not stored.
pub fn send(pool: SqlitePool, title: String, priority: &'static str) {
    tokio::spawn(async move {
        let api_key = match fetch_key(&pool).await {
            Some(k) => k,
            None => return,
        };

        let client = reqwest::Client::new();
        if let Err(e) = client
            .post(format!("{NOTIFY_BASE_URL}/api/notifications/"))
            .header("Authorization", format!("Bearer {api_key}"))
            .json(&serde_json::json!({
                "title": title,
                "priority": priority,
                "source": "kv-manager",
            }))
            .send()
            .await
        {
            tracing::warn!("notification send failed: {e}");
        }
    });
}

/// Resolve the hardcoded admin's `owner_id` from their OIDC-created session key.
/// `label = ADMIN_EMAIL AND type = 'session'` is not spoofable: `create_key` cannot mint
/// `type='session'` rows — only the OIDC callback does, with `label = email`.
pub(crate) async fn admin_owner_id(pool: &SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT owner_id FROM api_keys WHERE label = ? AND type = 'session' LIMIT 1",
    )
    .bind(crate::config::ADMIN_EMAIL)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

async fn fetch_key(pool: &SqlitePool) -> Option<String> {
    // Scope strictly to the admin owner so a non-admin's NOTIFY_API_KEY entry can never be used.
    let owner = admin_owner_id(pool).await?;
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM kv_entries WHERE key = 'NOTIFY_API_KEY' AND owner_id = ? LIMIT 1",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Fetch the priority-notify management key (admin-owner-scoped), mirroring `fetch_key`.
async fn fetch_management_key(pool: &SqlitePool) -> Option<String> {
    let owner = admin_owner_id(pool).await?;
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM kv_entries WHERE key = 'NOTIFY_MANAGEMENT_KEY' AND owner_id = ? LIMIT 1",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// True if a management key is stored for the admin owner. Handlers use this to return a
/// clear 409 instead of a generic 500 when the credential hasn't been provisioned yet.
pub(crate) async fn has_management_key(pool: &SqlitePool) -> bool {
    fetch_management_key(pool).await.is_some()
}

/// A priority-notify token as returned by `GET /api/tokens/` (the `token` plaintext is only
/// present on create, never here). Deserialized from priority-notify; serialized back to the
/// admin caller.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenInfo {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub device_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Deserialize)]
struct CreateTokenResponse {
    id: String,
    token: String,
}

/// Turn a 401 into an actionable error — the management key is missing or was revoked.
fn reject_unauthorized(resp: reqwest::Response) -> Result<reqwest::Response> {
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!(
            "priority-notify rejected the management key (401) — it may be missing or revoked; \
             re-provision NOTIFY_MANAGEMENT_KEY"
        );
    }
    Ok(resp)
}

/// Provision a fresh `write`-scope send token. Returns `(id, plaintext)`.
async fn create_send_token(mgmt_key: &str) -> Result<(String, String)> {
    let resp = reqwest::Client::new()
        .post(format!("{NOTIFY_BASE_URL}/api/tokens/"))
        .header("Authorization", format!("Bearer {mgmt_key}"))
        .json(&serde_json::json!({
            "name": "kv-manager", "device_type": "other", "scope": "write",
        }))
        .send()
        .await
        .context("create send-token request failed")?;
    let created: CreateTokenResponse = reject_unauthorized(resp)?
        .error_for_status()
        .context("create send-token returned an error status")?
        .json()
        .await
        .context("parse create send-token response")?;
    Ok((created.id, created.token))
}

async fn list_tokens(mgmt_key: &str) -> Result<Vec<TokenInfo>> {
    let resp = reqwest::Client::new()
        .get(format!("{NOTIFY_BASE_URL}/api/tokens/"))
        .header("Authorization", format!("Bearer {mgmt_key}"))
        .send()
        .await
        .context("list tokens request failed")?;
    reject_unauthorized(resp)?
        .error_for_status()
        .context("list tokens returned an error status")?
        .json()
        .await
        .context("parse token list")
}

/// Revoke a token. A 404 means it is already gone — treated as success (safe during rotation).
async fn revoke_token(mgmt_key: &str, id: &str) -> Result<()> {
    let resp = reqwest::Client::new()
        .delete(format!("{NOTIFY_BASE_URL}/api/tokens/{id}"))
        .header("Authorization", format!("Bearer {mgmt_key}"))
        .send()
        .await
        .context("revoke token request failed")?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    reject_unauthorized(resp)?
        .error_for_status()
        .context("revoke token returned an error status")?;
    Ok(())
}

/// Owner-scoped UPSERT of `NOTIFY_API_KEY` (admin owner). The server writes the send token
/// itself during rotation/bootstrap instead of it being hand-pasted.
async fn write_send_token(pool: &SqlitePool, token: &str) -> Result<()> {
    let owner = admin_owner_id(pool)
        .await
        .context("no admin session exists yet — cannot store NOTIFY_API_KEY")?;
    sqlx::query(
        "INSERT INTO kv_entries (key, owner_id, value) VALUES ('NOTIFY_API_KEY', ?, ?)
         ON CONFLICT(key, owner_id) DO UPDATE SET value = excluded.value",
    )
    .bind(owner)
    .bind(token)
    .execute(pool)
    .await
    .context("write NOTIFY_API_KEY")?;
    Ok(())
}

/// Rotate `NOTIFY_API_KEY` with **create-before-revoke** ordering: mint the new token, write it
/// first, then revoke the old (and any orphaned `kv-manager` tokens). There is never a window
/// where the server has no working send token. Also used for one-time bootstrap when absent.
pub(crate) async fn rotate_send_token(pool: &SqlitePool) -> Result<()> {
    let mgmt = fetch_management_key(pool)
        .await
        .context("NOTIFY_MANAGEMENT_KEY is not set")?;

    let (new_id, new_token) = create_send_token(&mgmt).await?;
    write_send_token(pool, &new_token).await?; // write the new token BEFORE revoking any old one

    // Revoke old / orphaned kv-manager tokens. Failures here are non-fatal — the new token
    // already works — so log and continue.
    match list_tokens(&mgmt).await {
        Ok(tokens) => {
            for t in tokens {
                if t.id != new_id && t.name.as_deref() == Some("kv-manager") {
                    if let Err(e) = revoke_token(&mgmt, &t.id).await {
                        tracing::warn!("failed to revoke old notify token {}: {e}", t.id);
                    }
                }
            }
        }
        Err(e) => tracing::warn!("could not list notify tokens to revoke old ones: {e}"),
    }
    Ok(())
}

/// List the tokens the management key can see (for the admin inventory endpoint).
pub(crate) async fn list_provisioned_tokens(pool: &SqlitePool) -> Result<Vec<TokenInfo>> {
    let mgmt = fetch_management_key(pool)
        .await
        .context("NOTIFY_MANAGEMENT_KEY is not set")?;
    list_tokens(&mgmt).await
}

/// Revoke a specific token id via the management key (for the admin revoke endpoint).
pub(crate) async fn revoke_provisioned_token(pool: &SqlitePool, id: &str) -> Result<()> {
    let mgmt = fetch_management_key(pool)
        .await
        .context("NOTIFY_MANAGEMENT_KEY is not set")?;
    revoke_token(&mgmt, id).await
}

/// Fire-and-forget bootstrap: if the send token is missing but a management key is present,
/// provision `NOTIFY_API_KEY`. No-ops (leaving the hand-paste path intact) when either the send
/// token already exists or the management key is absent. Never blocks or panics.
pub fn bootstrap_send_token(pool: SqlitePool) {
    tokio::spawn(async move {
        if fetch_key(&pool).await.is_some() {
            return; // send token already present
        }
        if !has_management_key(&pool).await {
            return; // nothing to bootstrap with — keep working from a hand-pasted key
        }
        match rotate_send_token(&pool).await {
            Ok(()) => tracing::info!("provisioned NOTIFY_API_KEY from the management key"),
            Err(e) => tracing::warn!("notify send-token bootstrap failed: {e}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    /// In-memory DB with an admin OIDC session row so `admin_owner_id` resolves to `owner`.
    async fn pool_with_admin(owner: &str) -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id)
             VALUES ('admin-key', 'hash', ?, 'session', 'active', ?)",
        )
        .bind(crate::config::ADMIN_EMAIL)
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn write_and_fetch_send_token_roundtrips_and_overwrites() {
        let pool = pool_with_admin("admin-owner").await;
        assert!(fetch_key(&pool).await.is_none());
        write_send_token(&pool, "send-tok-123").await.unwrap();
        assert_eq!(fetch_key(&pool).await.as_deref(), Some("send-tok-123"));
        // Rotation overwrites the same (key, owner) row rather than duplicating it.
        write_send_token(&pool, "send-tok-456").await.unwrap();
        assert_eq!(fetch_key(&pool).await.as_deref(), Some("send-tok-456"));
    }

    #[tokio::test]
    async fn management_key_presence_is_detected() {
        let pool = pool_with_admin("admin-owner").await;
        assert!(!has_management_key(&pool).await);
        sqlx::query(
            "INSERT INTO kv_entries (key, owner_id, value)
             VALUES ('NOTIFY_MANAGEMENT_KEY', 'admin-owner', 'mgmt-xyz')",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(has_management_key(&pool).await);
    }

    #[tokio::test]
    async fn send_token_is_admin_owner_scoped() {
        // A NOTIFY_API_KEY owned by a non-admin must never be picked up.
        let pool = pool_with_admin("admin-owner").await;
        sqlx::query(
            "INSERT INTO kv_entries (key, owner_id, value)
             VALUES ('NOTIFY_API_KEY', 'attacker-owner', 'evil-token')",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            fetch_key(&pool).await.is_none(),
            "a non-admin's NOTIFY_API_KEY entry must be ignored"
        );
    }
}
