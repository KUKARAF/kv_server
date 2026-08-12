use sqlx::SqlitePool;

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
            .post("https://notifications.osmosis.page/api/notifications/")
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
