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
            .post("http://localhost:8000/api/notifications/")
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

async fn fetch_key(pool: &SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM kv_entries WHERE key = 'NOTIFY_API_KEY' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}
