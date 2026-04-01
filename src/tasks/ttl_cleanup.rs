use sqlx::SqlitePool;
use std::time::Duration;

pub async fn run(pool: SqlitePool, interval_secs: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if let Err(e) = cleanup(&pool).await {
            tracing::error!("TTL cleanup failed: {e:#}");
        }
    }
}

async fn cleanup(pool: &SqlitePool) -> anyhow::Result<()> {
    let kv = sqlx::query!(
        "DELETE FROM kv_entries WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    let sessions = sqlx::query!(
        "DELETE FROM session_tokens WHERE expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    let approvals = sqlx::query!(
        "UPDATE approval_requests SET status = 'expired'
         WHERE status = 'pending' AND expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    if kv + sessions + approvals > 0 {
        tracing::info!(
            kv_deleted = kv,
            sessions_deleted = sessions,
            approvals_expired = approvals,
            "TTL cleanup complete"
        );
    }

    Ok(())
}
