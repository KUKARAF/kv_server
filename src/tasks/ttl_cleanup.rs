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

    let approvals = sqlx::query!(
        "UPDATE approval_requests SET status = 'expired'
         WHERE status = 'pending' AND expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    let device_auth = sqlx::query!(
        "UPDATE device_auth_requests SET status = 'expired'
         WHERE status = 'pending' AND expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    let session_requests = sqlx::query!(
        "UPDATE session_requests SET status = 'expired'
         WHERE status = 'pending' AND expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    // No downstream UI ever reads a challenge's status/history, so expired rows are just
    // deleted outright rather than marked (unlike session_requests/device_proposals below,
    // which are polled and should say "expired" explicitly).
    let session_request_challenges =
        sqlx::query!("DELETE FROM session_request_challenges WHERE expires_at <= datetime('now')")
            .execute(pool)
            .await?
            .rows_affected();

    let device_proposals = sqlx::query!(
        "UPDATE device_proposals SET status = 'expired'
         WHERE status = 'pending' AND expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    let shares = sqlx::query!(
        "DELETE FROM one_time_shares WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    // Lift expired temporary IP blocks. Keep block_count + last_failure as
    // offender history so a re-block escalates in duration.
    let unblocked = sqlx::query!(
        "UPDATE blocked_ips SET blocked_at = NULL, failed_count = 0
         WHERE unblock_at IS NOT NULL AND blocked_at IS NOT NULL
           AND unblock_at <= datetime('now')"
    )
    .execute(pool)
    .await?
    .rows_affected();

    if kv
        + approvals
        + device_auth
        + session_requests
        + session_request_challenges
        + device_proposals
        + shares
        + unblocked
        > 0
    {
        tracing::info!(
            kv_deleted = kv,
            approvals_expired = approvals,
            device_auth_expired = device_auth,
            session_requests_expired = session_requests,
            session_request_challenges_deleted = session_request_challenges,
            device_proposals_expired = device_proposals,
            shares_deleted = shares,
            ips_unblocked = unblocked,
            "TTL cleanup complete"
        );
    }

    Ok(())
}
