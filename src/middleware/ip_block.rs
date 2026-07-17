use crate::{middleware::rate_limit::extract_real_ip, notify, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use sqlx::SqlitePool;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

/// Carries the resolved client IP through request extensions so
/// downstream extractors can access it without re-extracting headers.
/// This is the *real* address (for access logging), not the counter bucket.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

/// Cap on any single temporary block: 30 days.
const MAX_BLOCK_SECS: u64 = 30 * 24 * 3600;

/// Collapses an address to the unit we count and block on. IPv4 is used as-is;
/// IPv6 is bucketed to its /64 (low 64 bits zeroed) so a host rotating within a
/// prefix can't dodge counting one address at a time.
pub fn counter_bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in octets[8..].iter_mut() {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

pub async fn layer(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let ip = extract_real_ip(
        request.headers(),
        addr.ip(),
        state.config.trust_proxy_headers,
    );
    request.extensions_mut().insert(ClientIp(ip));

    // A block is active when blocked_at is set and either it's permanent
    // (unblock_at IS NULL) or the temporary window hasn't elapsed.
    let bucket = counter_bucket(ip).to_string();
    let blocked = sqlx::query_scalar!(
        "SELECT 1 FROM blocked_ips
         WHERE ip = ? AND blocked_at IS NOT NULL
           AND (unblock_at IS NULL OR unblock_at > datetime('now'))",
        bucket
    )
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None)
    .is_some();

    if blocked {
        tracing::warn!(ip = %ip, "blocked IP rejected");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"error":"access denied"}"#))
            .unwrap();
    }

    next.run(request).await
}

/// Clears accumulated failure debt for an IP after a successful authentication.
/// Never touches `blocked_at`/`block_count` — active blocks and offender history
/// survive so repeat offenders keep escalating.
pub async fn reset_failures_on_success(pool: &SqlitePool, ip: IpAddr) {
    let bucket = counter_bucket(ip).to_string();
    if let Err(e) = sqlx::query!(
        "UPDATE blocked_ips SET failed_count = 0
         WHERE ip = ? AND failed_count > 0 AND blocked_at IS NULL",
        bucket
    )
    .execute(pool)
    .await
    {
        tracing::error!("failed to reset failure count for {ip}: {e}");
    }
}

pub async fn record_auth_failure(
    pool: &SqlitePool,
    ip: IpAddr,
    threshold: u32,
    base_secs: u64,
    reason: &str,
) {
    let bucket = counter_bucket(ip).to_string();
    let threshold_i64 = threshold as i64;

    tracing::warn!(ip = %ip, %reason, "auth failure recorded — blocked_ips counter incremented");

    // Accrue failure debt (block decision handled separately below so the
    // escalating duration can be computed in Rust).
    if let Err(e) = sqlx::query!(
        "INSERT INTO blocked_ips (ip, failed_count, last_failure)
         VALUES (?, 1, datetime('now'))
         ON CONFLICT(ip) DO UPDATE SET
             failed_count = failed_count + 1,
             last_failure = datetime('now')",
        bucket
    )
    .execute(pool)
    .await
    {
        tracing::error!("failed to record auth failure for {ip}: {e}");
        return;
    }

    let row = match sqlx::query!(
        "SELECT failed_count, block_count, blocked_at, unblock_at
         FROM blocked_ips WHERE ip = ?",
        bucket
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(e) => {
            tracing::error!("failed to read failure state for {ip}: {e}");
            return;
        }
    };

    // Already under an active block (permanent, or temp not yet expired)? Leave it.
    let actively_blocked = row.blocked_at.is_some(); // expired temp blocks are cleared by ttl_cleanup
    if actively_blocked || row.failed_count < threshold_i64 {
        return;
    }

    // Escalate: nth block lasts base * 2^(n-1), capped at 30 days.
    let new_block_count = row.block_count + 1;
    let shift = (new_block_count - 1).clamp(0, 40) as u32;
    let secs = base_secs.saturating_mul(1u64 << shift).min(MAX_BLOCK_SECS);
    let modifier = format!("+{secs} seconds");

    if let Err(e) = sqlx::query!(
        "UPDATE blocked_ips
         SET blocked_at = datetime('now'),
             block_count = ?,
             unblock_at = datetime('now', ?)
         WHERE ip = ?",
        new_block_count,
        modifier,
        bucket
    )
    .execute(pool)
    .await
    {
        tracing::error!("failed to apply block for {ip}: {e}");
        return;
    }

    tracing::warn!(ip = %ip, block_count = new_block_count, secs, threshold, "IP temporarily blocked");
    notify::send(
        pool.clone(),
        format!("IP {ip} blocked for {secs}s (offense #{new_block_count}) after {threshold} failed auth attempts"),
        "high",
    );
}
