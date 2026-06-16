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
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Carries the resolved client IP through request extensions so
/// downstream extractors can access it without re-extracting headers.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

pub async fn layer(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let ip = extract_real_ip(request.headers(), addr.ip());
    request.extensions_mut().insert(ClientIp(ip));

    let ip_str = ip.to_string();
    let blocked = sqlx::query_scalar!(
        "SELECT 1 FROM blocked_ips WHERE ip = ? AND blocked_at IS NOT NULL",
        ip_str
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
/// Never touches `blocked_at` — IPs that reached the threshold stay blocked.
pub async fn reset_failures_on_success(pool: &SqlitePool, ip: IpAddr) {
    let ip_str = ip.to_string();
    if let Err(e) = sqlx::query!(
        "UPDATE blocked_ips SET failed_count = 0
         WHERE ip = ? AND failed_count > 0 AND blocked_at IS NULL",
        ip_str
    )
    .execute(pool)
    .await
    {
        tracing::error!("failed to reset failure count for {ip}: {e}");
    }
}

pub async fn record_auth_failure(pool: &SqlitePool, ip: IpAddr, threshold: u32, reason: &str) {
    let ip_str = ip.to_string();
    let threshold_i64 = threshold as i64;

    tracing::warn!(ip = %ip, %reason, "auth failure recorded — blocked_ips counter incremented");

    if let Err(e) = sqlx::query!(
        "INSERT INTO blocked_ips (ip, failed_count, last_failure)
         VALUES (?, 1, datetime('now'))
         ON CONFLICT(ip) DO UPDATE SET
             failed_count = failed_count + 1,
             last_failure = datetime('now'),
             blocked_at   = CASE
                 WHEN blocked_at IS NULL AND failed_count + 1 >= ?
                 THEN datetime('now')
                 ELSE blocked_at
             END",
        ip_str,
        threshold_i64
    )
    .execute(pool)
    .await
    {
        tracing::error!("failed to record auth failure for {ip}: {e}");
        return;
    }

    if let Ok(Some(row)) = sqlx::query!(
        "SELECT failed_count, blocked_at FROM blocked_ips WHERE ip = ?",
        ip_str
    )
    .fetch_optional(pool)
    .await
    {
        if row.blocked_at.is_some() {
            tracing::warn!(ip = %ip, count = row.failed_count, threshold, "IP permanently blocked");
            if row.failed_count == threshold_i64 {
                notify::send(
                    pool.clone(),
                    format!("IP {ip} permanently blocked after {threshold} failed auth attempts"),
                    "high",
                );
            }
        }
    }
}
