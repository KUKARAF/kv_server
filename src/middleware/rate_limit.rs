use crate::{error::AppError, notify, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Resolves the client IP. When `trust_proxy` is true, honors only the
/// `x-real-ip` header (Caddy overwrites it, so clients cannot forge it through
/// the proxy); `x-forwarded-for` is never used — its leftmost entry is
/// attacker-controlled. When `trust_proxy` is false, all headers are ignored
/// and the socket peer address is used.
pub fn extract_real_ip(headers: &HeaderMap, fallback: IpAddr, trust_proxy: bool) -> IpAddr {
    if !trust_proxy {
        return fallback;
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(fallback)
}

pub async fn layer(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // Skip rate limiting only for established interactive/session clients.
    // X-Api-Key requests are NOT exempt: the counter only increments on auth
    // failures, so valid keys are unaffected while invalid-key floods get counted.
    let headers = request.headers();
    let has_auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("Bearer "))
        .unwrap_or(false)
        || headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').any(|p| p.trim().starts_with("session_token=")))
            .unwrap_or(false);

    if has_auth {
        return Ok(next.run(request).await);
    }

    // Resolve the real client IP from proxy headers set by Caddy,
    // falling back to the socket address when running without a proxy.
    let ip = extract_real_ip(headers, addr.ip(), state.config.trust_proxy_headers);

    let limit = state.config.daily_rate_limit;

    // Reject immediately if already over the limit from previous failures.
    let current = *state.rate_counters.entry(ip).or_insert(0);
    if current >= limit {
        tracing::warn!(ip = %ip, count = current, limit, "rate limit exceeded");
        return Err(AppError::RateLimited);
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let response = next.run(request).await;

    // Only count failed authentication attempts — successful requests (including
    // open-access reads) must not penalise the caller.
    if response
        .extensions()
        .get::<crate::error::AuthFailed>()
        .is_some()
    {
        let mut entry = state.rate_counters.entry(ip).or_insert(0);
        *entry += 1;
        let new_count = *entry;
        drop(entry);

        tracing::warn!(ip = %ip, count = new_count, limit, method = %method, path = %path, "rate limit counter incremented");

        if new_count == limit {
            tracing::warn!(ip = %ip, count = new_count, limit, "rate limit reached");
            notify::send(
                state.pool.clone(),
                format!("Rate limit reached by {ip}"),
                "medium",
            );
        }
    }

    Ok(response)
}
