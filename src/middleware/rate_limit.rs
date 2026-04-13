use crate::{error::AppError, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::Response,
};
use std::{net::SocketAddr, sync::Arc};

pub async fn layer(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // Skip rate limiting for authenticated requests — any credential header is sufficient.
    // The actual endpoints will reject invalid tokens; we don't need to validate here.
    let headers = request.headers();
    let has_auth = headers.contains_key("x-api-key")
        || headers
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
    let ip = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse().ok())
        })
        .unwrap_or_else(|| addr.ip());

    let limit = state.config.daily_rate_limit;
    let mut entry = state.rate_counters.entry(ip).or_insert(0);
    *entry += 1;
    let current = *entry;
    drop(entry);

    if current > limit {
        tracing::warn!(ip = %ip, count = current, limit, "rate limit exceeded");
        return Err(AppError::RateLimited);
    }

    Ok(next.run(request).await)
}
