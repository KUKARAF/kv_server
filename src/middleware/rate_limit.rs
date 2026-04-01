use crate::{error::AppError, state::AppState};
use axum::{
    extract::{ConnectInfo, State},
    middleware::Next,
    response::Response,
    http::Request,
    body::Body,
};
use std::{net::SocketAddr, sync::Arc};

pub async fn layer(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let ip = addr.ip();
    let limit = state.config.daily_rate_limit;

    let mut entry = state.rate_counters.entry(ip).or_insert(0);
    *entry += 1;
    let current = *entry;
    drop(entry);

    if current > limit {
        return Err(AppError::RateLimited);
    }

    Ok(next.run(request).await)
}
