pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new().route("/", post(handlers::create_share))
}

pub fn public_router() -> Router<Arc<AppState>> {
    Router::new().route("/:id", get(handlers::claim_share))
}
