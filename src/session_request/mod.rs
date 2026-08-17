pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn public_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(handlers::create_request))
        .route("/challenge", post(handlers::create_challenge))
        .route("/:id/status", get(handlers::poll_status))
}

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handlers::list_pending))
        .route("/:id", get(handlers::get_request))
        .route("/:id/approve", post(handlers::approve))
        .route("/:id/reject", post(handlers::reject))
}
