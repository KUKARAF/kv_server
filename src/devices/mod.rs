pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{routing::{delete, get, post}, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", post(handlers::register))
}

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handlers::list))
        .route("/:id", delete(handlers::delete))
}
