pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{routing::post, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", post(handlers::register))
}
