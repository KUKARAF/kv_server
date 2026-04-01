pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{delete, get, put},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handlers::list_entries))
        .route("/:key", get(handlers::get_entry))
        .route("/:key", put(handlers::upsert_entry))
        .route("/:key", delete(handlers::delete_entry))
}
