pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/request-access", post(handlers::request_access))
        .route("/", get(handlers::list_entries))
        // zt-payload must be registered before /:key to avoid being matched as key="zt-payload"
        .route("/:key/zt-payload", get(handlers::get_zt_payload))
        .route("/:key", get(handlers::get_entry))
        .route("/:key", put(handlers::upsert_entry))
        .route("/:key", delete(handlers::delete_entry))
}

