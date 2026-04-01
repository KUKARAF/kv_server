pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/keys", get(handlers::list_keys).post(handlers::create_key))
        .route("/keys/:id", delete(handlers::revoke_key))
        .route("/keys/:id/request-approval", post(handlers::request_approval))
        .route("/approvals", get(handlers::list_approvals))
        .route("/approvals/:id/approve", post(handlers::approve_request))
        .route("/approvals/:id/reject", post(handlers::reject_request))
        .route("/session", get(handlers::get_session))
        .route("/kv", get(handlers::list_kv_entries))
}
