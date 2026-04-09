pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/keys", get(handlers::list_keys).post(handlers::create_key))
        .route("/keys/:id/revoke", post(handlers::revoke_key))
        .route("/keys/:id", delete(handlers::delete_key))
        .route("/keys/:id/request-approval", post(handlers::request_approval))
        .route("/approvals", get(handlers::list_approvals))
        .route("/approvals/:id/approve", post(handlers::approve_request))
        .route("/approvals/:id/reject", post(handlers::reject_request))
        .route("/session", get(handlers::get_session))
        .route("/kv", get(handlers::list_kv_entries).put(handlers::admin_write_kv))
        .route("/kv/scopes", get(handlers::list_scopes))
        .route("/kv/import", post(handlers::admin_import_kv))
        .route("/kv/:key", patch(handlers::admin_patch_kv))
}
