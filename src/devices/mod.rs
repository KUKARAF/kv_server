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
        .route("/register/begin", post(handlers::register_begin))
        .route("/register/finish", post(handlers::register_finish))
        .route("/propose", post(handlers::propose))
        .route("/propose/:id/status", get(handlers::poll_proposal_status))
        // A device reading its own device-encrypted KV entry: device-facing and
        // self-authenticating (AdminAuth accepts the device's session token), so
        // it belongs on the public /api/devices nest too — matching the path the
        // clients and the plain-KV 403 hint already point at. Also mounted under
        // /api/admin/devices (admin_router) for the web UI.
        .route("/:device_id/kv/:kv_key", get(handlers::get_device_kv))
}

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handlers::list))
        .route(
            "/:id",
            delete(handlers::delete).patch(handlers::set_default_recipient),
        )
        .route("/:device_id/kv/:kv_key", get(handlers::get_device_kv))
}

pub fn proposal_admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handlers::list_proposals))
        .route("/:id", get(handlers::get_proposal))
        .route("/:id/link", post(handlers::link_proposal))
        .route("/:id/reject", post(handlers::reject_proposal))
}
