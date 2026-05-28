pub mod handlers;
pub mod model;

use crate::{state::AppState, webauthn};
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
        .route(
            "/secret-requests",
            get(handlers::list_secret_requests).post(handlers::create_secret_request),
        )
        .route(
            "/secret-requests/:id/revoke",
            post(handlers::revoke_secret_request),
        )
        .route(
            "/secret-requests/:id",
            delete(handlers::delete_secret_request),
        )
        .route("/session-key", get(handlers::get_session_key).post(handlers::create_session_key))
        .route("/session-key/logout", post(handlers::logout))
        .route("/session", get(handlers::get_session_info))
        .route("/session/token", get(handlers::get_session_token))
        .route("/session/logout", post(handlers::logout))
        .route("/session/device-token", post(handlers::create_device_token))
        .route("/kv", get(handlers::list_kv_entries).put(handlers::admin_write_kv))
        .route("/blocked-ips", get(handlers::list_blocked_ips))
        .route("/blocked-ips/:ip", delete(handlers::unblock_ip))
        .route("/rate-limits", get(handlers::list_rate_counters))
        .route("/access-log", get(handlers::list_access_log))
        .route("/kv/scopes", get(handlers::list_scopes))
        .route("/kv/import", post(handlers::admin_import_kv))
        .route("/kv/:key", patch(handlers::admin_patch_kv).delete(handlers::admin_delete_kv))
        .nest("/webauthn", webauthn::admin_router())
        .nest("/device-auth", crate::device_auth::admin_router())
}