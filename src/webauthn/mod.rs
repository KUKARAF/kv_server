pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{routing::post, Router};
use std::sync::Arc;

/// Public WebAuthn routes (no AdminAuth — auth is handled per-handler).
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/authenticate/begin", post(handlers::authenticate_begin))
        .route("/authenticate/finish", post(handlers::authenticate_finish))
}

/// Admin-only WebAuthn routes — mounted under /api/admin/webauthn.
pub fn admin_router() -> Router<Arc<AppState>> {
    use axum::routing::{delete, get};
    Router::new()
        .route("/register/begin", post(handlers::register_begin))
        .route("/register/finish", post(handlers::register_finish))
        .route("/credentials", get(handlers::list_credentials))
        .route("/credentials/:id", delete(handlers::delete_credential))
        .route("/challenge", post(handlers::prf_challenge))
}
