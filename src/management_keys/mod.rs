pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/",
            post(handlers::create_management_key).get(handlers::list_management_keys),
        )
        .route(
            "/:id/devices/:device_id",
            get(handlers::get_management_key_envelope),
        )
        .route("/:id/revoke", post(handlers::revoke_management_key))
        .route(
            "/:id/provisioned-keys",
            post(handlers::create_provisioned_key).get(handlers::list_provisioned_keys),
        )
        .route(
            "/:id/provisioned-keys/:pk_id/devices/:device_id",
            get(handlers::get_provisioned_key_envelope),
        )
        .route(
            "/:id/provisioned-keys/:pk_id/revoke",
            post(handlers::revoke_provisioned_key),
        )
}
