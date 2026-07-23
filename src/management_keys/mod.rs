pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use std::sync::Arc;

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/",
            post(handlers::create_management_key).get(handlers::list_management_keys),
        )
        .route("/:id", patch(handlers::update_management_key_defaults))
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
            "/:id/provisioned-keys/:pk_id",
            delete(handlers::delete_provisioned_key),
        )
}
