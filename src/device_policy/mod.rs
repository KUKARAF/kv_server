//! Per-device KV key access policies and escalating temporary device bans.
//!
//! A device-bound session (session token minted via session_request approval, carrying
//! `api_keys.device_id`) may be restricted to a subset of KV entry names. Requesting a
//! disallowed entry's value bans the device (see `enforce`). Management endpoints live
//! under `/api/admin/device-policies` and are closed to device-bound sessions so a device
//! can never edit its own policy or lift its own ban.

pub mod enforce;
pub mod handlers;
pub mod model;

use crate::state::AppState;
use axum::{
    routing::{delete, get, put},
    Router,
};
use std::sync::Arc;

/// Mounted at `/api/admin/device-policies`. `/bans` is registered before `/:device_id`
/// so it can never be captured as a device id.
pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handlers::list))
        .route("/bans", get(handlers::list_bans))
        .route("/:device_id", put(handlers::update))
        .route("/:device_id/ban", delete(handlers::unban))
}
