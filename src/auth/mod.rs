pub mod middleware;
pub mod oidc;
pub mod session;

use crate::state::AppState;
use axum::{routing::get, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/login", get(oidc::login))
        .route("/callback", get(oidc::callback))
}
