use crate::config::Config;
use dashmap::DashMap;
use openidconnect::core::CoreClient;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::sync::Arc;

pub struct AppState {
    pub pool: SqlitePool,
    pub config: Config,
    pub rate_counters: Arc<DashMap<IpAddr, u32>>,
    pub oidc_client: Option<CoreClient>,
}

impl AppState {
    pub fn new(pool: SqlitePool, config: Config, oidc_client: Option<CoreClient>) -> Arc<Self> {
        Arc::new(AppState {
            pool,
            config,
            rate_counters: Arc::new(DashMap::new()),
            oidc_client,
        })
    }
}
