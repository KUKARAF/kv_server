use crate::config::Config;
use dashmap::DashMap;
use openidconnect::core::CoreClient;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::sync::Arc;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration, Webauthn};

/// Pending WebAuthn registration state (between begin and finish).
pub struct RegChallengeEntry {
    pub state: PasskeyRegistration,
}

/// Pending WebAuthn authentication state (between begin and finish).
pub struct AuthChallengeEntry {
    pub state: PasskeyAuthentication,
    pub kv_key: String,
    pub owner_id: String,
    #[allow(dead_code)]
    pub prf_salt: Vec<u8>,
}

pub struct AppState {
    pub pool: SqlitePool,
    pub config: Config,
    pub rate_counters: Arc<DashMap<IpAddr, u32>>,
    pub oidc_client: Option<CoreClient>,
    pub webauthn: Option<Webauthn>,
    /// challenge_id -> registration state (cleared on finish or timeout)
    pub webauthn_reg_challenges: DashMap<String, RegChallengeEntry>,
    /// challenge_id -> authentication state
    pub webauthn_auth_challenges: DashMap<String, AuthChallengeEntry>,
    /// challenge_id -> PRF-only challenge state (for admin creation flow)
    pub webauthn_prf_challenges: DashMap<String, (Vec<Passkey>, Vec<u8>)>,
}

impl AppState {
    pub fn new(pool: SqlitePool, config: Config, oidc_client: Option<CoreClient>) -> Arc<Self> {
        let webauthn = build_webauthn(&config.webauthn_rp_id, &config.webauthn_rp_origin);
        Arc::new(AppState {
            pool,
            config,
            rate_counters: Arc::new(DashMap::new()),
            oidc_client,
            webauthn,
            webauthn_reg_challenges: DashMap::new(),
            webauthn_auth_challenges: DashMap::new(),
            webauthn_prf_challenges: DashMap::new(),
        })
    }
}

fn build_webauthn(rp_id: &str, rp_origin: &str) -> Option<Webauthn> {
    let origin = url::Url::parse(rp_origin)
        .map_err(|e| tracing::warn!("WEBAUTHN_RP_ORIGIN invalid, Zero Trust disabled: {e}"))
        .ok()?;
    webauthn_rs::WebauthnBuilder::new(rp_id, &origin)
        .map_err(|e| tracing::warn!("WebauthnBuilder failed, Zero Trust disabled: {e}"))
        .ok()?
        .rp_name("KV Manager")
        .build()
        .map_err(|e| tracing::warn!("Webauthn build failed, Zero Trust disabled: {e}"))
        .ok()
}
