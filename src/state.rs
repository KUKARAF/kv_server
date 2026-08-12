use crate::config::Config;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use openidconnect::core::CoreClient;
use sqlx::SqlitePool;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration, Webauthn};

pub const ACCESS_LOG_CAP: usize = 500;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AccessLogEntry {
    pub ip: String,
    pub api_key_id: Option<String>,
    pub key: String,
    pub op: String,
    pub ts: DateTime<Utc>,
}

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

/// Pending device-enrolment state. Registering a device requires a verified WebAuthn
/// assertion (a physical key touch), so the device fields are stashed here at `begin` and
/// only inserted at `finish` once the assertion checks out.
pub struct DeviceRegChallengeEntry {
    pub state: PasskeyAuthentication,
    pub owner_id: String,
    pub name: String,
    pub public_key: String,
    pub key_type: String,
}

pub struct AppState {
    pub pool: SqlitePool,
    pub config: Config,
    pub rate_counters: Arc<DashMap<IpAddr, u32>>,
    pub access_log: Arc<Mutex<VecDeque<AccessLogEntry>>>,
    pub oidc_client: Arc<RwLock<Option<CoreClient>>>,
    pub webauthn: Option<Webauthn>,
    /// challenge_id -> registration state (cleared on finish or timeout)
    pub webauthn_reg_challenges: DashMap<String, RegChallengeEntry>,
    /// challenge_id -> authentication state
    pub webauthn_auth_challenges: DashMap<String, AuthChallengeEntry>,
    /// challenge_id -> PRF-only challenge state (for admin creation flow)
    pub webauthn_prf_challenges: DashMap<String, (Vec<Passkey>, Vec<u8>)>,
    /// challenge_id -> pending device enrolment state (WebAuthn-gated)
    pub device_reg_challenges: DashMap<String, DeviceRegChallengeEntry>,
}

impl AppState {
    pub fn new(pool: SqlitePool, config: Config, oidc_client: Option<CoreClient>) -> Arc<Self> {
        let webauthn = build_webauthn(&config.webauthn_rp_id, &config.webauthn_rp_origin);
        Arc::new(AppState {
            pool,
            config,
            rate_counters: Arc::new(DashMap::new()),
            access_log: Arc::new(Mutex::new(VecDeque::with_capacity(ACCESS_LOG_CAP))),
            oidc_client: Arc::new(RwLock::new(oidc_client)),
            webauthn,
            webauthn_reg_challenges: DashMap::new(),
            webauthn_auth_challenges: DashMap::new(),
            webauthn_prf_challenges: DashMap::new(),
            device_reg_challenges: DashMap::new(),
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
