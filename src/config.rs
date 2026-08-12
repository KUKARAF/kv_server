use anyhow::{Context, Result};
use std::env;

/// The sole owner allowed to set and use the reserved `NOTIFY_API_KEY` entry.
/// Resolved to an `owner_id` via the OIDC-created session key whose `label` is this email.
pub const ADMIN_EMAIL: &str = "rafal.kuka94@gmail.com";

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub listen_addr: String,

    pub dev_mode: bool,

    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_uri: String,

    pub session_signing_key: String,

    pub webauthn_rp_id: String,
    pub webauthn_rp_origin: String,
    /// Extra origin accepted in WebAuthn ceremonies for the Android app, e.g.
    /// `android:apk-key-hash:<base64url>`. Unset ⇒ web origins only.
    pub webauthn_android_origin: Option<String>,

    pub daily_rate_limit: u32,
    pub auth_failure_threshold: u32,
    pub auth_block_base_secs: u64,
    pub ttl_cleanup_interval_secs: u64,
    pub trust_proxy_headers: bool,

    pub public_base_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let dev_mode = env::var("ENV").as_deref() == Ok("DEVELOPMENT");

        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .context("DATABASE_URL is required")?,
            listen_addr: env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3000".to_string()),

            dev_mode,

            oidc_issuer_url: env::var("OIDC_ISSUER_URL")
                .unwrap_or_default(),
            oidc_client_id: env::var("OIDC_CLIENT_ID")
                .unwrap_or_default(),
            oidc_client_secret: env::var("OIDC_CLIENT_SECRET")
                .unwrap_or_default(),
            oidc_redirect_uri: env::var("OIDC_REDIRECT_URI")
                .unwrap_or_default(),

            webauthn_rp_id: env::var("WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".to_string()),
            webauthn_rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            webauthn_android_origin: env::var("WEBAUTHN_ANDROID_ORIGIN")
                .ok()
                .filter(|s| !s.is_empty()),

            session_signing_key: env::var("SESSION_SIGNING_KEY").unwrap_or_else(|_| {
                use rand::RngCore;
                let mut bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut bytes);
                let key = hex::encode(bytes);
                tracing::warn!("SESSION_SIGNING_KEY not set — generated ephemeral key (sessions will invalidate on restart)");
                key
            }),

            daily_rate_limit: env::var("DAILY_RATE_LIMIT")
                .unwrap_or_else(|_| "1000".to_string())
                .parse()
                .context("DAILY_RATE_LIMIT must be a number")?,

            auth_failure_threshold: env::var("AUTH_FAILURE_THRESHOLD")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .context("AUTH_FAILURE_THRESHOLD must be a number")?,

            // Base duration for the first temporary block; doubles per repeat
            // offense, capped at 30 days in record_auth_failure.
            auth_block_base_secs: env::var("AUTH_BLOCK_BASE_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .context("AUTH_BLOCK_BASE_SECS must be a number")?,

            ttl_cleanup_interval_secs: env::var("TTL_CLEANUP_INTERVAL_SECS")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .context("TTL_CLEANUP_INTERVAL_SECS must be a number")?,

            trust_proxy_headers: env::var("TRUST_PROXY_HEADERS")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),

            public_base_url: env::var("PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
        })
    }
}
