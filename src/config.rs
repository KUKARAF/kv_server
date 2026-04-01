use anyhow::{Context, Result};
use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub listen_addr: String,

    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_uri: String,

    pub session_signing_key: String,

    pub daily_rate_limit: u32,
    pub ttl_cleanup_interval_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .context("DATABASE_URL is required")?,
            listen_addr: env::var("LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3000".to_string()),

            oidc_issuer_url: env::var("OIDC_ISSUER_URL")
                .context("OIDC_ISSUER_URL is required")?,
            oidc_client_id: env::var("OIDC_CLIENT_ID")
                .context("OIDC_CLIENT_ID is required")?,
            oidc_client_secret: env::var("OIDC_CLIENT_SECRET")
                .context("OIDC_CLIENT_SECRET is required")?,
            oidc_redirect_uri: env::var("OIDC_REDIRECT_URI")
                .context("OIDC_REDIRECT_URI is required")?,

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

            ttl_cleanup_interval_secs: env::var("TTL_CLEANUP_INTERVAL_SECS")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .context("TTL_CLEANUP_INTERVAL_SECS must be a number")?,
        })
    }
}
