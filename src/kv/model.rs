use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct KvEntry {
    pub key: String,
    pub value: String,
    pub ttl_hours: Option<f64>,
    pub ttl_sliding: bool,
    pub expires_at: Option<String>,
    pub open_access: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct KvUpsertRequest {
    #[serde(default)]
    pub value: String,
    pub ttl_hours: Option<f64>,
    #[serde(default)]
    pub ttl_sliding: bool,
    #[serde(default)]
    pub open_access: bool,
    // Zero Trust fields — all must be present together for ZT entries.
    pub zt_ciphertext: Option<String>,
    pub zt_wrapped_dek: Option<String>,
    pub zt_nonce: Option<String>,
    pub zt_aad: Option<String>,
    pub zt_credential_id: Option<String>,
    pub zt_prf_salt: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KvMetaResponse {
    pub key: String,
    pub ttl_hours: Option<f64>,
    pub ttl_sliding: bool,
    pub expires_at: Option<String>,
    pub open_access: bool,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_device_ids: Option<Vec<String>>,
}

pub fn compute_expires_at(ttl_hours: Option<f64>) -> Option<String> {
    ttl_hours.map(|h| {
        let secs = (h * 3600.0) as i64;
        (Utc::now() + Duration::seconds(secs))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    })
}

#[allow(dead_code)]
pub fn is_expired(expires_at: &Option<String>) -> bool {
    match expires_at {
        None => false,
        Some(s) => DateTime::parse_from_str(&format!("{} +0000", s), "%Y-%m-%d %H:%M:%S %z")
            .map(|dt| dt.with_timezone(&Utc) <= Utc::now())
            .unwrap_or(false),
    }
}

// ── Device-encrypted KV ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DeviceKvRecipient {
    pub device_id: String,
    pub key_type: String,
    pub ephemeral_pub: String,
    pub dek_nonce: String,
    pub encrypted_dek: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceKvWriteRequest {
    pub key: String,
    pub nonce: String,
    pub ciphertext: String,
    pub aad: String,
    pub recipients: Vec<DeviceKvRecipient>,
}
