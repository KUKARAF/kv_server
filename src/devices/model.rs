use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub public_key: String,
    #[serde(default = "default_key_type")]
    pub key_type: String,
}

fn default_key_type() -> String {
    "p256".to_string()
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    pub id: String,
}

/// `begin` returns a WebAuthn authentication challenge; the device fields from
/// `RegisterDeviceRequest` are stashed server-side keyed by `challenge_id`.
#[derive(Debug, Serialize)]
pub struct RegisterDeviceBeginResponse {
    pub challenge_id: String,
    pub options: serde_json::Value,
}

/// `finish` carries only the challenge id and the signed assertion — the device fields
/// were captured at `begin` so they can't be swapped after the key touch.
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceFinishRequest {
    pub challenge_id: String,
    pub assertion: webauthn_rs::prelude::PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub public_key: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}
