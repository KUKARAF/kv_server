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

/// Self-service enrollment: a headless client proposes itself with a name + public key it
/// generated locally, instead of a human copy-pasting the key into the web panel. Confirmed
/// by an admin via the existing WebAuthn ceremony (`register_begin`/`register_finish`) — the
/// passkey touch remains the real security gate, this just removes manual key/id handling.
#[derive(Debug, Deserialize)]
pub struct ProposeDeviceBody {
    pub name: String,
    pub public_key: String,
    #[serde(default = "default_key_type")]
    pub key_type: String,
}

#[derive(Debug, Serialize)]
pub struct ProposeDeviceResponse {
    pub id: String,
    /// Includes `confirm_token` as a `token` query param — the only link/QR that can load
    /// this proposal's data (and therefore drive the WebAuthn confirm ceremony) or link it.
    /// Admin-facing surfaces (dashboard toast, list endpoint) never see this token.
    pub url: String,
    pub expires_at: String,
    /// Secret held only by the proposer; required to poll for the resulting device_id.
    pub poll_secret: String,
    /// Same value embedded in `url`, exposed separately for clients building their own link.
    pub confirm_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ProposalPollQuery {
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct ProposalTokenQuery {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ProposalPollResponse {
    pub status: String,
    /// Present once `status == "confirmed"`. Not a secret — knowing your own device_id
    /// isn't a capability — so this can be polled idempotently, unlike the session envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DeviceProposalRow {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub key_type: String,
    pub requested_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkProposalBody {
    pub device_id: String,
    /// Same token required to load the proposal (`ProposalTokenQuery`) — re-checked here as
    /// defense in depth, not trusted just because the GET gate was passed earlier.
    pub token: String,
}
