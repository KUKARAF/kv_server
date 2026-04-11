use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::PublicKeyCredential;

// ── Registration ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterBeginRequest {
    pub device_label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterBeginResponse {
    pub challenge_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct RegisterFinishRequest {
    pub challenge_id: String,
    pub label: Option<String>,
    pub credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct RegisterFinishResponse {
    pub credential_id: String,
}

// ── Authentication ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthenticateBeginRequest {
    /// The KV key name that is being unlocked.
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticateBeginResponse {
    pub challenge_id: String,
    pub options: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticateFinishRequest {
    pub challenge_id: String,
    pub assertion: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct AuthenticateFinishResponse {
    pub zt_token: String,
}

// ── Admin PRF challenge (creation flow) ──────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PrfChallengeRequest {
    /// base64url-encoded 32-byte salt to embed in the PRF extension.
    pub prf_salt: String,
}

#[derive(Debug, Serialize)]
pub struct PrfChallengeResponse {
    pub challenge_id: String,
    pub options: serde_json::Value,
}

// ── Credential listing ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CredentialRow {
    pub id: String,
    pub credential_id: String,
    pub device_label: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}
