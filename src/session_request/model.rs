use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequestBody {
    pub label: Option<String>,
    pub requested_duration_hours: Option<i64>,
    /// Registered device the approved session token will be ECDH-wrapped to. Required:
    /// the approval is only usable by whoever holds this device's private key.
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct CreateSessionRequestResponse {
    pub id: String,
    pub url: String,
    pub expires_at: String,
    /// Secret held only by the requester; required to poll for the session token.
    pub poll_secret: String,
    /// Human-verifiable code the requester must relay to the approving admin
    /// out-of-band; required (hashed) proof that an approval actually corresponds to
    /// this specific requester, not just whoever's row the admin happens to click.
    pub confirm_code: String,
}

#[derive(Debug, Deserialize)]
pub struct PollQuery {
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct PollStatusResponse {
    pub status: String,
    /// Present only in the single `approved` response that claims the token. The token is
    /// delivered ECDH-wrapped to the request's device; decrypt with the device private key
    /// using the same routine as device-KV (`kv_cli`/`kv_apk` `decrypt_device_kv`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<SessionEnvelope>,
}

/// Device-KV envelope carrying the wrapped session token (all fields base64).
#[derive(Debug, Serialize)]
pub struct SessionEnvelope {
    pub nonce: String,
    pub ciphertext: String,
    pub aad: String,
    pub recipient: EnvelopeRecipient,
}

#[derive(Debug, Serialize)]
pub struct EnvelopeRecipient {
    pub key_type: String,
    pub ephemeral_pub: String,
    pub dek_nonce: String,
    pub encrypted_dek: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SessionRequestRow {
    pub id: String,
    pub label: Option<String>,
    pub status: String,
    pub requested_at: String,
    pub expires_at: String,
    pub requested_duration_hours: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveSessionRequestBody {
    pub approved_duration_hours: Option<i64>,
    pub confirm_code: String,
}
