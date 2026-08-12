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
    /// Present while `pending`: the one-time approval token ECDH-wrapped to the request's
    /// device. Served idempotently (NOT consumed) so the device can re-fetch and re-display
    /// the token. The device decrypts it with its private key (same routine as `envelope`)
    /// and the human relays the plaintext token to the approving admin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_envelope: Option<SessionEnvelope>,
}

/// Device-KV envelope carrying a wrapped token (all fields base64). `Deserialize` so the
/// pending approval envelope can be rehydrated from its stored JSON column when polling.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionEnvelope {
    pub nonce: String,
    pub ciphertext: String,
    pub aad: String,
    pub recipient: EnvelopeRecipient,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvelopeRecipient {
    pub key_type: String,
    pub ephemeral_pub: String,
    pub dek_nonce: String,
    pub encrypted_dek: String,
}

impl From<crate::crypto::Envelope> for SessionEnvelope {
    fn from(e: crate::crypto::Envelope) -> Self {
        SessionEnvelope {
            nonce: e.nonce,
            ciphertext: e.ciphertext,
            aad: e.aad,
            recipient: EnvelopeRecipient {
                key_type: e.key_type,
                ephemeral_pub: e.ephemeral_pub,
                dek_nonce: e.dek_nonce,
                encrypted_dek: e.encrypted_dek,
            },
        }
    }
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
    /// The one-time approval token, relayed by the requester from their device (which
    /// decrypted it out of the pending `approval_envelope`). Its sha256 must match the
    /// stored `approval_token_hash` or approval is forbidden — binding approval to a secret
    /// only the real requester's device could recover, not just a click on a pending row.
    pub approval_token: String,
}
