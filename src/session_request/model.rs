use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequestBody {
    pub label: Option<String>,
    pub requested_duration_hours: Option<i64>,
    /// Identifies an already-verified `session_request_challenges` row (see
    /// `create_challenge`/`CreateChallengeResponse`) — the caller no longer states which
    /// device it's requesting for; the device is whichever one the challenge was issued for.
    pub challenge_id: String,
    /// The plaintext nonce the caller decrypted from the challenge envelope with the
    /// device's private key. Proves possession before a pending request (and therefore an
    /// admin-visible approval prompt) is ever created.
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateChallengeBody {
    pub device_id: String,
}

#[derive(Debug, Serialize)]
pub struct CreateChallengeResponse {
    pub challenge_id: String,
    /// The nonce, ECDH-wrapped to the device's public key. Decrypt with the same routine
    /// used for `PollStatusResponse::envelope` and submit the plaintext back as `nonce` in
    /// `CreateSessionRequestBody`.
    pub envelope: SessionEnvelope,
    pub expires_at: String,
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
    /// Attacker-controlled, free-text, self-reported by whoever called `create_request` —
    /// cosmetic only. Never use this to decide whether to approve; use `device_name`, which
    /// is the device's real, immutable, owner-scoped identity.
    pub label: Option<String>,
    pub status: String,
    pub requested_at: String,
    pub expires_at: String,
    pub requested_duration_hours: Option<i64>,
    /// The requested device's real, immutable name (set at WebAuthn-gated registration).
    /// `None` only for the theoretical case of a request with no device bound.
    pub device_name: Option<String>,
    /// Whether the device belongs to the admin making this request — computed server-side
    /// from the authenticated session, never derived from anything client-supplied.
    pub is_own_device: bool,
}

#[derive(Debug, Deserialize)]
pub struct ApproveSessionRequestBody {
    pub approved_duration_hours: Option<i64>,
}
