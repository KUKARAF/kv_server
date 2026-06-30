use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: String,
    pub label: String,
    pub key_type: String,
    pub status: String,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[allow(dead_code)]
pub struct AllowedKeyRow {
    pub id: i64,
    pub api_key_id: String,
    pub kv_key: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyWithAllowedKeys {
    #[serde(flatten)]
    pub key: ApiKeyRow,
    pub allowed_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub label: String,
    pub key_type: String, // standard | one_time | approval_required | zero_trust | shareable
    pub expires_at: Option<String>,
    /// For manually-created (non-session) keys: the list of KV key names this token may access.
    /// Session keys ignore this field and have implicit full access.
    #[serde(default)]
    pub allowed_keys: Vec<String>,
    /// For one-time or shareable keys: if provided, automatically restricts the token to this
    /// single KV key name (added to allowed_keys).
    #[serde(default)]
    pub entry_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub id: String,
    pub key: String, // plaintext — shown once
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ApprovalRow {
    pub id: String,
    pub api_key_id: String,
    pub api_key_label: String,
    #[serde(skip)] // stored as bcrypt hash — never exposed to admin
    #[allow(dead_code)]
    pub emoji_sequence: String,
    pub status: String,
    pub requested_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AdminKvWriteRequest {
    pub key: String,
    #[serde(default)]
    pub value: String,
    pub ttl_hours: Option<f64>,
    #[serde(default)]
    pub ttl_sliding: bool,
    #[serde(default)]
    pub open_access: bool,
    // Zero Trust fields — all required together when creating a ZT entry.
    pub zt_ciphertext: Option<String>,
    pub zt_wrapped_dek: Option<String>,
    pub zt_nonce: Option<String>,
    pub zt_aad: Option<String>,
    pub zt_credential_id: Option<String>,
    pub zt_prf_salt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminKvImportRequest {
    pub content: String,        // raw .env file text
    pub prefix: Option<String>, // optional key prefix, e.g. "myapp/"
    pub ttl_hours: Option<f64>,
    #[serde(default)]
    pub ttl_sliding: bool,
    #[serde(default)]
    pub open_access: bool,
}

#[derive(Debug, Serialize)]
pub struct AdminKvImportResponse {
    pub imported: usize,
    pub skipped: usize, // blank/comment lines
}

#[derive(Debug, Serialize)]
pub struct RequestApprovalResponse {
    pub confirm: String, // emoji sequence — shown to user for verification
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub confirm: String, // emoji sequence submitted by admin — must match stored sequence
}

// ── Secret request links ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateSecretRequestBody {
    pub description: Option<String>,
    pub key_prefix: Option<String>,
    pub required_keys: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct CreateSecretRequestResponse {
    pub id: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SecretRequestRow {
    pub id: String,
    pub owner_label: String,
    pub description: Option<String>,
    pub key_prefix: Option<String>,
    pub required_keys: Option<String>, // raw JSON string
    pub status: String,
    pub created_at: String,
    pub fulfilled_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretRequestPublic {
    pub owner_label: String,
    pub description: Option<String>,
    pub status: String,
    pub key_prefix: Option<String>,
    pub required_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitSecretRequestBody {
    pub entries: Vec<SubmitEntry>,
    pub bypasses: Option<Vec<BypassEntry>>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct BypassEntry {
    pub key: String,
    pub note: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FauxApprovalRow {
    pub id: String,
    pub message: String,
    pub created_at: String,
    pub secret_request_id: String,
}

// ── Blocked IPs ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct BlockedIpRow {
    pub ip: String,
    pub failed_count: i64,
    pub blocked_at: Option<String>,
    pub last_failure: String,
}

/// Info about the current active session key for an owner
#[derive(Debug, Serialize)]
pub struct SessionKeyInfo {
    pub id: String,
    pub expires_at: Option<String>,
}

/// Returned by GET /api/admin/session — used by the dashboard nav and session tab
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub email: String,
    pub oidc_subject: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}
