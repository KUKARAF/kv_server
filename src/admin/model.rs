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
pub struct ScopeRow {
    pub id: String,
    pub api_key_id: String,
    pub key_pattern: String,
    pub ops: String,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyWithScopes {
    #[serde(flatten)]
    pub key: ApiKeyRow,
    pub scopes: Vec<ScopeRow>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub label: String,
    pub key_type: String, // standard | one_time | approval_required
    pub expires_at: Option<String>,
    pub scopes: Vec<CreateScopeRequest>,
}

#[derive(Debug, Deserialize)]
pub struct CreateScopeRequest {
    pub key_pattern: String,
    pub ops: String, // comma-separated: read,write,delete,list
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
    pub scope: Option<String>,
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
    pub content: String,          // raw .env file text
    pub prefix: Option<String>,   // optional key prefix, e.g. "myapp/"
    pub scope: Option<String>,
    pub ttl_hours: Option<f64>,
    #[serde(default)]
    pub ttl_sliding: bool,
    #[serde(default)]
    pub open_access: bool,
}

#[derive(Debug, Deserialize)]
pub struct AdminKvPatchRequest {
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminKvImportResponse {
    pub imported: usize,
    pub skipped: usize,  // blank/comment lines
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
    pub scope: Option<String>,
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
    pub scope: Option<String>,
    pub status: String,
    pub created_at: String,
    pub fulfilled_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretRequestPublic {
    pub owner_label: String,
    pub description: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitSecretRequestBody {
    pub entries: Vec<SubmitEntry>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitEntry {
    pub key: String,
    pub value: String,
}

// ── Session ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SessionRow {
    pub id: String,
    pub email: String,
    pub oidc_subject: String,
    pub expires_at: String,
    pub created_at: String,
}
