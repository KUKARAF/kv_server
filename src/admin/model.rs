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
    pub emoji_sequence: String,
    pub status: String,
    pub requested_at: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SessionRow {
    pub id: String,
    pub email: String,
    pub oidc_subject: String,
    pub expires_at: String,
    pub created_at: String,
}
