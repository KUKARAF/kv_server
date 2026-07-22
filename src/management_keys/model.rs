use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DeviceRecipient {
    pub device_id: String,
    pub key_type: String,
    pub ephemeral_pub: String,
    pub dek_nonce: String,
    pub encrypted_dek: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateManagementKeyRequest {
    pub provider: String,
    pub label: String,
    pub nonce: String,
    pub ciphertext: String,
    pub aad: String,
    pub recipients: Vec<DeviceRecipient>,
    pub default_limit: Option<f64>,
    pub default_limit_reset: Option<String>,
}

#[derive(Serialize)]
pub struct CreateManagementKeyResponse {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct ManagementKeyRow {
    pub id: String,
    pub provider: String,
    pub label: String,
    pub status: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub default_limit: Option<f64>,
    pub default_limit_reset: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateManagementKeyDefaultsRequest {
    pub default_limit: Option<f64>,
    pub default_limit_reset: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateProvisionedKeyRequest {
    pub provider_key_id: String,
    pub label: String,
    pub nonce: String,
    pub ciphertext: String,
    pub aad: String,
    pub recipients: Vec<DeviceRecipient>,
}

#[derive(Serialize)]
pub struct CreateProvisionedKeyResponse {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct ProvisionedKeyRow {
    pub id: String,
    pub provider: String,
    pub provider_key_id: String,
    pub label: String,
    pub status: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}
