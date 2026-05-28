use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateDeviceAuthRequest {
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateDeviceAuthResponse {
    pub id: String,
    pub url: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct PollStatusResponse {
    pub status: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveDeviceAuthRequest {
    pub label: String,
    pub scopes: Vec<DeviceAuthScope>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DeviceAuthScope {
    #[serde(rename = "key_pattern")]
    pub scope: String,
    pub ops: String,
    #[serde(default)]
    pub deny: bool,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DeviceAuthRequestRow {
    pub id: String,
    pub label: Option<String>,
    pub status: String,
    pub requested_at: String,
    pub expires_at: String,
}
