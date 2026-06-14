use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}
