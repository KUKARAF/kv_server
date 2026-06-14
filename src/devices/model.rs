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
