use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub kv_key: String,
    pub ciphertext: String,
    pub nonce: String,
    pub expires_in_hours: Option<f64>,
}

#[derive(Serialize)]
pub struct CreateShareResponse {
    pub id: String,
}

#[derive(Serialize)]
pub struct ClaimShareResponse {
    pub kv_key: String,
    pub ciphertext: String,
    pub nonce: String,
}
