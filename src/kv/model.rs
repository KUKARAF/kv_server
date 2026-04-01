use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct KvEntry {
    pub key: String,
    pub value: String,
    pub ttl_hours: Option<f64>,
    pub ttl_sliding: bool,
    pub expires_at: Option<String>,
    pub open_access: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct KvUpsertRequest {
    pub value: String,
    pub ttl_hours: Option<f64>,
    #[serde(default)]
    pub ttl_sliding: bool,
    #[serde(default)]
    pub open_access: bool,
}

#[derive(Debug, Serialize)]
pub struct KvResponse {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct KvMetaResponse {
    pub key: String,
    pub ttl_hours: Option<f64>,
    pub ttl_sliding: bool,
    pub expires_at: Option<String>,
    pub open_access: bool,
    pub created_at: String,
}

pub fn compute_expires_at(ttl_hours: Option<f64>) -> Option<String> {
    ttl_hours.map(|h| {
        let secs = (h * 3600.0) as i64;
        (Utc::now() + Duration::seconds(secs))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    })
}

#[allow(dead_code)]
pub fn is_expired(expires_at: &Option<String>) -> bool {
    match expires_at {
        None => false,
        Some(s) => {
            DateTime::parse_from_str(&format!("{} +0000", s), "%Y-%m-%d %H:%M:%S %z")
                .map(|dt| dt.with_timezone(&Utc) <= Utc::now())
                .unwrap_or(false)
        }
    }
}
