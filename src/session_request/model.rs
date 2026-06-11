use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequestBody {
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateSessionRequestResponse {
    pub id: String,
    pub url: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct PollStatusResponse {
    pub status: String,
    pub session_token: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SessionRequestRow {
    pub id: String,
    pub label: Option<String>,
    pub status: String,
    pub requested_at: String,
    pub expires_at: String,
}
