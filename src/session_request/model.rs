use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequestBody {
    pub label: Option<String>,
    pub requested_duration_hours: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateSessionRequestResponse {
    pub id: String,
    pub url: String,
    pub expires_at: String,
    /// Secret held only by the requester; required to poll for the session token.
    pub poll_secret: String,
    /// Human-verifiable code the requester must relay to the approving admin
    /// out-of-band; required (hashed) proof that an approval actually corresponds to
    /// this specific requester, not just whoever's row the admin happens to click.
    pub confirm_code: String,
}

#[derive(Debug, Deserialize)]
pub struct PollQuery {
    pub secret: String,
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
    pub requested_duration_hours: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveSessionRequestBody {
    pub approved_duration_hours: Option<i64>,
    pub confirm_code: String,
}
