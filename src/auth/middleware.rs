use crate::{auth::session::{validate_session, SessionClaims}, error::AppError, state::AppState};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use std::sync::Arc;

pub struct AdminAuth(pub SessionClaims);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AdminAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if state.config.dev_mode {
            return Ok(AdminAuth(SessionClaims {
                id: "dev".to_string(),
                oidc_subject: "dev".to_string(),
                email: "dev@localhost".to_string(),
            }));
        }

        let token = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?;

        let claims = validate_session(&state.pool, token).await?;
        Ok(AdminAuth(claims))
    }
}
