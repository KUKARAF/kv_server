use crate::{auth::middleware::AdminAuth, devices::model::*, error::AppError, state::AppState};
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use uuid::Uuid;

pub async fn register(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    let id = Uuid::new_v4().to_string();
    let owner_id = &auth.0.oidc_subject;

    sqlx::query!(
        "INSERT INTO devices (id, owner_id, name, public_key) VALUES (?, ?, ?, ?)",
        id,
        owner_id,
        body.name,
        body.public_key,
    )
    .execute(&state.pool)
    .await?;

    tracing::info!(owner_id = %owner_id, device_id = %id, name = %body.name, "device registered");

    Ok((StatusCode::CREATED, Json(RegisterDeviceResponse { id })))
}
