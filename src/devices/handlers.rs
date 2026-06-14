use crate::{auth::middleware::AdminAuth, devices::model::*, error::AppError, state::AppState};
use axum::{extract::{Path, State}, http::StatusCode, Json};
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

pub async fn list(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<DeviceRow>>, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let rows = sqlx::query!(
        "SELECT id, name, created_at, last_seen_at FROM devices WHERE owner_id = ? ORDER BY created_at DESC",
        owner_id
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|r| DeviceRow {
        id: r.id.unwrap_or_default(),
        name: r.name,
        created_at: r.created_at,
        last_seen_at: r.last_seen_at,
    })
    .collect();
    Ok(Json(rows))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let affected = sqlx::query!(
        "DELETE FROM devices WHERE id = ? AND owner_id = ?",
        id,
        owner_id
    )
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
