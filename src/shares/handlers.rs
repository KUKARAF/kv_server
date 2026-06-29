use crate::{
    auth::middleware::AdminAuth,
    error::AppError,
    shares::model::{ClaimShareResponse, CreateShareRequest, CreateShareResponse},
    state::AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use uuid::Uuid;

pub async fn create_share(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<CreateShareRequest>,
) -> Result<(StatusCode, Json<CreateShareResponse>), AppError> {
    let owner_id = &auth.0.oidc_subject;
    let id = Uuid::new_v4().to_string();

    let expires_at = body.expires_in_hours.map(|h| {
        let secs = (h * 3600.0) as i64;
        format!(
            "{}",
            (chrono::Utc::now() + chrono::Duration::seconds(secs))
                .format("%Y-%m-%d %H:%M:%S")
        )
    });

    sqlx::query!(
        "INSERT INTO one_time_shares (id, owner_id, kv_key, ciphertext, nonce, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        id, owner_id, body.kv_key, body.ciphertext, body.nonce, expires_at
    )
    .execute(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(CreateShareResponse { id })))
}

pub async fn claim_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ClaimShareResponse>, AppError> {
    let mut tx = state.pool.begin().await?;

    let row = sqlx::query!(
        "SELECT kv_key, ciphertext, nonce FROM one_time_shares
         WHERE id = ? AND (expires_at IS NULL OR expires_at > datetime('now'))",
        id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound)?;

    sqlx::query!("DELETE FROM one_time_shares WHERE id = ?", id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Json(ClaimShareResponse {
        kv_key: row.kv_key,
        ciphertext: row.ciphertext,
        nonce: row.nonce,
    }))
}
