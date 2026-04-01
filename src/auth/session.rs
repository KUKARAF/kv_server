use crate::{error::AppError, keys::generate::{generate_session_token, hash_key}};
use sqlx::SqlitePool;
use uuid::Uuid;

#[allow(dead_code)]
pub struct SessionClaims {
    pub id: String,
    pub oidc_subject: String,
    pub email: String,
}

/// Creates a new session token, stores it hashed, returns the plaintext once.
pub async fn create_session(
    pool: &SqlitePool,
    oidc_subject: &str,
    email: &str,
) -> Result<String, AppError> {
    let (plaintext, token_hash) = generate_session_token();
    let id = Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO session_tokens (id, token_hash, oidc_subject, email, expires_at)
         VALUES (?, ?, ?, ?, datetime('now', '+10 hours'))",
        id,
        token_hash,
        oidc_subject,
        email
    )
    .execute(pool)
    .await?;

    Ok(plaintext)
}

/// Validates a session token, returns claims if valid and not expired.
pub async fn validate_session(
    pool: &SqlitePool,
    plaintext: &str,
) -> Result<SessionClaims, AppError> {
    let token_hash = hash_key(plaintext);

    let row = sqlx::query!(
        "SELECT id, oidc_subject, email
         FROM session_tokens
         WHERE token_hash = ? AND expires_at > datetime('now')",
        token_hash
    )
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    Ok(SessionClaims {
        id: row.id,
        oidc_subject: row.oidc_subject,
        email: row.email,
    })
}

#[allow(dead_code)]
/// Revokes a session token by deleting it.
pub async fn revoke_session(pool: &SqlitePool, plaintext: &str) -> Result<(), AppError> {
    let token_hash = hash_key(plaintext);
    sqlx::query!(
        "DELETE FROM session_tokens WHERE token_hash = ?",
        token_hash
    )
    .execute(pool)
    .await?;
    Ok(())
}
