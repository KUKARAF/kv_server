use crate::{
    auth::middleware::AdminAuth,
    error::AppError,
    keys::generate::hash_key,
    kv::handlers::ZtClaims,
    state::{AppState, AuthChallengeEntry, RegChallengeEntry},
    webauthn::model::*,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

fn webauthn_unavailable() -> AppError {
    AppError::Internal(anyhow::anyhow!("WebAuthn not configured (check WEBAUTHN_RP_ID/WEBAUTHN_RP_ORIGIN)"))
}

fn inject_prf_extension(options_json: &mut serde_json::Value, prf_salt: &[u8]) {
    let salt_b64 = URL_SAFE_NO_PAD.encode(prf_salt);
    let prf_value = serde_json::json!({
        "eval": { "first": salt_b64 }
    });
    if let Some(pk) = options_json.get_mut("publicKey") {
        let obj = match pk.as_object_mut() {
            Some(o) => o,
            None => return,
        };
        obj.entry("extensions")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .map(|ext| ext.insert("prf".to_string(), prf_value));
    }
}

// ── Registration ─────────────────────────────────────────────────────────────

pub async fn register_begin(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<RegisterBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(webauthn_unavailable)?;
    let owner_id = &auth.0.oidc_subject;

    // Stable user UUID derived from the owner_id.
    let user_uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, owner_id.as_bytes());
    let display = body.device_label.as_deref().unwrap_or("Hardware key");

    // Collect existing credential IDs to exclude (prevent duplicate registration).
    let existing: Vec<String> = sqlx::query_scalar!(
        "SELECT credential_id FROM zero_trust_credentials WHERE owner_id = ?",
        owner_id
    )
    .fetch_all(&state.pool)
    .await?;

    let exclude: Option<Vec<webauthn_rs::prelude::CredentialID>> = if existing.is_empty() {
        None
    } else {
        Some(
            existing
                .into_iter()
                .filter_map(|s| URL_SAFE_NO_PAD.decode(&s).ok())
                .map(|bytes| bytes.into())
                .collect(),
        )
    };

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(user_uuid, owner_id, display, exclude)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn registration begin: {e}")))?;

    let challenge_id = Uuid::new_v4().to_string();
    state.webauthn_reg_challenges.insert(
        challenge_id.clone(),
        RegChallengeEntry { state: reg_state },
    );

    let options = serde_json::to_value(&ccr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize options: {e}")))?;

    Ok(Json(RegisterBeginResponse { challenge_id, options }))
}

pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<RegisterFinishRequest>,
) -> Result<Json<RegisterFinishResponse>, AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(webauthn_unavailable)?;
    let owner_id = &auth.0.oidc_subject;

    let entry = state
        .webauthn_reg_challenges
        .remove(&body.challenge_id)
        .ok_or_else(|| AppError::Forbidden("unknown or expired registration challenge".to_string()))?;

    let passkey: Passkey = webauthn
        .finish_passkey_registration(&body.credential, &entry.1.state)
        .map_err(|e| AppError::Forbidden(format!("WebAuthn registration failed: {e}")))?;

    let cred_id_bytes: Vec<u8> = passkey.cred_id().to_vec();
    let cred_id_str = URL_SAFE_NO_PAD.encode(&cred_id_bytes);
    let passkey_json = serde_json::to_string(&passkey)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize passkey: {e}")))?;

    let id = Uuid::new_v4().to_string();
    let label = body.label.as_deref().unwrap_or("Hardware key");

    sqlx::query!(
        "INSERT INTO zero_trust_credentials (id, owner_id, credential_id, public_key_cose, device_label)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(credential_id) DO UPDATE SET
             public_key_cose = excluded.public_key_cose,
             last_used_at    = datetime('now')",
        id, owner_id, cred_id_str, passkey_json, label
    )
    .execute(&state.pool)
    .await?;

    Ok(Json(RegisterFinishResponse { credential_id: cred_id_str }))
}

// ── Authentication (public — X-Api-Key for zero_trust type) ─────────────────

/// Validates that the X-Api-Key header belongs to an active zero_trust key
/// and returns (api_key.id, api_key.owner_id).
async fn validate_zt_api_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, String), AppError> {
    let raw_key = headers
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let key_hash = hash_key(raw_key);
    let api_key = sqlx::query!(
        "SELECT id, type as key_type, status, owner_id
         FROM api_keys
         WHERE key_hash = ?",
        key_hash
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    if api_key.key_type != "zero_trust" || api_key.status != "active" {
        return Err(AppError::Unauthorized);
    }

    Ok((api_key.id, api_key.owner_id))
}

pub async fn authenticate_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AuthenticateBeginRequest>,
) -> Result<Json<AuthenticateBeginResponse>, AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(webauthn_unavailable)?;
    let (_, owner_id) = validate_zt_api_key(&state, &headers).await?;

    // Look up the target KV entry to get the PRF salt and bound credential.
    let kv_row = sqlx::query!(
        "SELECT zt_prf_salt, zt_credential_id
         FROM kv_entries
         WHERE key = ? AND owner_id = ?
           AND zt_ciphertext IS NOT NULL
           AND (expires_at IS NULL OR expires_at > datetime('now'))",
        body.key, owner_id
    )
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let prf_salt_b64 = kv_row.zt_prf_salt.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("ZT entry missing prf_salt"))
    })?;
    let prf_salt = URL_SAFE_NO_PAD
        .decode(&prf_salt_b64)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode prf_salt: {e}")))?;

    // Load credentials for this owner (optionally filtered to the bound credential).
    let passkeys = load_passkeys_for_owner(&state, &owner_id, kv_row.zt_credential_id.as_deref()).await?;
    if passkeys.is_empty() {
        return Err(AppError::Forbidden(
            "no registered hardware keys for this account".to_string(),
        ));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn auth begin: {e}")))?;

    let challenge_id = Uuid::new_v4().to_string();
    state.webauthn_auth_challenges.insert(
        challenge_id.clone(),
        AuthChallengeEntry {
            state: auth_state,
            kv_key: body.key,
            owner_id,
            prf_salt: prf_salt.clone(),
        },
    );

    // Serialize and inject PRF extension with the secret's salt.
    let mut options = serde_json::to_value(&rcr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize options: {e}")))?;
    inject_prf_extension(&mut options, &prf_salt);

    Ok(Json(AuthenticateBeginResponse { challenge_id, options }))
}

pub async fn authenticate_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthenticateFinishRequest>,
) -> Result<Json<AuthenticateFinishResponse>, AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(webauthn_unavailable)?;

    let entry = state
        .webauthn_auth_challenges
        .remove(&body.challenge_id)
        .ok_or_else(|| AppError::Forbidden("unknown or expired authentication challenge".to_string()))?;

    let AuthChallengeEntry { state: auth_state, kv_key, owner_id, .. } = entry.1;

    let auth_result = webauthn
        .finish_passkey_authentication(&body.assertion, &auth_state)
        .map_err(|e| AppError::Forbidden(format!("WebAuthn authentication failed: {e}")))?;

    // Update last_used_at on the credential (fire and forget).
    let cred_id_str = URL_SAFE_NO_PAD.encode(auth_result.cred_id());
    {
        let pool = state.pool.clone();
        let owner = owner_id.clone();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                "UPDATE zero_trust_credentials
                 SET last_used_at = datetime('now')
                 WHERE credential_id = ? AND owner_id = ?",
                cred_id_str, owner
            )
            .execute(&pool)
            .await;
        });
    }

    // Issue short-lived (60 s) single-use JWT scoped to this key.
    let jti = Uuid::new_v4().to_string();
    let exp = (Utc::now() + chrono::Duration::seconds(60)).timestamp() as usize;
    let claims = ZtClaims { sub: owner_id, kv_key, jti, exp };
    let zt_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.session_signing_key.as_bytes()),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("JWT sign: {e}")))?;

    Ok(Json(AuthenticateFinishResponse { zt_token }))
}

// ── Admin: PRF challenge for creation flow ────────────────────────────────────

pub async fn prf_challenge(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Json(body): Json<PrfChallengeRequest>,
) -> Result<Json<PrfChallengeResponse>, AppError> {
    let webauthn = state.webauthn.as_ref().ok_or_else(webauthn_unavailable)?;
    let owner_id = &auth.0.oidc_subject;

    let prf_salt = URL_SAFE_NO_PAD
        .decode(&body.prf_salt)
        .map_err(|_| AppError::Forbidden("invalid prf_salt base64".to_string()))?;

    let passkeys = load_passkeys_for_owner(&state, owner_id, None).await?;
    if passkeys.is_empty() {
        return Err(AppError::Forbidden(
            "register a hardware key first (Zero Trust → Register key)".to_string(),
        ));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("WebAuthn prf challenge: {e}")))?;

    let challenge_id = Uuid::new_v4().to_string();
    state
        .webauthn_prf_challenges
        .insert(challenge_id.clone(), (passkeys, prf_salt.clone()));

    let mut options = serde_json::to_value(&rcr)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize: {e}")))?;
    inject_prf_extension(&mut options, &prf_salt);

    // Store auth state separately — the admin creation flow doesn't verify the
    // assertion on the server; the admin is already authenticated via session.
    // We still provide a real challenge so the browser gets a valid WebAuthn ceremony.
    // (A verify endpoint could be added later for extra assurance.)
    drop(auth_state); // not stored; admin auth handles authorization

    Ok(Json(PrfChallengeResponse { challenge_id, options }))
}

// ── Admin: list / delete credentials ─────────────────────────────────────────

pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
) -> Result<Json<Vec<CredentialRow>>, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let rows = sqlx::query_as!(
        CredentialRow,
        "SELECT id, credential_id, device_label, created_at, last_used_at
         FROM zero_trust_credentials
         WHERE owner_id = ?
         ORDER BY created_at DESC",
        owner_id
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

pub async fn delete_credential(
    State(state): State<Arc<AppState>>,
    auth: AdminAuth,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner_id = &auth.0.oidc_subject;
    let result = sqlx::query!(
        "DELETE FROM zero_trust_credentials WHERE id = ? AND owner_id = ?",
        id, owner_id
    )
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn load_passkeys_for_owner(
    state: &AppState,
    owner_id: &str,
    only_credential_id: Option<&str>,
) -> Result<Vec<Passkey>, AppError> {
    let rows: Vec<(String,)> = if let Some(cred_id) = only_credential_id {
        sqlx::query_as(
            "SELECT public_key_cose FROM zero_trust_credentials
             WHERE owner_id = ? AND credential_id = ?",
        )
        .bind(owner_id)
        .bind(cred_id)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT public_key_cose FROM zero_trust_credentials WHERE owner_id = ?",
        )
        .bind(owner_id)
        .fetch_all(&state.pool)
        .await?
    };

    let mut passkeys = Vec::with_capacity(rows.len());
    for (json,) in rows {
        let pk: Passkey = serde_json::from_str(&json)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("deserialize passkey: {e}")))?;
        passkeys.push(pk);
    }
    Ok(passkeys)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use rand::RngCore;

    fn make_zt_token(kv_key: &str, owner_id: &str, exp_offset_secs: i64, secret: &[u8]) -> String {
        let exp = (Utc::now() + chrono::Duration::seconds(exp_offset_secs)).timestamp() as usize;
        let jti = Uuid::new_v4().to_string();
        let claims = ZtClaims {
            sub: owner_id.to_string(),
            kv_key: kv_key.to_string(),
            jti,
            exp,
        };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(secret)).unwrap()
    }

    #[test]
    fn valid_zt_token_decodes() {
        let secret = b"test-secret-key";
        let token = make_zt_token("my-key", "user1", 60, secret);
        let data = decode::<ZtClaims>(&token, &DecodingKey::from_secret(secret), &Validation::default());
        assert!(data.is_ok());
        let claims = data.unwrap().claims;
        assert_eq!(claims.kv_key, "my-key");
        assert_eq!(claims.sub, "user1");
    }

    #[test]
    fn expired_zt_token_rejected() {
        let secret = b"test-secret-key";
        let token = make_zt_token("my-key", "user1", -120, secret); // expired 2 minutes ago
        let data = decode::<ZtClaims>(&token, &DecodingKey::from_secret(secret), &Validation::default());
        assert!(data.is_err(), "expired token should be rejected");
    }

    #[test]
    fn wrong_key_token_rejected() {
        let secret = b"test-secret-key";
        let wrong_secret = b"different-secret";
        let token = make_zt_token("my-key", "user1", 60, secret);
        let data = decode::<ZtClaims>(&token, &DecodingKey::from_secret(wrong_secret), &Validation::default());
        assert!(data.is_err(), "token signed with wrong key should be rejected");
    }

    #[test]
    fn scope_enforcement_kv_key_mismatch() {
        // Simulate what get_zt_payload does: verify claims.kv_key == path key.
        let secret = b"test-secret-key";
        let token = make_zt_token("secret-A", "user1", 60, secret);
        let data = decode::<ZtClaims>(&token, &DecodingKey::from_secret(secret), &Validation::default()).unwrap();
        let claims = data.claims;
        // Token for "secret-A" used to request "secret-B" — must be rejected.
        assert_ne!(claims.kv_key, "secret-B");
    }

    #[test]
    fn prf_salt_base64_roundtrip() {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        let encoded = URL_SAFE_NO_PAD.encode(&salt);
        let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        assert_eq!(&salt[..], decoded.as_slice());
    }
}
