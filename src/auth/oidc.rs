use crate::{auth::session::create_session, error::AppError, state::AppState};
use anyhow::Context;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};
use rand::RngCore;
use serde::Deserialize;
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// Initialize the OIDC client via discovery against Authentik.
pub async fn init_client(
    issuer_url: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> anyhow::Result<CoreClient> {
    let issuer = IssuerUrl::new(issuer_url.to_string())?;
    let metadata = CoreProviderMetadata::discover_async(issuer, async_http_client)
        .await
        .context("OIDC discovery failed — check OIDC_ISSUER_URL")?;

    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string())?);

    Ok(client)
}

fn sign(payload: &str, key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn encode_state_cookie(state: &str, pkce_verifier: &str, signing_key: &str) -> String {
    let payload = serde_json::json!({
        "state": state,
        "pkce_verifier": pkce_verifier,
    })
    .to_string();
    let sig = sign(&payload, signing_key);
    let encoded = URL_SAFE_NO_PAD.encode(&payload);
    format!("{}.{}", encoded, sig)
}

fn decode_state_cookie(
    cookie_value: &str,
    signing_key: &str,
) -> Option<(String, String)> {
    let (encoded, sig) = cookie_value.split_once('.')?;
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()?;
    let expected_sig = sign(&payload, signing_key);
    if sig != expected_sig {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&payload).ok()?;
    let state = v["state"].as_str()?.to_string();
    let pkce_verifier = v["pkce_verifier"].as_str()?.to_string();
    Some((state, pkce_verifier))
}

pub async fn login(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let oidc_client = state
        .oidc_client
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("OIDC not initialized")))?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let csrf_state = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let csrf_state_for_closure = csrf_state.clone();

    let (auth_url, _csrf_token, _nonce) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(csrf_state_for_closure.clone()),
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let cookie_value = encode_state_cookie(
        &csrf_state,
        pkce_verifier.secret(),
        &state.config.session_signing_key,
    );

    let cookie = Cookie::build(("oidc_state", cookie_value))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(300))
        .path("/")
        .build();

    let jar = CookieJar::new().add(cookie);
    Ok((jar, Redirect::to(auth_url.as_str())).into_response())
}

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

pub async fn callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(params): Query<CallbackParams>,
) -> Result<Response, AppError> {
    let oidc_client = state
        .oidc_client
        .as_ref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("OIDC not initialized")))?;

    // Verify state cookie
    let cookie_value = jar
        .get("oidc_state")
        .map(|c| c.value().to_string())
        .ok_or(AppError::Unauthorized)?;

    let (expected_state, pkce_verifier_secret) =
        decode_state_cookie(&cookie_value, &state.config.session_signing_key)
            .ok_or(AppError::Unauthorized)?;

    if params.state != expected_state {
        return Err(AppError::Unauthorized);
    }

    let pkce_verifier = PkceCodeVerifier::new(pkce_verifier_secret);

    // Exchange code for tokens
    let token_response = oidc_client
        .exchange_code(AuthorizationCode::new(params.code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("token exchange failed: {e}")))?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("no id_token in response")))?;

    let claims = id_token
        .claims(&oidc_client.id_token_verifier(), &Nonce::new("".to_string()))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("id_token verification failed: {e}")))?;

    let oidc_subject = claims.subject().to_string();
    let email = claims
        .email()
        .map(|e| e.to_string())
        .unwrap_or_else(|| oidc_subject.clone());

    // Issue session token
    let session_token = create_session(&state.pool, &oidc_subject, &email).await?;

    // Clear oidc_state cookie, set session cookie, redirect to admin
    let clear_cookie = Cookie::build(("oidc_state", ""))
        .http_only(true)
        .secure(true)
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();

    let session_cookie = Cookie::build(("session_token", session_token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(36000))
        .path("/")
        .build();

    let jar = jar.remove(clear_cookie).add(session_cookie);
    Ok((jar, Redirect::to("/admin/")).into_response())
}
