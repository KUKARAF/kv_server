use crate::{config::Config, devices, keys::generate::generate_api_key, kv, middleware, shares, state::AppState};
use axum::{
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::Request,
    middleware as axum_middleware,
    Router,
};
use rstest::rstest;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const TEST_OWNER: &str = "test-owner";
const SCOPED_KEY: &str = "scoped-key";
const OPEN_KEY: &str = "open-key";

fn test_config() -> Config {
    Config {
        database_url: "sqlite::memory:".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        dev_mode: false,
        oidc_issuer_url: String::new(),
        oidc_client_id: String::new(),
        oidc_client_secret: String::new(),
        oidc_redirect_uri: String::new(),
        // 64 hex chars = 32 bytes, enough for any signing use
        session_signing_key: "a".repeat(64),
        webauthn_rp_id: "localhost".to_string(),
        webauthn_rp_origin: "http://localhost:3000".to_string(),
        daily_rate_limit: 100,
        auth_failure_threshold: 50,
        ttl_cleanup_interval_secs: 300,
        public_base_url: "http://localhost:3000".to_string(),
    }
}

async fn build_test_app() -> (Router, Arc<AppState>) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    let state = AppState::new(pool, test_config(), None);
    let mock_addr = SocketAddr::new(TEST_IP, 12345);

    let app = Router::new()
        .nest("/kv", kv::router())
        .nest("/api/devices", devices::router())
        .nest("/api/admin/devices", devices::admin_router())
        .layer(axum_middleware::from_fn(middleware::security_headers::layer))
        .layer(axum_middleware::from_fn_with_state(
            Arc::clone(&state),
            middleware::rate_limit::layer,
        ))
        .layer(axum_middleware::from_fn_with_state(
            Arc::clone(&state),
            middleware::ip_block::layer,
        ))
        .with_state(Arc::clone(&state))
        .layer(MockConnectInfo(mock_addr));

    (app, state)
}

fn rate_count(state: &AppState) -> u32 {
    state.rate_counters.get(&TEST_IP).map(|v| *v).unwrap_or(0)
}

async fn block_count(pool: &SqlitePool) -> i64 {
    let ip_str = TEST_IP.to_string();
    sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(failed_count, 0) FROM blocked_ips WHERE ip = ?",
    )
    .bind(&ip_str)
    .fetch_optional(pool)
    .await
    .unwrap()
    .unwrap_or(0)
}

async fn seed_open_access_entry(pool: &SqlitePool) {
    sqlx::query(
        "INSERT INTO kv_entries (key, owner_id, value, open_access) VALUES (?, '', 'public', 1)",
    )
    .bind(OPEN_KEY)
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_scoped_entry(pool: &SqlitePool) {
    sqlx::query(
        "INSERT INTO kv_entries (key, owner_id, value, scope) VALUES (?, ?, 'secret', 'restricted')",
    )
    .bind(SCOPED_KEY)
    .bind(TEST_OWNER)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_session_key(pool: &SqlitePool, status: &str, expires_at: Option<&str>) -> String {
    let (plaintext, hash) = generate_api_key();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id, expires_at)
         VALUES (?, ?, 'test-session', 'session', ?, ?, ?)",
    )
    .bind(&id)
    .bind(&hash)
    .bind(status)
    .bind(TEST_OWNER)
    .bind(expires_at)
    .execute(pool)
    .await
    .unwrap();
    plaintext
}

async fn insert_api_key(
    pool: &SqlitePool,
    status: &str,
    expires_at: Option<&str>,
    scope: &str,
) -> String {
    let (plaintext, hash) = generate_api_key();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id, expires_at)
         VALUES (?, ?, 'test-key', 'standard', ?, ?, ?)",
    )
    .bind(&id)
    .bind(&hash)
    .bind(status)
    .bind(TEST_OWNER)
    .bind(expires_at)
    .execute(pool)
    .await
    .unwrap();

    let scope_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO api_key_scopes (id, api_key_id, scope, ops) VALUES (?, ?, ?, 'read')",
    )
    .bind(&scope_id)
    .bind(&id)
    .bind(scope)
    .execute(pool)
    .await
    .unwrap();

    plaintext
}

fn req(method: &str, path: &str, bearer: Option<&str>, body: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(s) => Body::from(s.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

fn get_req(path: &str, bearer: Option<String>, api_key: Option<String>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(token) = bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(key) = api_key {
        builder = builder.header("X-Api-Key", key);
    }
    builder.body(Body::empty()).unwrap()
}

/// Each variant describes how to acquire credentials for a test scenario.
/// The actual token is seeded at runtime so it must be constructed after build_test_app().
enum Cred {
    None,
    BearerUnknown,
    BearerValid,
    BearerExpired,
    BearerRevoked,
    ApiKeyUnknown,
    ApiKeyValid,
    ApiKeyExpired,
    ApiKeyRevoked,
    ApiKeyWrongScope,
}

async fn resolve_cred(cred: Cred, pool: &SqlitePool) -> (Option<String>, Option<String>) {
    match cred {
        Cred::None => (None, None),
        Cred::BearerUnknown => (Some("kv_notindatabaseatall".to_string()), None),
        Cred::BearerValid => (Some(insert_session_key(pool, "active", None).await), None),
        Cred::BearerExpired => {
            (Some(insert_session_key(pool, "active", Some("2020-01-01 00:00:00")).await), None)
        }
        Cred::BearerRevoked => (Some(insert_session_key(pool, "revoked", None).await), None),
        Cred::ApiKeyUnknown => (None, Some("kv_notindatabaseatall".to_string())),
        Cred::ApiKeyValid => (None, Some(insert_api_key(pool, "active", None, "*").await)),
        Cred::ApiKeyExpired => (
            None,
            Some(insert_api_key(pool, "active", Some("2020-01-01 00:00:00"), "*").await),
        ),
        Cred::ApiKeyRevoked => (None, Some(insert_api_key(pool, "revoked", None, "*").await)),
        // scope 'allowed' does not cover kv entry scope 'restricted'
        Cred::ApiKeyWrongScope => {
            (None, Some(insert_api_key(pool, "active", None, "allowed").await))
        }
    }
}

/// Verifies all 11 scenarios from expected_behaviour_for_tests.md.
///
/// Each case encodes: scenario number, request path, credential kind,
/// whether the rate counter should increment, whether the block counter should increment.
#[rstest]
#[case(1,  "/kv/protected-key", Cred::None,           true,  true )]
#[case(2,  "/kv/protected-key", Cred::BearerUnknown,  false, false)]
#[case(3,  "/kv/protected-key", Cred::BearerValid,    false, false)]
#[case(4,  "/kv/protected-key", Cred::BearerExpired,  false, false)]
#[case(5,  "/kv/protected-key", Cred::BearerRevoked,  false, true )]
#[case(6,  "/kv/protected-key", Cred::ApiKeyUnknown,  false, true )]
#[case(7,  "/kv/protected-key", Cred::ApiKeyValid,    false, false)]
#[case(8,  "/kv/protected-key", Cred::ApiKeyExpired,  false, true )]
#[case(9,  "/kv/protected-key", Cred::ApiKeyRevoked,  false, true )]
#[case(10, "/kv/scoped-key",    Cred::ApiKeyWrongScope, false, false)]
#[case(11, "/kv/open-key",      Cred::None,           false, false)]
#[tokio::test]
async fn auth_counter_behaviour(
    #[case] scenario: u8,
    #[case] path: &'static str,
    #[case] cred: Cred,
    #[case] expect_rate_inc: bool,
    #[case] expect_block_inc: bool,
) {
    let (app, state) = build_test_app().await;
    let pool = &state.pool;

    seed_open_access_entry(pool).await;
    seed_scoped_entry(pool).await;

    let (bearer, api_key) = resolve_cred(cred, pool).await;
    let req = get_req(path, bearer, api_key);

    app.oneshot(req).await.unwrap();

    // Allow fire-and-forget tokio::spawn tasks (record_auth_failure) to complete.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let rate = rate_count(&state);
    let block = block_count(pool).await;

    assert_eq!(
        rate > 0,
        expect_rate_inc,
        "scenario {scenario}: rate counter expected {}, got {rate}",
        if expect_rate_inc { "increment" } else { "no change" }
    );
    assert_eq!(
        block > 0,
        expect_block_inc,
        "scenario {scenario}: block counter expected {}, got {block}",
        if expect_block_inc { "increment" } else { "no change" }
    );
}

/// Verifies that each endpoint enforces authentication correctly.
///
/// Unauthenticated requests return 401 JSON.
/// Authenticated requests reach the handler and return the expected status.
#[rstest]
// ── unauthenticated → 401 ───────────────────────────────────────────────────
#[case("POST",   "/api/devices",                   Some(r#"{"name":"t","public_key":"dGVzdA=="}"#), false, 401)]
#[case("GET",    "/api/admin/devices",             None,                                             false, 401)]
#[case("DELETE", "/api/admin/devices/nonexistent", None,                                             false, 401)]
// ── authenticated → handler response ────────────────────────────────────────
#[case("POST",   "/api/devices",                   Some(r#"{"name":"t","public_key":"dGVzdA=="}"#), true,  201)]
#[case("GET",    "/api/admin/devices",             None,                                             true,  200)]
#[case("DELETE", "/api/admin/devices/nonexistent", None,                                             true,  404)]
#[tokio::test]
async fn endpoint_auth(
    #[case] method: &str,
    #[case] path: &str,
    #[case] body: Option<&str>,
    #[case] authenticated: bool,
    #[case] expected_status: u16,
) {
    let (app, state) = build_test_app().await;

    let token = if authenticated {
        Some(insert_session_key(&state.pool, "active", None).await)
    } else {
        None
    };

    let request = req(method, path, token.as_deref(), body);
    let resp = app.oneshot(request).await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        expected_status,
        "{method} {path} authenticated={authenticated}"
    );
}

// ── One-time share tests ─────────────────────────────────────────────────────

/// These tests cover every step of the one-time share lifecycle:
///
/// Step 1  – create a share (POST /api/admin/shares): 201 + id returned
/// Step 2  – DB stores ciphertext, never the raw plaintext
/// Step 3a – claim (GET /api/share/:id): payload decrypts to the original value
/// Step 3b – share row is gone from DB after a successful claim
/// Step 3c – second claim on the same id returns 404
/// Step 3d – a failed claim (wrong id) leaves the real share untouched
mod share_tests {
    use super::*;
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use axum::body::to_bytes;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::RngCore;

    // ── App builder ───────────────────────────────────────────────────────────

    async fn build_share_app() -> (Router, Arc<AppState>) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let state = AppState::new(pool, test_config(), None);
        let app = Router::new()
            .nest("/api/admin/shares", shares::admin_router())
            .nest("/api/share", shares::public_router())
            .with_state(Arc::clone(&state));
        (app, state)
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    struct Fixture {
        key_bytes: Vec<u8>,
        ciphertext_b64: String,
        nonce_b64: String,
        plaintext: String,
    }

    fn encrypt_value(plaintext: &str) -> Fixture {
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut key_bytes);
        rng.fill_bytes(&mut nonce_bytes);
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = Aes256Gcm::new(key)
            .encrypt(nonce, plaintext.as_bytes())
            .unwrap();
        Fixture {
            key_bytes: key_bytes.to_vec(),
            ciphertext_b64: URL_SAFE_NO_PAD.encode(&ciphertext),
            nonce_b64: URL_SAFE_NO_PAD.encode(&nonce_bytes),
            plaintext: plaintext.to_string(),
        }
    }

    fn decrypt_value(fixture: &Fixture, ciphertext_b64: &str, nonce_b64: &str) -> String {
        let ct = URL_SAFE_NO_PAD.decode(ciphertext_b64).unwrap();
        let n  = URL_SAFE_NO_PAD.decode(nonce_b64).unwrap();
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&fixture.key_bytes);
        let plaintext = Aes256Gcm::new(key)
            .decrypt(Nonce::from_slice(&n), ct.as_slice())
            .expect("decryption failed — ciphertext or key is wrong");
        String::from_utf8(plaintext).unwrap()
    }

    // ── Request helpers ───────────────────────────────────────────────────────

    async fn post_share(app: &Router, session_token: &str, kv_key: &str, f: &Fixture) -> String {
        let body = serde_json::json!({
            "kv_key": kv_key,
            "ciphertext": f.ciphertext_b64,
            "nonce": f.nonce_b64,
            "expires_in_hours": 48.0,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/shares")
                    .header("Authorization", format!("Bearer {session_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 201, "create share must return 201");
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn get_share(app: &Router, share_id: &str) -> (u16, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/share/{share_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn share_row_exists(pool: &SqlitePool, share_id: &str) -> bool {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM one_time_shares WHERE id = ?",
        )
        .bind(share_id)
        .fetch_one(pool)
        .await
        .unwrap()
            > 0
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Step 1: POST /api/admin/shares → 201 with a non-empty id.
    #[tokio::test]
    async fn step1_create_share_returns_id() {
        let (app, state) = build_share_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let f = encrypt_value("my-secret");
        let id = post_share(&app, &token, "MY_KEY", &f).await;
        assert!(!id.is_empty(), "returned id must not be empty");
    }

    /// Step 1 (auth): Unauthenticated create must be rejected.
    #[tokio::test]
    async fn step1_create_share_requires_auth() {
        let (app, _state) = build_share_app().await;
        let f = encrypt_value("my-secret");
        let body = serde_json::json!({
            "kv_key": "KEY", "ciphertext": f.ciphertext_b64,
            "nonce": f.nonce_b64, "expires_in_hours": 1.0,
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/shares")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401, "unauthenticated create must return 401");
    }

    /// Step 2: DB must store the encrypted blob, not the raw plaintext.
    #[tokio::test]
    async fn step2_db_stores_ciphertext_not_plaintext() {
        let (app, state) = build_share_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let plaintext = "super-secret-value-that-must-not-appear-in-db";
        let f = encrypt_value(plaintext);
        let id = post_share(&app, &token, "MY_KEY", &f).await;

        let stored_ciphertext = sqlx::query_scalar::<_, String>(
            "SELECT ciphertext FROM one_time_shares WHERE id = ?",
        )
        .bind(&id)
        .fetch_one(&state.pool)
        .await
        .unwrap();

        let stored_nonce = sqlx::query_scalar::<_, String>(
            "SELECT nonce FROM one_time_shares WHERE id = ?",
        )
        .bind(&id)
        .fetch_one(&state.pool)
        .await
        .unwrap();

        assert_ne!(
            stored_ciphertext, plaintext,
            "DB must not store the raw plaintext as ciphertext"
        );
        assert!(
            !stored_ciphertext.contains(plaintext),
            "plaintext must not appear as a substring of the stored ciphertext"
        );
        // nonce must also be opaque (not the plaintext)
        assert_ne!(stored_nonce, plaintext);
    }

    /// Step 3a: GET /api/share/:id returns 200 and the payload decrypts to the original value.
    #[tokio::test]
    async fn step3a_claim_decrypts_to_original_value() {
        let (app, state) = build_share_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let plaintext = "the-real-secret";
        let f = encrypt_value(plaintext);
        let id = post_share(&app, &token, "DECRYPTION_KEY", &f).await;

        let (status, json) = get_share(&app, &id).await;
        assert_eq!(status, 200, "first claim must succeed");
        assert_eq!(
            json["kv_key"].as_str().unwrap(),
            "DECRYPTION_KEY",
            "kv_key must match what was stored"
        );

        let recovered = decrypt_value(
            &f,
            json["ciphertext"].as_str().unwrap(),
            json["nonce"].as_str().unwrap(),
        );
        assert_eq!(recovered, plaintext, "decrypted value must match original plaintext");
    }

    /// Step 3b: Share row is deleted from DB after a successful claim.
    #[tokio::test]
    async fn step3b_share_deleted_from_db_after_claim() {
        let (app, state) = build_share_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let f = encrypt_value("secret");
        let id = post_share(&app, &token, "KEY", &f).await;

        assert!(
            share_row_exists(&state.pool, &id).await,
            "row must exist in DB before claim"
        );

        let (status, _) = get_share(&app, &id).await;
        assert_eq!(status, 200, "claim must succeed");

        assert!(
            !share_row_exists(&state.pool, &id).await,
            "row must be deleted from DB after successful claim"
        );
    }

    /// Step 3c: A second GET on the same id returns 404 (already consumed).
    #[tokio::test]
    async fn step3c_second_claim_returns_404() {
        let (app, state) = build_share_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let f = encrypt_value("secret");
        let id = post_share(&app, &token, "KEY", &f).await;

        let (first_status, _) = get_share(&app, &id).await;
        assert_eq!(first_status, 200, "first claim must succeed");

        let (second_status, _) = get_share(&app, &id).await;
        assert_eq!(second_status, 404, "second claim must return 404 — share is consumed");
    }

    /// Step 3d: A claim with a wrong/nonexistent id returns 404 and leaves
    /// the real share completely untouched — both the DB row and the value.
    #[tokio::test]
    async fn step3d_wrong_id_does_not_affect_real_share() {
        let (app, state) = build_share_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let f = encrypt_value("secret");
        let real_id = post_share(&app, &token, "KEY", &f).await;

        // Attempt with a garbage id
        let (bad_status, _) = get_share(&app, "00000000-0000-0000-0000-000000000000").await;
        assert_eq!(bad_status, 404, "wrong id must return 404");

        // Real share row must still exist
        assert!(
            share_row_exists(&state.pool, &real_id).await,
            "real share row must survive a failed claim attempt"
        );

        // And the real share must still be fully claimable and decryptable
        let (good_status, json) = get_share(&app, &real_id).await;
        assert_eq!(good_status, 200, "real share must still be claimable after wrong-id attempt");
        let recovered = decrypt_value(
            &f,
            json["ciphertext"].as_str().unwrap(),
            json["nonce"].as_str().unwrap(),
        );
        assert_eq!(recovered, "secret", "real share must still decrypt correctly");
    }
}
