use crate::{
    config::Config, devices, keys::generate::generate_api_key, kv, middleware, shares,
    state::AppState,
};
use axum::{
    body::Body, extract::connect_info::MockConnectInfo, http::Request,
    middleware as axum_middleware, Router,
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
const RESTRICTED_KEY: &str = "scoped-key";
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
        webauthn_android_origin: None,
        daily_rate_limit: 100,
        auth_failure_threshold: 50,
        auth_block_base_secs: 3600,
        ttl_cleanup_interval_secs: 300,
        trust_proxy_headers: true,
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
        .layer(axum_middleware::from_fn(
            middleware::security_headers::layer,
        ))
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
    sqlx::query_scalar::<_, i64>("SELECT COALESCE(failed_count, 0) FROM blocked_ips WHERE ip = ?")
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

async fn seed_restricted_entry(pool: &SqlitePool) {
    sqlx::query("INSERT INTO kv_entries (key, owner_id, value) VALUES (?, ?, 'secret')")
        .bind(RESTRICTED_KEY)
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
    allowed_keys: &[&str],
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

    for kv_key in allowed_keys {
        sqlx::query(
            "INSERT OR IGNORE INTO api_key_allowed_keys (api_key_id, kv_key) VALUES (?, ?)",
        )
        .bind(&id)
        .bind(kv_key)
        .execute(pool)
        .await
        .unwrap();
    }

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
    ApiKeyNoAccess,
}

async fn resolve_cred(cred: Cred, pool: &SqlitePool) -> (Option<String>, Option<String>) {
    match cred {
        Cred::None => (None, None),
        Cred::BearerUnknown => (Some("kv_notindatabaseatall".to_string()), None),
        Cred::BearerValid => (Some(insert_session_key(pool, "active", None).await), None),
        Cred::BearerExpired => (
            Some(insert_session_key(pool, "active", Some("2020-01-01 00:00:00")).await),
            None,
        ),
        Cred::BearerRevoked => (Some(insert_session_key(pool, "revoked", None).await), None),
        Cred::ApiKeyUnknown => (None, Some("kv_notindatabaseatall".to_string())),
        Cred::ApiKeyValid => (
            None,
            Some(insert_api_key(pool, "active", None, &["protected-key"]).await),
        ),
        Cred::ApiKeyExpired => (
            None,
            Some(insert_api_key(pool, "active", Some("2020-01-01 00:00:00"), &[]).await),
        ),
        Cred::ApiKeyRevoked => (None, Some(insert_api_key(pool, "revoked", None, &[]).await)),
        // token allowed to access "other-key" but not RESTRICTED_KEY ("scoped-key")
        Cred::ApiKeyNoAccess => (
            None,
            Some(insert_api_key(pool, "active", None, &["other-key"]).await),
        ),
    }
}

/// Verifies all 11 scenarios from expected_behaviour_for_tests.md.
///
/// Each case encodes: scenario number, request path, credential kind,
/// whether the rate counter should increment, whether the block counter should increment.
#[rstest]
#[case(1, "/kv/protected-key", Cred::None, true, true)]
#[case(2, "/kv/protected-key", Cred::BearerUnknown, true, false)]
#[case(3, "/kv/protected-key", Cred::BearerValid, false, false)]
#[case(4, "/kv/protected-key", Cred::BearerExpired, false, false)]
#[case(5, "/kv/protected-key", Cred::BearerRevoked, true, true)]
#[case(6, "/kv/protected-key", Cred::ApiKeyUnknown, true, true)]
#[case(7, "/kv/protected-key", Cred::ApiKeyValid, false, false)]
#[case(8, "/kv/protected-key", Cred::ApiKeyExpired, true, true)]
#[case(9, "/kv/protected-key", Cred::ApiKeyRevoked, true, true)]
#[case(10, "/kv/scoped-key", Cred::ApiKeyNoAccess, false, false)]
#[case(11, "/kv/open-key", Cred::None, false, false)]
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
    seed_restricted_entry(pool).await;

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
        if expect_rate_inc {
            "increment"
        } else {
            "no change"
        }
    );
    assert_eq!(
        block > 0,
        expect_block_inc,
        "scenario {scenario}: block counter expected {}, got {block}",
        if expect_block_inc {
            "increment"
        } else {
            "no change"
        }
    );
}

/// Verifies that each endpoint enforces authentication correctly.
///
/// Unauthenticated requests return 401 JSON.
/// Authenticated requests reach the handler and return the expected status.
#[rstest]
// ── unauthenticated → 401 ───────────────────────────────────────────────────
#[case(
    "POST",
    "/api/devices/register/begin",
    Some(r#"{"name":"t","public_key":"dGVzdA=="}"#),
    false,
    401
)]
#[case("GET", "/api/admin/devices", None, false, 401)]
#[case("DELETE", "/api/admin/devices/nonexistent", None, false, 401)]
// ── authenticated → handler response ────────────────────────────────────────
// Enrolment is WebAuthn-gated: an authenticated admin with no registered hardware key
// is forbidden from enrolling a device (403), rather than the old one-shot 201.
#[case(
    "POST",
    "/api/devices/register/begin",
    Some(r#"{"name":"t","public_key":"dGVzdA=="}"#),
    true,
    403
)]
#[case("GET", "/api/admin/devices", None, true, 200)]
#[case("DELETE", "/api/admin/devices/nonexistent", None, true, 404)]
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
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
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
        let n = URL_SAFE_NO_PAD.decode(nonce_b64).unwrap();
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
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM one_time_shares WHERE id = ?")
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
        assert_eq!(
            resp.status().as_u16(),
            401,
            "unauthenticated create must return 401"
        );
    }

    /// Step 2: DB must store the encrypted blob, not the raw plaintext.
    #[tokio::test]
    async fn step2_db_stores_ciphertext_not_plaintext() {
        let (app, state) = build_share_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let plaintext = "super-secret-value-that-must-not-appear-in-db";
        let f = encrypt_value(plaintext);
        let id = post_share(&app, &token, "MY_KEY", &f).await;

        let stored_ciphertext =
            sqlx::query_scalar::<_, String>("SELECT ciphertext FROM one_time_shares WHERE id = ?")
                .bind(&id)
                .fetch_one(&state.pool)
                .await
                .unwrap();

        let stored_nonce =
            sqlx::query_scalar::<_, String>("SELECT nonce FROM one_time_shares WHERE id = ?")
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
        assert_eq!(
            recovered, plaintext,
            "decrypted value must match original plaintext"
        );
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
        assert_eq!(
            second_status, 404,
            "second claim must return 404 — share is consumed"
        );
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
        assert_eq!(
            good_status, 200,
            "real share must still be claimable after wrong-id attempt"
        );
        let recovered = decrypt_value(
            &f,
            json["ciphertext"].as_str().unwrap(),
            json["nonce"].as_str().unwrap(),
        );
        assert_eq!(
            recovered, "secret",
            "real share must still decrypt correctly"
        );
    }
}

// ── API key type tests ───────────────────────────────────────────────────────

const PROTECTED_KEY: &str = "protected-key";

async fn insert_typed_api_key(
    pool: &SqlitePool,
    key_type: &str,
    status: &str,
    expires_at: Option<&str>,
    allowed_keys: &[&str],
) -> String {
    let (plaintext, hash) = generate_api_key();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id, expires_at)
         VALUES (?, ?, 'test-key', ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&hash)
    .bind(key_type)
    .bind(status)
    .bind(TEST_OWNER)
    .bind(expires_at)
    .execute(pool)
    .await
    .unwrap();

    for kv_key in allowed_keys {
        sqlx::query(
            "INSERT OR IGNORE INTO api_key_allowed_keys (api_key_id, kv_key) VALUES (?, ?)",
        )
        .bind(&id)
        .bind(kv_key)
        .execute(pool)
        .await
        .unwrap();
    }

    plaintext
}

async fn seed_protected_entry(pool: &SqlitePool) {
    sqlx::query("INSERT OR IGNORE INTO kv_entries (key, owner_id, value) VALUES (?, ?, 'secret')")
        .bind(PROTECTED_KEY)
        .bind(TEST_OWNER)
        .execute(pool)
        .await
        .unwrap();
}

/// Verifies HTTP status for each API key type and status combination.
#[rstest]
#[case("approval_required", "pending_approval", 403)]
#[case("zero_trust", "pending_approval", 401)]
#[case("one_time", "active", 200)]
#[case("shareable", "active", 200)]
#[tokio::test]
async fn key_type_behaviour(
    #[case] key_type: &'static str,
    #[case] status: &'static str,
    #[case] expected_status: u16,
) {
    let (app, state) = build_test_app().await;
    let pool = &state.pool;
    seed_protected_entry(pool).await;

    let raw_key = insert_typed_api_key(pool, key_type, status, None, &[PROTECTED_KEY]).await;

    let req = get_req(&format!("/kv/{}", PROTECTED_KEY), None, Some(raw_key));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        expected_status,
        "key_type={key_type} status={status}"
    );
}

/// A one-time key is consumed on first use and rejected on the second.
#[tokio::test]
async fn one_time_key_consumed_on_first_use() {
    let (app, state) = build_test_app().await;
    let pool = &state.pool;
    seed_protected_entry(pool).await;

    let raw_key = insert_typed_api_key(pool, "one_time", "active", None, &[PROTECTED_KEY]).await;

    // First request — should succeed.
    let resp1 = app
        .clone()
        .oneshot(get_req(
            &format!("/kv/{}", PROTECTED_KEY),
            None,
            Some(raw_key.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp1.status().as_u16(),
        200,
        "first use of one-time key must succeed"
    );

    // Allow the fire-and-forget consume UPDATE to land.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second request — key is now status='used', must be rejected.
    let resp2 = app
        .oneshot(get_req(
            &format!("/kv/{}", PROTECTED_KEY),
            None,
            Some(raw_key),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp2.status().as_u16(),
        401,
        "second use of one-time key must be rejected"
    );
}

/// An IP that hits the threshold gets a temporary block; a repeat offense after
/// the block is lifted escalates both the counter and the block duration.
#[tokio::test]
async fn escalating_temp_blocks() {
    let (_app, state) = build_test_app().await;
    let pool = &state.pool;
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let ip_str = "203.0.113.9";
    let threshold = 3u32;
    let base = 3600u64;

    for _ in 0..threshold {
        middleware::ip_block::record_auth_failure(pool, ip, threshold, base, "test").await;
    }

    let row = sqlx::query!(
        r#"SELECT blocked_at, unblock_at, block_count as "block_count: i64"
           FROM blocked_ips WHERE ip = ?"#,
        ip_str
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(row.blocked_at.is_some(), "should be blocked at threshold");
    assert!(row.unblock_at.is_some(), "temp block must set unblock_at");
    assert_eq!(row.block_count, 1);

    // Mimic ttl_cleanup lifting an expired temp block (block_count retained).
    sqlx::query!(
        "UPDATE blocked_ips SET blocked_at = NULL, failed_count = 0 WHERE ip = ?",
        ip_str
    )
    .execute(pool)
    .await
    .unwrap();

    // Second offense: block_count -> 2, window doubled to ~2h (> 90m from now).
    for _ in 0..threshold {
        middleware::ip_block::record_auth_failure(pool, ip, threshold, base, "test").await;
    }

    let row2 = sqlx::query!(
        r#"SELECT block_count as "block_count: i64",
                  (unblock_at > datetime('now', '+90 minutes')) as "over_90m: i64"
           FROM blocked_ips WHERE ip = ?"#,
        ip_str
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row2.block_count, 2, "repeat offense increments block_count");
    assert_eq!(
        row2.over_90m, 1,
        "second block should exceed 90m (doubled from 1h base)"
    );
}

/// `check_kv_access` unit tests — no DB or HTTP involved.
#[cfg(test)]
mod check_kv_access_tests {
    use super::*;
    use crate::middleware::api_key::check_kv_access;

    #[test]
    fn none_allows_any_key() {
        assert!(check_kv_access(&None, "anything").is_ok());
    }

    #[test]
    fn matching_key_is_allowed() {
        let keys = Some(vec!["foo".to_string()]);
        assert!(check_kv_access(&keys, "foo").is_ok());
    }

    #[test]
    fn non_matching_key_is_forbidden() {
        let keys = Some(vec!["foo".to_string()]);
        assert!(check_kv_access(&keys, "bar").is_err());
    }

    #[test]
    fn empty_allowlist_forbids_everything() {
        let keys: Option<Vec<String>> = Some(vec![]);
        assert!(check_kv_access(&keys, "anything").is_err());
    }
}

// ── Device-bound session request tests ─────────────────────────────────────────
//
// The approval flow must deliver the session token ECDH-wrapped to a registered device,
// never in plaintext, and device enrolment must be gated behind a WebAuthn assertion.
mod session_request_tests {
    use super::*;
    use crate::keys::generate::hash_key;
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Key, Nonce,
    };
    use axum::body::to_bytes;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hkdf::Hkdf;
    use rand_core::OsRng;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    async fn build_session_app() -> (Router, Arc<AppState>) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let state = AppState::new(pool, test_config(), None);
        let app = Router::new()
            .nest("/session-request", crate::session_request::public_router())
            .nest(
                "/api/admin/session-requests",
                crate::session_request::admin_router(),
            )
            .nest("/api/devices", devices::router())
            .with_state(Arc::clone(&state));
        (app, state)
    }

    /// Insert a device row directly with a fresh X25519 keypair, returning its id and the
    /// private key (enrolment itself needs a real authenticator, tested separately).
    async fn insert_x25519_device(pool: &SqlitePool, owner: &str) -> (String, StaticSecret) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let pub_b64 = STANDARD.encode(public.as_bytes());
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices (id, owner_id, name, public_key, key_type)
             VALUES (?, ?, 'test-device', ?, 'x25519')",
        )
        .bind(&id)
        .bind(owner)
        .bind(&pub_b64)
        .execute(pool)
        .await
        .unwrap();
        (id, secret)
    }

    /// Client-side unwrap of the poll envelope, mirroring `decrypt_device_kv`.
    fn decrypt_envelope(secret: &StaticSecret, env: &serde_json::Value) -> Vec<u8> {
        let r = &env["recipient"];
        let eph: [u8; 32] = STANDARD
            .decode(r["ephemeral_pub"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let shared = secret.diffie_hellman(&PublicKey::from(eph));
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared.as_bytes());
        let mut wrap_key = [0u8; 32];
        hk.expand(b"kv-device-wrap", &mut wrap_key).unwrap();
        let dek = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key))
            .decrypt(
                Nonce::from_slice(&STANDARD.decode(r["dek_nonce"].as_str().unwrap()).unwrap()),
                STANDARD
                    .decode(r["encrypted_dek"].as_str().unwrap())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek))
            .decrypt(
                Nonce::from_slice(&STANDARD.decode(env["nonce"].as_str().unwrap()).unwrap()),
                Payload {
                    msg: &STANDARD
                        .decode(env["ciphertext"].as_str().unwrap())
                        .unwrap(),
                    aad: &STANDARD.decode(env["aad"].as_str().unwrap()).unwrap(),
                },
            )
            .unwrap()
    }

    async fn create_req(app: &Router, device_id: &str) -> (u16, serde_json::Value) {
        let body = serde_json::json!({
            "label": "hermes-agent",
            "requested_duration_hours": 24,
            "device_id": device_id,
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/session-request")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn approve(app: &Router, token: &str, id: &str, approval_token: &str) -> u16 {
        let body = serde_json::json!({ "approval_token": approval_token });
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/admin/session-requests/{id}/approve"))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn poll(app: &Router, id: &str, secret: &str) -> (u16, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/session-request/{id}/status?secret={secret}"))
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

    /// End-to-end: approve wraps the token to the device; poll delivers an envelope that
    /// decrypts to the *real* session token (its hash matches the minted api_key), and the
    /// DB never holds a usable plaintext token.
    #[tokio::test]
    async fn approved_token_is_device_wrapped_and_decrypts() {
        let (app, state) = build_session_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (device_id, device_secret) = insert_x25519_device(&state.pool, TEST_OWNER).await;

        let (status, created) = create_req(&app, &device_id).await;
        assert_eq!(status, 201, "create must return 201");
        let id = created["id"].as_str().unwrap().to_string();
        let poll_secret = created["poll_secret"].as_str().unwrap().to_string();
        // The create response must NOT leak the approval token in the clear.
        assert!(
            created.get("confirm_code").is_none() && created.get("approval_token").is_none(),
            "create must not return a plaintext approval token"
        );

        // Before approval: pending, no session envelope, but the wrapped approval token is
        // present. Decrypt it with the device key to recover the token the human relays.
        let (s, pending) = poll(&app, &id, &poll_secret).await;
        assert_eq!(s, 200);
        assert_eq!(pending["status"].as_str().unwrap(), "pending");
        assert!(pending["envelope"].is_null());
        assert!(
            !pending["approval_envelope"].is_null(),
            "pending poll must carry the wrapped approval token"
        );
        let approval_token = String::from_utf8(decrypt_envelope(
            &device_secret,
            &pending["approval_envelope"],
        ))
        .unwrap();

        // Idempotent: re-polling while pending re-serves the same approval envelope (not
        // consumed), so a device can re-display the token.
        let (s2, pending2) = poll(&app, &id, &poll_secret).await;
        assert_eq!(s2, 200);
        assert_eq!(pending2["status"].as_str().unwrap(), "pending");
        assert_eq!(
            String::from_utf8(decrypt_envelope(
                &device_secret,
                &pending2["approval_envelope"]
            ))
            .unwrap(),
            approval_token,
            "approval token must be re-fetchable while pending"
        );

        assert_eq!(approve(&app, &admin, &id, &approval_token).await, 204);

        // DB must hold the wrap, never a plaintext token.
        let plaintext: Option<String> =
            sqlx::query_scalar("SELECT plaintext_token FROM session_requests WHERE id = ?")
                .bind(&id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert!(plaintext.is_none(), "plaintext_token must never be written");
        let wrap_ct: Option<String> =
            sqlx::query_scalar("SELECT wrap_ciphertext FROM session_requests WHERE id = ?")
                .bind(&id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert!(wrap_ct.is_some(), "wrap_ciphertext must be populated");

        // Poll delivers the envelope; it decrypts to the real token.
        let (s, approved) = poll(&app, &id, &poll_secret).await;
        assert_eq!(s, 200);
        assert_eq!(approved["status"].as_str().unwrap(), "approved");
        let token =
            String::from_utf8(decrypt_envelope(&device_secret, &approved["envelope"])).unwrap();

        let minted_hash: String = sqlx::query_scalar(
            "SELECT key_hash FROM api_keys WHERE id =
             (SELECT session_key_id FROM session_requests WHERE id = ?)",
        )
        .bind(&id)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(
            hash_key(&token),
            minted_hash,
            "decrypted token must be the minted session key"
        );

        // Second poll: consumed, envelope cleared.
        let (s, delivered) = poll(&app, &id, &poll_secret).await;
        assert_eq!(s, 200);
        assert_eq!(delivered["status"].as_str().unwrap(), "delivered");
        assert!(delivered["envelope"].is_null());
        let wrap_ct_after: Option<String> =
            sqlx::query_scalar("SELECT wrap_ciphertext FROM session_requests WHERE id = ?")
                .bind(&id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert!(
            wrap_ct_after.is_none(),
            "envelope must be cleared on delivery"
        );
    }

    /// A create referencing a non-existent device is rejected (nothing to wrap to).
    #[tokio::test]
    async fn create_with_unknown_device_is_rejected() {
        let (app, _state) = build_session_app().await;
        let (status, _) = create_req(&app, "no-such-device").await;
        assert_eq!(status, 404, "unknown device_id must be rejected");
    }

    /// Approval requires the one-time approval token; a wrong one is forbidden and mints
    /// nothing — the row stays pending.
    #[tokio::test]
    async fn approve_with_wrong_approval_token_is_forbidden() {
        let (app, state) = build_session_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (device_id, _) = insert_x25519_device(&state.pool, TEST_OWNER).await;
        let (_, created) = create_req(&app, &device_id).await;
        let id = created["id"].as_str().unwrap().to_string();

        assert_eq!(
            approve(&app, &admin, &id, "kv_not-the-real-token").await,
            403
        );
        let status: String = sqlx::query_scalar("SELECT status FROM session_requests WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(
            status, "pending",
            "a failed approval token must not approve the row"
        );
    }

    /// Enrolment gate: with no registered hardware key, begin is forbidden — a stolen OIDC
    /// session alone cannot add a device.
    #[tokio::test]
    async fn device_enrolment_requires_a_passkey() {
        let (app, state) = build_session_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let body = serde_json::json!({
            "name": "laptop", "public_key": "AAAA", "key_type": "x25519",
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/devices/register/begin")
                    .header("Authorization", format!("Bearer {admin}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            403,
            "enrolment without a hardware key must be forbidden"
        );
    }
}
