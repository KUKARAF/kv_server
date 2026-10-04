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
        device_ban_base_secs: 3600,
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

    /// Requests a challenge for `device_id`, decrypts it with `device_secret` (proving
    /// possession, exactly as a real client must), and only then calls `create_request` —
    /// mirrors the real two-step flow end to end. Returns `create_request`'s response,
    /// except when the challenge step itself fails (e.g. unknown device), in which case
    /// that failure is returned instead — same shape callers already expect.
    async fn create_req(
        app: &Router,
        device_id: &str,
        device_secret: &StaticSecret,
    ) -> (u16, serde_json::Value) {
        let challenge_body = serde_json::json!({ "device_id": device_id });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/session-request/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(challenge_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let challenge: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        if status != 201 {
            return (status, challenge);
        }

        let challenge_id = challenge["challenge_id"].as_str().unwrap().to_string();
        let nonce =
            String::from_utf8(decrypt_envelope(device_secret, &challenge["envelope"])).unwrap();

        let body = serde_json::json!({
            "label": "hermes-agent",
            "requested_duration_hours": 24,
            "challenge_id": challenge_id,
            "nonce": nonce,
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

    async fn approve(app: &Router, admin_token: &str, id: &str, approve_token: &str) -> u16 {
        let body = serde_json::json!({ "token": approve_token });
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/admin/session-requests/{id}/approve"))
                    .header("Authorization", format!("Bearer {admin_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn reject(app: &Router, token: &str, id: &str) -> u16 {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/admin/session-requests/{id}/reject"))
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
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

        let (status, created) = create_req(&app, &device_id, &device_secret).await;
        assert_eq!(status, 201, "create must return 201");
        let id = created["id"].as_str().unwrap().to_string();
        let poll_secret = created["poll_secret"].as_str().unwrap().to_string();
        let approve_token = created["approve_token"].as_str().unwrap().to_string();
        // The create response must NOT leak any (legacy-named) approval secret in the clear.
        assert!(
            created.get("confirm_code").is_none() && created.get("approval_token").is_none(),
            "create must not return a plaintext legacy approval token"
        );

        // Before approval: pending, no session envelope.
        let (s, pending) = poll(&app, &id, &poll_secret).await;
        assert_eq!(s, 200);
        assert_eq!(pending["status"].as_str().unwrap(), "pending");
        assert!(pending["envelope"].is_null());

        assert_eq!(approve(&app, &admin, &id, &approve_token).await, 204);

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

    /// Approve requires the exact `approve_token` returned to the requester at creation —
    /// a valid admin session plus the request id (everything a bare dashboard notification
    /// exposes) must never be sufficient, whether the token is missing or simply wrong.
    #[tokio::test]
    async fn approve_rejects_missing_or_wrong_token() {
        let (app, state) = build_session_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (device_id, device_secret) = insert_x25519_device(&state.pool, TEST_OWNER).await;
        let (_, created) = create_req(&app, &device_id, &device_secret).await;
        let id = created["id"].as_str().unwrap().to_string();

        assert_eq!(
            approve(&app, &admin, &id, "not-the-real-token").await,
            404,
            "a wrong token must not approve"
        );
        assert_eq!(
            approve(&app, &admin, &id, "").await,
            404,
            "an empty token must not approve"
        );

        let status: String = sqlx::query_scalar("SELECT status FROM session_requests WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(
            status, "pending",
            "a failed token check must not change the row"
        );

        let approve_token = created["approve_token"].as_str().unwrap().to_string();
        assert_eq!(
            approve(&app, &admin, &id, &approve_token).await,
            204,
            "the real token must still approve"
        );
    }

    /// A create referencing a non-existent device is rejected (nothing to wrap to).
    #[tokio::test]
    async fn create_with_unknown_device_is_rejected() {
        let (app, _state) = build_session_app().await;
        let dummy_secret = StaticSecret::random_from_rng(OsRng);
        let (status, _) = create_req(&app, "no-such-device", &dummy_secret).await;
        assert_eq!(status, 404, "unknown device_id must be rejected");
    }

    /// A challenge is single-use: submitting the same decrypted nonce twice only ever
    /// creates one pending request.
    #[tokio::test]
    async fn challenge_cannot_be_replayed() {
        let (app, state) = build_session_app().await;
        let (device_id, device_secret) = insert_x25519_device(&state.pool, TEST_OWNER).await;

        let challenge_body = serde_json::json!({ "device_id": device_id });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/session-request/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(challenge_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let challenge: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let challenge_id = challenge["challenge_id"].as_str().unwrap().to_string();
        let nonce =
            String::from_utf8(decrypt_envelope(&device_secret, &challenge["envelope"])).unwrap();

        let make_request = || {
            serde_json::json!({
                "challenge_id": challenge_id,
                "nonce": nonce,
            })
        };

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/session-request")
                    .header("content-type", "application/json")
                    .body(Body::from(make_request().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            first.status().as_u16(),
            201,
            "first submission must succeed"
        );

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/session-request")
                    .header("content-type", "application/json")
                    .body(Body::from(make_request().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            second.status().as_u16(),
            404,
            "a consumed challenge must not create a second request"
        );
    }

    /// A wrong nonce (right challenge id, wrong plaintext) is rejected identically to an
    /// unknown challenge — no distinguishing signal for an attacker guessing.
    #[tokio::test]
    async fn create_request_rejects_wrong_nonce() {
        let (app, state) = build_session_app().await;
        let (device_id, _) = insert_x25519_device(&state.pool, TEST_OWNER).await;

        let challenge_body = serde_json::json!({ "device_id": device_id });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/session-request/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(challenge_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let challenge: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let challenge_id = challenge["challenge_id"].as_str().unwrap().to_string();

        let body =
            serde_json::json!({ "challenge_id": challenge_id, "nonce": "kv_not-the-real-nonce" });
        let resp = app
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
        assert_eq!(resp.status().as_u16(), 404, "wrong nonce must be rejected");
    }

    /// The old create_request contract (bare device_id, no challenge) no longer parses.
    #[tokio::test]
    async fn create_request_rejects_old_device_id_body() {
        let (app, state) = build_session_app().await;
        let (device_id, _) = insert_x25519_device(&state.pool, TEST_OWNER).await;

        let body = serde_json::json!({
            "label": "hermes-agent",
            "requested_duration_hours": 24,
            "device_id": device_id,
        });
        let resp = app
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
        assert!(
            !resp.status().is_success(),
            "the old device_id-only body must be rejected now that challenge_id/nonce are required"
        );
    }

    /// Approval requires the admin to own the request's device; an admin approving/rejecting
    /// someone else's device is forbidden and the row stays pending — this is the actual
    /// binding replacing the old human-relayed approval token: the admin's decision is
    /// grounded in the device's real, owner-scoped identity, not a self-reported label.
    #[tokio::test]
    async fn approve_and_reject_by_non_owner_are_forbidden() {
        let (app, state) = build_session_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (device_id, device_secret) = insert_x25519_device(&state.pool, "someone-else").await;
        let (_, created) = create_req(&app, &device_id, &device_secret).await;
        let id = created["id"].as_str().unwrap().to_string();
        let approve_token = created["approve_token"].as_str().unwrap().to_string();

        assert_eq!(approve(&app, &admin, &id, &approve_token).await, 403);
        assert_eq!(reject(&app, &admin, &id).await, 403);
        let status: String = sqlx::query_scalar("SELECT status FROM session_requests WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(
            status, "pending",
            "a non-owner's approve/reject must not change the row"
        );
    }

    /// `list_pending`/`get_request` surface the device's real, immutable name (not the
    /// attacker-controlled `label`) and flag whether the caller owns that device.
    #[tokio::test]
    async fn pending_requests_expose_device_name_and_ownership() {
        let (app, state) = build_session_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (own_device, own_secret) = insert_x25519_device(&state.pool, TEST_OWNER).await;
        let (foreign_device, foreign_secret) =
            insert_x25519_device(&state.pool, "someone-else").await;

        let (_, own_created) = create_req(&app, &own_device, &own_secret).await;
        let own_id = own_created["id"].as_str().unwrap().to_string();
        create_req(&app, &foreign_device, &foreign_secret).await;

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/admin/session-requests")
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rows = list.as_array().unwrap();
        assert_eq!(
            rows.len(),
            1,
            "list_pending must only show the admin's own devices' requests"
        );
        assert_eq!(rows[0]["id"].as_str().unwrap(), own_id);
        assert_eq!(rows[0]["device_name"].as_str().unwrap(), "test-device");
        assert!(rows[0]["is_own_device"].as_bool().unwrap());

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/admin/session-requests/{own_id}"))
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let detail: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(detail["device_name"].as_str().unwrap(), "test-device");
        assert!(detail["is_own_device"].as_bool().unwrap());
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

mod device_proposal_tests {
    use super::*;
    use axum::body::to_bytes;

    async fn build_proposal_app() -> (Router, Arc<AppState>) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let state = AppState::new(pool, test_config(), None);
        let app = Router::new()
            .nest("/api/devices", devices::router())
            .nest(
                "/api/admin/device-proposals",
                devices::proposal_admin_router(),
            )
            .with_state(Arc::clone(&state));
        (app, state)
    }

    async fn propose(app: &Router, name: &str) -> (u16, serde_json::Value) {
        let body = serde_json::json!({ "name": name, "public_key": "AAAA", "key_type": "x25519" });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/devices/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// End-to-end: propose (unauthenticated) → admin lists it → link (simulating a
    /// register_finish that already happened) → the proposer polls and receives the
    /// assigned device_id automatically — no manual key/id handling anywhere in the loop.
    #[tokio::test]
    async fn propose_list_link_and_poll_round_trip() {
        let (app, state) = build_proposal_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;

        let (status, created) = propose(&app, "bigboy").await;
        assert_eq!(status, 201);
        let id = created["id"].as_str().unwrap().to_string();
        let poll_secret = created["poll_secret"].as_str().unwrap().to_string();
        let confirm_token = created["confirm_token"].as_str().unwrap().to_string();

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/admin/device-proposals")
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["name"].as_str().unwrap(), "bigboy");

        // Simulate the WebAuthn ceremony (register_begin/finish) having already created a
        // real device row — that ceremony itself is covered by session_request_tests's
        // device_enrolment_requires_a_passkey and devices' own tests, not re-exercised here.
        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices (id, owner_id, name, public_key, key_type)
             VALUES (?, ?, 'bigboy', 'AAAA', 'x25519')",
        )
        .bind(&device_id)
        .bind(TEST_OWNER)
        .execute(&state.pool)
        .await
        .unwrap();

        // Loading the proposal (which feeds the WebAuthn ceremony's inputs) requires the
        // proposer's own confirm_token — a bare id, as a dashboard toast alone provides, must
        // not be sufficient.
        let get_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/api/admin/device-proposals/{id}?token={confirm_token}"
                    ))
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status().as_u16(), 200);

        let link_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/admin/device-proposals/{id}/link"))
                    .header("Authorization", format!("Bearer {admin}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "device_id": device_id, "token": confirm_token })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(link_resp.status().as_u16(), 204);

        let poll_resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/api/devices/propose/{id}/status?secret={poll_secret}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(poll_resp.status().as_u16(), 200);
        let bytes = to_bytes(poll_resp.into_body(), usize::MAX).await.unwrap();
        let status_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status_json["status"].as_str().unwrap(), "confirmed");
        assert_eq!(status_json["device_id"].as_str().unwrap(), device_id);
    }

    /// A bare id (everything a dashboard toast exposes) must not be enough to load a
    /// proposal's public key/name, nor to link it — both require the proposer's own
    /// confirm_token, whether missing or simply wrong.
    #[tokio::test]
    async fn get_proposal_rejects_missing_or_wrong_token() {
        let (app, state) = build_proposal_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (_, created) = propose(&app, "bigboy").await;
        let id = created["id"].as_str().unwrap().to_string();

        // Missing token: axum rejects the Query extractor before the handler runs.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/admin/device-proposals/{id}"))
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            !resp.status().is_success(),
            "a missing token must not load the proposal"
        );

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/admin/device-proposals/{id}?token=wrong"))
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "a wrong token must not load the proposal"
        );

        let link_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/admin/device-proposals/{id}/link"))
                    .header("Authorization", format!("Bearer {admin}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "device_id": "attacker-controlled", "token": "wrong" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            link_resp.status().as_u16(),
            404,
            "a wrong token must not link either"
        );

        let status: String = sqlx::query_scalar("SELECT status FROM device_proposals WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(
            status, "pending",
            "a failed token check must not change the row"
        );
    }

    /// Listing is deliberately owner-agnostic: no device row (and therefore no owner) exists
    /// yet at proposal time, so two different admins both see the same pending proposal —
    /// intentional for this single/small-user deployment, not a bug.
    #[tokio::test]
    async fn listing_is_owner_agnostic() {
        let (app, state) = build_proposal_app().await;
        let admin_a = insert_session_key(&state.pool, "active", None).await;
        let admin_b = {
            let (plaintext, hash) = generate_api_key();
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id)
                 VALUES (?, ?, 'k', 'session', 'active', 'someone-else')",
            )
            .bind(&id)
            .bind(&hash)
            .execute(&state.pool)
            .await
            .unwrap();
            plaintext
        };

        propose(&app, "shared-toast").await;

        for token in [&admin_a, &admin_b] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/admin/device-proposals")
                        .header("Authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 200);
            let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                list.as_array().unwrap().len(),
                1,
                "every admin must see the pending proposal"
            );
        }
    }

    #[tokio::test]
    async fn reject_removes_proposal_from_listing() {
        let (app, state) = build_proposal_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (_, created) = propose(&app, "throwaway").await;
        let id = created["id"].as_str().unwrap().to_string();

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/admin/device-proposals/{id}/reject"))
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 204);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/admin/device-proposals")
                    .header("Authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 0);
    }
}

mod whoami_tests {
    use super::*;
    use axum::body::to_bytes;

    async fn build_whoami_app() -> (Router, Arc<AppState>) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let state = AppState::new(pool, test_config(), None);
        let app = Router::new()
            .nest("/api/admin", crate::admin::router())
            .with_state(Arc::clone(&state));
        (app, state)
    }

    async fn whoami(app: &Router, token: &str) -> serde_json::Value {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/admin/session/whoami")
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn non_device_bound_session_returns_null() {
        let (app, state) = build_whoami_app().await;
        let token = insert_session_key(&state.pool, "active", None).await;
        let resp = whoami(&app, &token).await;
        assert!(resp["device_id"].is_null());
        assert!(resp["device_name"].is_null());
    }

    #[tokio::test]
    async fn device_bound_session_returns_its_device_name() {
        let (app, state) = build_whoami_app().await;
        let device_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices (id, owner_id, name, public_key, key_type)
             VALUES (?, ?, 'bigboy', 'AAAA', 'x25519')",
        )
        .bind(&device_id)
        .bind(TEST_OWNER)
        .execute(&state.pool)
        .await
        .unwrap();

        let (plaintext, hash) = generate_api_key();
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id, device_id)
             VALUES (?, ?, 'session', 'session', 'active', ?, ?)",
        )
        .bind(&id)
        .bind(&hash)
        .bind(TEST_OWNER)
        .bind(&device_id)
        .execute(&state.pool)
        .await
        .unwrap();

        let resp = whoami(&app, &plaintext).await;
        assert_eq!(resp["device_id"].as_str().unwrap(), device_id);
        assert_eq!(resp["device_name"].as_str().unwrap(), "bigboy");
    }
}

/// Per-device key policies + temporary device bans (src/device_policy).
// serde_json::Value indexing returns Null for missing keys instead of panicking.
#[allow(clippy::indexing_slicing)]
mod device_policy_tests {
    use super::*;
    use axum::body::to_bytes;

    async fn build_policy_app() -> (Router, Arc<AppState>) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        build_policy_app_with_pool(pool).await
    }

    async fn build_policy_app_with_pool(pool: SqlitePool) -> (Router, Arc<AppState>) {
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let state = AppState::new(pool, test_config(), None);
        let app = Router::new()
            .nest("/kv", kv::router())
            .nest("/api/devices", devices::router())
            .nest("/api/admin/devices", devices::admin_router())
            .nest(
                "/api/admin/device-policies",
                crate::device_policy::admin_router(),
            )
            .nest(
                "/api/admin/management-keys",
                crate::management_keys::admin_router(),
            )
            .nest(
                "/api/admin/device-proposals",
                devices::proposal_admin_router(),
            )
            .nest("/api/admin", crate::admin::router())
            .nest("/session-request", crate::session_request::public_router())
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
            .layer(MockConnectInfo(SocketAddr::new(TEST_IP, 12345)));
        (app, state)
    }

    async fn insert_device(pool: &SqlitePool, name: &str) -> String {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices (id, owner_id, name, public_key, key_type)
             VALUES (?, ?, ?, 'AAAA', 'x25519')",
        )
        .bind(&id)
        .bind(TEST_OWNER)
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    /// Device-bound session token, exactly as session_request approval mints it.
    async fn insert_device_session(pool: &SqlitePool, device_id: &str) -> String {
        let (plaintext, hash) = generate_api_key();
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id, device_id, expires_at)
             VALUES (?, ?, 'session', 'session', 'active', ?, ?, datetime('now', '+1 hour'))",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&hash)
        .bind(TEST_OWNER)
        .bind(device_id)
        .execute(pool)
        .await
        .unwrap();
        plaintext
    }

    async fn seed_kv(pool: &SqlitePool, keys: &[&str]) {
        for k in keys {
            sqlx::query("INSERT INTO kv_entries (key, owner_id, value) VALUES (?, ?, ?)")
                .bind(k)
                .bind(TEST_OWNER)
                .bind(format!("value-of-{k}"))
                .execute(pool)
                .await
                .unwrap();
        }
    }

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (u16, String) {
        let body = body.map(|b| b.to_string());
        let resp = app
            .clone()
            .oneshot(req(method, path, token, body.as_deref()))
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap_or(serde_json::Value::Null)
    }

    async fn put_policy(
        app: &Router,
        admin: &str,
        device_id: &str,
        body: serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let (s, b) = call(
            app,
            "PUT",
            &format!("/api/admin/device-policies/{device_id}"),
            Some(admin),
            Some(body),
        )
        .await;
        (s, json(&b))
    }

    fn assert_banned(status: u16, body: &str) {
        assert_eq!(status, 403, "body: {body}");
        assert_eq!(json(body), serde_json::json!({ "error": "device banned" }));
    }

    async fn ban_row(
        pool: &SqlitePool,
        device_id: &str,
    ) -> Option<(Option<String>, i64, Option<String>)> {
        sqlx::query_as::<_, (Option<String>, i64, Option<String>)>(
            "SELECT banned_at, ban_count, last_key FROM device_bans WHERE device_id = ?",
        )
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    /// Common fixture: app, state, non-device admin token, device id, device token.
    async fn fixture() -> (Router, Arc<AppState>, String, String, String) {
        let (app, state) = build_policy_app().await;
        seed_kv(
            &state.pool,
            &["OPENROUTER_API_KEY", "OTHER_KEY", "FOO", "FOO_BAR"],
        )
        .await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let device_id = insert_device(&state.pool, "hermes").await;
        let device_token = insert_device_session(&state.pool, &device_id).await;
        (app, state, admin, device_id, device_token)
    }

    #[tokio::test]
    async fn no_policy_device_reads_any_key() {
        let (app, state, _admin, device_id, dt) = fixture().await;
        for k in ["OPENROUTER_API_KEY", "OTHER_KEY", "FOO_BAR"] {
            let (s, b) = call(&app, "GET", &format!("/kv/{k}"), Some(&dt), None).await;
            assert_eq!(s, 200);
            assert_eq!(b, format!("value-of-{k}"));
        }
        let (s, _) = call(
            &app,
            "GET",
            "/api/admin/kv/OTHER_KEY/value",
            Some(&dt),
            None,
        )
        .await;
        assert_eq!(s, 200);
        assert!(ban_row(&state.pool, &device_id).await.is_none());
    }

    #[tokio::test]
    async fn allow_list_violation_bans_device_everywhere() {
        let (app, state, admin, device_id, dt) = fixture().await;
        let (s, row) = put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["OPENROUTER_API_KEY"] }),
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(row["mode"], "allow_list");
        assert_eq!(row["keys"], serde_json::json!(["OPENROUTER_API_KEY"]));
        assert!(row["ban"].is_null());

        let (s, b) = call(&app, "GET", "/kv/OPENROUTER_API_KEY", Some(&dt), None).await;
        assert_eq!((s, b.as_str()), (200, "value-of-OPENROUTER_API_KEY"));

        // Violation: name only in the response, no value, no policy contents.
        let (s, b) = call(&app, "GET", "/kv/OTHER_KEY", Some(&dt), None).await;
        assert_banned(s, &b);
        assert!(!b.contains("value-of") && !b.contains("OPENROUTER"));
        let (banned_at, count, last_key) = ban_row(&state.pool, &device_id).await.unwrap();
        assert!(banned_at.is_some());
        assert_eq!(count, 1);
        assert_eq!(last_key.as_deref(), Some("OTHER_KEY"));

        // Banned: even the allowed key, any AdminAuth endpoint, and session minting.
        let (s, b) = call(&app, "GET", "/kv/OPENROUTER_API_KEY", Some(&dt), None).await;
        assert_banned(s, &b);
        let (s, b) = call(&app, "GET", "/kv", Some(&dt), None).await;
        assert_banned(s, &b);
        let (s, b) = call(&app, "GET", "/api/admin/session/whoami", Some(&dt), None).await;
        assert_banned(s, &b);
        // (Session-request minting while banned: see session_request_flow_refused_while_banned.)

        // Owner sees the ban in the listing and the active-bans endpoint.
        let (s, b) = call(
            &app,
            "GET",
            "/api/admin/device-policies",
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 200);
        let list = json(&b);
        assert_eq!(list[0]["ban"]["active"], true);
        assert_eq!(list[0]["ban"]["ban_count"], 1);
        assert_eq!(list[0]["ban"]["last_key"], "OTHER_KEY");
        let (s, b) = call(
            &app,
            "GET",
            "/api/admin/device-policies/bans",
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 200);
        let bans = json(&b);
        assert_eq!(bans.as_array().unwrap().len(), 1);
        assert_eq!(bans[0]["device_id"], device_id.as_str());
        assert_eq!(bans[0]["device_name"], "hermes");
        assert_eq!(bans[0]["active"], true);
    }

    #[tokio::test]
    async fn deny_list_happy_and_violation() {
        let (app, state, admin, device_id, dt) = fixture().await;
        let (s, _) = put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "deny_list", "keys": ["OTHER_KEY"] }),
        )
        .await;
        assert_eq!(s, 200);
        let (s, _) = call(&app, "GET", "/kv/OPENROUTER_API_KEY", Some(&dt), None).await;
        assert_eq!(s, 200);
        // Percent-encoded name is decoded before the policy check (no bypass).
        let (s, b) = call(&app, "GET", "/kv/OTHER%5FKEY", Some(&dt), None).await;
        assert_banned(s, &b);
        assert_eq!(ban_row(&state.pool, &device_id).await.unwrap().1, 1);
    }

    #[tokio::test]
    async fn regex_happy_and_violation_is_anchored() {
        let (app, state, admin, device_id, dt) = fixture().await;
        let (s, row) = put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "regex", "pattern": "FOO", "keys": ["ignored"] }),
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(row["pattern"], "FOO");
        assert_eq!(row["keys"], serde_json::json!([]));
        let (s, _) = call(&app, "GET", "/kv/FOO", Some(&dt), None).await;
        assert_eq!(s, 200);
        let (s, b) = call(&app, "GET", "/kv/FOO_BAR", Some(&dt), None).await;
        assert_banned(s, &b);
        assert_eq!(
            ban_row(&state.pool, &device_id).await.unwrap().2.as_deref(),
            Some("FOO_BAR")
        );
    }

    #[tokio::test]
    async fn admin_value_and_device_kv_reads_are_enforced() {
        let (app, state, admin, device_id, dt) = fixture().await;
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        let (s, b) = call(&app, "GET", "/api/admin/kv/FOO/value", Some(&dt), None).await;
        assert_eq!((s, b.as_str()), (200, "value-of-FOO"));
        let (s, b) = call(
            &app,
            "GET",
            "/api/admin/kv/OTHER_KEY/value",
            Some(&dt),
            None,
        )
        .await;
        assert_banned(s, &b);
        assert_eq!(ban_row(&state.pool, &device_id).await.unwrap().1, 1);

        // Device-encrypted fetch (separate device so it isn't already banned).
        let d2 = insert_device(&state.pool, "laptop").await;
        let t2 = insert_device_session(&state.pool, &d2).await;
        put_policy(
            &app,
            &admin,
            &d2,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        let (s, b) = call(
            &app,
            "GET",
            &format!("/api/devices/{d2}/kv/OTHER_KEY"),
            Some(&t2),
            None,
        )
        .await;
        assert_banned(s, &b);
        assert_eq!(ban_row(&state.pool, &d2).await.unwrap().1, 1);

        // Non-device caller asking for a disallowed key's envelope for d3: refused, no ban.
        let d3 = insert_device(&state.pool, "cli-box").await;
        put_policy(
            &app,
            &admin,
            &d3,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        let (s, b) = call(
            &app,
            "GET",
            &format!("/api/admin/devices/{d3}/kv/OTHER_KEY"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 403);
        assert_ne!(json(&b)["error"], "device banned");
        assert!(ban_row(&state.pool, &d3).await.is_none());
    }

    #[tokio::test]
    async fn violation_moves_neither_ip_counter() {
        let (app, state, admin, device_id, dt) = fixture().await;
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        for _ in 0..3 {
            let (s, _) = call(&app, "GET", "/kv/OTHER_KEY", Some(&dt), None).await;
            assert_eq!(s, 403);
            let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(&dt), None).await;
            assert_eq!(s, 403);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(rate_count(&state), 0, "rate counter must not move");
        assert_eq!(
            block_count(&state.pool).await,
            0,
            "block counter must not move"
        );
        // Banned once, not escalated by repeated requests while banned.
        assert_eq!(ban_row(&state.pool, &device_id).await.unwrap().1, 1);
    }

    #[tokio::test]
    async fn non_device_requests_unaffected_by_device_policy() {
        let (app, state, admin, device_id, _dt) = fixture().await;
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        let (s, _) = call(&app, "GET", "/kv/OTHER_KEY", Some(&admin), None).await;
        assert_eq!(s, 200);
        let (s, _) = call(
            &app,
            "GET",
            "/api/admin/kv/OTHER_KEY/value",
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 200);
        let api_key = insert_api_key(&state.pool, "active", None, &["OTHER_KEY"]).await;
        let resp = app
            .clone()
            .oneshot(get_req("/kv/OTHER_KEY", None, Some(api_key)))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert!(ban_row(&state.pool, &device_id).await.is_none());
    }

    #[tokio::test]
    async fn unban_keeps_count_and_next_ban_escalates() {
        let (app, state, admin, device_id, dt) = fixture().await;
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        let unban_path = format!("/api/admin/device-policies/{device_id}/ban");

        // No active ban yet → 404.
        let (s, _) = call(&app, "DELETE", &unban_path, Some(&admin), None).await;
        assert_eq!(s, 404);

        call(&app, "GET", "/kv/OTHER_KEY", Some(&dt), None).await;
        let (s, _) = call(&app, "DELETE", &unban_path, Some(&admin), None).await;
        assert_eq!(s, 204);
        let (banned_at, count, _) = ban_row(&state.pool, &device_id).await.unwrap();
        assert!(banned_at.is_none());
        assert_eq!(count, 1, "unban keeps ban_count");
        let (s, _) = call(&app, "GET", "/kv/FOO", Some(&dt), None).await;
        assert_eq!(s, 200, "unbanned device works again");

        let (s, b) = call(
            &app,
            "GET",
            "/api/admin/device-policies",
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(json(&b)[0]["ban"]["active"], false);

        // Second offence: base 3600s doubled → > 90 min.
        call(&app, "GET", "/kv/OTHER_KEY", Some(&dt), None).await;
        let (count, over_90m) = sqlx::query_as::<_, (i64, i64)>(
            "SELECT ban_count, unban_at > datetime('now', '+90 minutes') FROM device_bans WHERE device_id = ?",
        )
        .bind(&device_id)
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(over_90m, 1, "second ban must be longer than the first");
    }

    #[tokio::test]
    async fn device_session_cannot_manage_policies_or_unban_itself() {
        let (app, state, admin, device_id, dt) = fixture().await;
        let base = "/api/admin/device-policies";
        let body = serde_json::json!({ "mode": "allow_all" });
        let calls: Vec<(&str, String, Option<serde_json::Value>)> = vec![
            ("GET", base.to_string(), None),
            ("GET", format!("{base}/bans"), None),
            ("PUT", format!("{base}/{device_id}"), Some(body.clone())),
            ("DELETE", format!("{base}/{device_id}/ban"), None),
        ];
        for (m, p, b) in &calls {
            let (s, resp) = call(&app, m, p, Some(&dt), b.clone()).await;
            assert_eq!(s, 403, "{m} {p}: {resp}");
        }

        // Banned device trying to unban itself / reset its policy: still 403, ban intact.
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        call(&app, "GET", "/kv/OTHER_KEY", Some(&dt), None).await;
        for (m, p, b) in &calls {
            let (s, _) = call(&app, m, p, Some(&dt), b.clone()).await;
            assert_eq!(s, 403);
        }
        assert!(ban_row(&state.pool, &device_id).await.unwrap().0.is_some());

        // A device can't delete itself to shed its policy/ban.
        let d2 = insert_device(&state.pool, "other").await;
        let t2 = insert_device_session(&state.pool, &d2).await;
        let (s, _) = call(
            &app,
            "DELETE",
            &format!("/api/admin/devices/{d2}"),
            Some(&t2),
            None,
        )
        .await;
        assert_eq!(s, 403);
    }

    #[tokio::test]
    async fn restricted_device_cannot_mint_credentials() {
        let (app, _state, admin, device_id, dt) = fixture().await;
        let cli = serde_json::json!({ "days": 1 });
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&dt),
            Some(cli.clone()),
        )
        .await;
        assert_eq!(s, 200, "unrestricted device keeps today's behaviour");

        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&dt),
            Some(cli.clone()),
        )
        .await;
        assert_eq!(s, 403);
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/session/device-token",
            Some(&dt),
            None,
        )
        .await;
        assert_eq!(s, 403);
        let (s, _) = call(&app, "POST", "/api/admin/session-key", Some(&dt), None).await;
        assert_eq!(s, 403);
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/keys",
            Some(&dt),
            Some(serde_json::json!({ "label": "x", "key_type": "standard", "allowed_keys": ["OTHER_KEY"] })),
        )
        .await;
        assert_eq!(s, 403);
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&admin),
            Some(cli),
        )
        .await;
        assert_eq!(s, 200, "non-device admin unaffected");
    }

    #[tokio::test]
    async fn put_validation() {
        let (app, _state, admin, device_id, _dt) = fixture().await;
        let bad = [
            serde_json::json!({ "mode": "allow_some" }),
            serde_json::json!({ "mode": "allow_list", "keys": [] }),
            serde_json::json!({ "mode": "deny_list" }),
            serde_json::json!({ "mode": "allow_list", "keys": ["  ", ""] }),
            serde_json::json!({ "mode": "allow_list", "keys": ["x".repeat(257)] }),
            serde_json::json!({ "mode": "allow_list", "keys": (0..501).map(|i| format!("K{i}")).collect::<Vec<_>>() }),
            serde_json::json!({ "mode": "regex" }),
            serde_json::json!({ "mode": "regex", "pattern": "" }),
            serde_json::json!({ "mode": "regex", "pattern": "(" }),
            serde_json::json!({ "mode": "regex", "pattern": "a".repeat(513) }),
            serde_json::json!({ "mode": "regex", "pattern": r"\w{1000}\w{1000}" }),
            // Anchor escapes: invalid on their own, valid only once wrapped in ^(?:…)$.
            serde_json::json!({ "mode": "regex", "pattern": "FOO)|(.*" }),
            serde_json::json!({ "mode": "regex", "pattern": "FOO)|.*(?:" }),
            serde_json::json!({ "mode": "regex", "pattern": "a)|(b" }),
        ];
        for b in bad {
            let (s, _) = put_policy(&app, &admin, &device_id, b.clone()).await;
            assert!((400..500).contains(&s), "{b} → {s}");
        }

        let (s, _) = put_policy(
            &app,
            &admin,
            "no-such-device",
            serde_json::json!({ "mode": "allow_all" }),
        )
        .await;
        assert_eq!(s, 404);

        // Trim + dedup; switching mode clears stale keys/pattern.
        let (s, row) = put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": [" FOO ", "FOO", "BAR", ""], "pattern": "x" }),
        )
        .await;
        assert_eq!(s, 200);
        let mut keys: Vec<String> = serde_json::from_value(row["keys"].clone()).unwrap();
        keys.sort();
        assert_eq!(keys, vec!["BAR", "FOO"]);
        assert!(row["pattern"].is_null());
        let (s, row) = put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_all" }),
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(row["keys"], serde_json::json!([]));
        assert_eq!(row["mode"], "allow_all");
    }

    #[tokio::test]
    async fn list_shows_unconfigured_devices_as_allow_all() {
        let (app, state, admin, device_id, _dt) = fixture().await;
        // Another owner's device must not be listed.
        sqlx::query(
            "INSERT INTO devices (id, owner_id, name, public_key, key_type) VALUES ('foreign', 'someone-else', 'x', 'AAAA', 'x25519')",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        let (s, b) = call(
            &app,
            "GET",
            "/api/admin/device-policies",
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(
            json(&b),
            serde_json::json!([{
                "device_id": device_id, "device_name": "hermes", "mode": "allow_all",
                "keys": [], "pattern": null, "ban": null
            }])
        );
        let (s, _) = put_policy(
            &app,
            &admin,
            "foreign",
            serde_json::json!({ "mode": "allow_all" }),
        )
        .await;
        assert_eq!(s, 404);
    }

    #[tokio::test]
    async fn expired_ban_no_longer_blocks() {
        let (app, state, admin, device_id, dt) = fixture().await;
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        call(&app, "GET", "/kv/OTHER_KEY", Some(&dt), None).await;
        let (s, _) = call(&app, "GET", "/kv/FOO", Some(&dt), None).await;
        assert_eq!(s, 403);

        sqlx::query(
            "UPDATE device_bans SET unban_at = datetime('now', '-1 second') WHERE device_id = ?",
        )
        .bind(&device_id)
        .execute(&state.pool)
        .await
        .unwrap();
        let (s, _) = call(&app, "GET", "/kv/FOO", Some(&dt), None).await;
        assert_eq!(s, 200);
        let (s, b) = call(
            &app,
            "GET",
            "/api/admin/device-policies/bans",
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(json(&b), serde_json::json!([]));
        // An expired ban can't be "lifted" again.
        let (s, _) = call(
            &app,
            "DELETE",
            &format!("/api/admin/device-policies/{device_id}/ban"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 404);
    }

    #[tokio::test]
    async fn deleting_device_removes_policy_and_ban_rows() {
        let (app, state, admin, _device_id, _dt) = fixture().await;
        // (Devices WITH sessions/minted tokens: deleting_device_deletes_all_its_credentials.)
        let d = insert_device(&state.pool, "old-phone").await;
        put_policy(
            &app,
            &admin,
            &d,
            serde_json::json!({ "mode": "allow_list", "keys": ["FOO"] }),
        )
        .await;
        sqlx::query(
            "INSERT INTO device_bans (device_id, owner_id, banned_at, unban_at, ban_count, last_key)
             VALUES (?, ?, datetime('now'), datetime('now', '+1 hour'), 1, 'OTHER_KEY')",
        )
        .bind(&d)
        .bind(TEST_OWNER)
        .execute(&state.pool)
        .await
        .unwrap();

        let (s, _) = call(
            &app,
            "DELETE",
            &format!("/api/admin/devices/{d}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 204);
        for table in ["device_policies", "device_policy_keys", "device_bans"] {
            let n: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE device_id = ?"))
                    .bind(&d)
                    .fetch_one(&state.pool)
                    .await
                    .unwrap();
            assert_eq!(n, 0, "{table} row left behind");
        }
    }

    // ── Helpers for flows needing a real device keypair ─────────────────────────

    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Key, Nonce,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hkdf::Hkdf;
    use rand_core::OsRng;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    async fn insert_device_with_key(pool: &SqlitePool, name: &str) -> (String, StaticSecret) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let pub_b64 = STANDARD.encode(PublicKey::from(&secret).as_bytes());
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO devices (id, owner_id, name, public_key, key_type) VALUES (?, ?, ?, ?, 'x25519')",
        )
        .bind(&id)
        .bind(TEST_OWNER)
        .bind(name)
        .bind(&pub_b64)
        .execute(pool)
        .await
        .unwrap();
        (id, secret)
    }

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

    /// POST /session-request/challenge → (challenge_id, decrypted nonce).
    async fn challenge(app: &Router, device_id: &str, secret: &StaticSecret) -> (String, String) {
        let (s, b) = call(
            app,
            "POST",
            "/session-request/challenge",
            None,
            Some(serde_json::json!({ "device_id": device_id })),
        )
        .await;
        assert_eq!(s, 201, "challenge: {b}");
        let ch = json(&b);
        let nonce = String::from_utf8(decrypt_envelope(secret, &ch["envelope"])).unwrap();
        (ch["challenge_id"].as_str().unwrap().to_string(), nonce)
    }

    async fn create_request(app: &Router, challenge_id: &str, nonce: &str) -> (u16, String) {
        call(
            app,
            "POST",
            "/session-request",
            None,
            Some(serde_json::json!({
                "label": "twin", "requested_duration_hours": 24,
                "challenge_id": challenge_id, "nonce": nonce,
            })),
        )
        .await
    }

    /// challenge → create_request for `device_id`. Returns (id, poll_secret, approve_token).
    async fn session_request(
        app: &Router,
        device_id: &str,
        secret: &StaticSecret,
    ) -> (String, String, String) {
        let (cid, nonce) = challenge(app, device_id, secret).await;
        let (s, b) = create_request(app, &cid, &nonce).await;
        assert_eq!(s, 201, "create_request: {b}");
        let c = json(&b);
        (
            c["id"].as_str().unwrap().to_string(),
            c["poll_secret"].as_str().unwrap().to_string(),
            c["approve_token"].as_str().unwrap().to_string(),
        )
    }

    async fn approve(app: &Router, token: &str, id: &str, approve_token: &str) -> (u16, String) {
        call(
            app,
            "POST",
            &format!("/api/admin/session-requests/{id}/approve"),
            Some(token),
            Some(serde_json::json!({ "token": approve_token, "approved_duration_hours": 24 })),
        )
        .await
    }

    async fn poll(app: &Router, id: &str, poll_secret: &str) -> (u16, String) {
        call(
            app,
            "GET",
            &format!("/session-request/{id}/status?secret={poll_secret}"),
            None,
            None,
        )
        .await
    }

    async fn restrict(app: &Router, admin: &str, device_id: &str, keys: &[&str]) {
        let (s, b) = put_policy(
            app,
            admin,
            device_id,
            serde_json::json!({ "mode": "allow_list", "keys": keys }),
        )
        .await;
        assert_eq!(s, 200, "restrict failed: {b}");
    }

    /// Fresh device + device-bound session, restricted to `keys`.
    async fn restricted_device(
        app: &Router,
        pool: &SqlitePool,
        admin: &str,
        keys: &[&str],
    ) -> (String, String) {
        let d = insert_device(pool, &format!("dev-{}", Uuid::new_v4())).await;
        let t = insert_device_session(pool, &d).await;
        restrict(app, admin, &d, keys).await;
        (d, t)
    }

    /// Writes an active ban row directly.
    async fn ban_now(pool: &SqlitePool, device_id: &str) {
        sqlx::query(
            "INSERT INTO device_bans (device_id, owner_id, banned_at, unban_at, ban_count, last_key)
             VALUES (?, ?, datetime('now'), datetime('now', '+1 hour'), 1, 'X')
             ON CONFLICT(device_id) DO UPDATE SET banned_at = excluded.banned_at,
                 unban_at = excluded.unban_at",
        )
        .bind(device_id)
        .bind(TEST_OWNER)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn kv_value(pool: &SqlitePool, key: &str) -> Option<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT value FROM kv_entries WHERE key = ? AND owner_id = ?",
        )
        .bind(key)
        .bind(TEST_OWNER)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    /// 403 that is NOT a ban (plain refusal), and no ban row was recorded.
    async fn assert_refused_not_banned(pool: &SqlitePool, device_id: &str, s: u16, b: &str) {
        assert_eq!(s, 403, "body: {b}");
        assert_eq!(json(b)["error"], "not permitted for this device", "{b}");
        assert!(
            ban_row(pool, device_id).await.is_none(),
            "a plain refusal must not ban"
        );
    }

    // ── Security review PoCs (ported as regression tests) ───────────────────────

    /// S1 (P0): a restricted device must not approve a session request for a sibling
    /// (allow_all) twin and so obtain an unrestricted session.
    #[tokio::test]
    async fn secrev_s1_restricted_device_cannot_approve_twin() {
        let (app, state) = build_policy_app().await;
        seed_kv(&state.pool, &["OPENROUTER_API_KEY", "SECRET_DB"]).await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d1, _) = insert_device_with_key(&state.pool, "d1-restricted").await;
        let d1_token = insert_device_session(&state.pool, &d1).await;
        restrict(&app, &admin, &d1, &["OPENROUTER_API_KEY"]).await;
        let (d2, d2_sec) = insert_device_with_key(&state.pool, "d2-twin").await;

        let (id, poll_secret, approve_token) = session_request(&app, &d2, &d2_sec).await;
        let (s, b) = approve(&app, &d1_token, &id, &approve_token).await;
        let approved = s == 204;

        let (ss, sb) = poll(&app, &id, &poll_secret).await;
        let v = json(&sb);
        let mut twin_read = false;
        if ss == 200 && v["envelope"].is_object() {
            let token = String::from_utf8(decrypt_envelope(&d2_sec, &v["envelope"])).unwrap();
            let (rs, _) = call(&app, "GET", "/kv/SECRET_DB", Some(&token), None).await;
            twin_read = rs == 200;
        }
        assert!(
            !(approved && twin_read),
            "S1: restricted device minted a twin session that read forbidden SECRET_DB"
        );
        assert_refused_not_banned(&state.pool, &d1, s, &b).await;
        assert_eq!(v["status"], "pending", "request must stay unapproved");
    }

    /// S2 (P0): deleting a device that owns a session token works, and the token dies.
    #[tokio::test]
    async fn secrev_s2_delete_device_with_session_token() {
        let (app, state) = build_policy_app().await;
        seed_kv(&state.pool, &["X"]).await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d, _sec) = insert_device_with_key(&state.pool, "compromised").await;
        let tok = insert_device_session(&state.pool, &d).await;

        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/devices/{d}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 204, "S2: delete device with a session token: {s} {b}");
        for path in [
            "/kv/X",
            "/api/admin/session/whoami",
            "/api/admin/kv/X/value",
        ] {
            let (s, _) = call(&app, "GET", path, Some(&tok), None).await;
            assert_eq!(s, 401, "{path}");
        }
    }

    /// S3 (P1): unbalanced parens must not escape the ^(?:…)$ anchors.
    #[tokio::test]
    async fn secrev_s3_regex_anchor_escape() {
        use crate::device_policy::enforce::policy_allows;
        use crate::device_policy::model::PolicyMode;
        let pat = "FOO)|(.*";
        assert!(
            !policy_allows(PolicyMode::Regex, &[], Some(pat), "SECRET_DB"),
            "S3: regex '{pat}' escaped its anchors"
        );
        // …and it's rejected on save with 400.
        let (app, _state, admin, device_id, _dt) = fixture().await;
        for p in ["FOO)|(.*", "FOO)|.*(?:", "a)|(b"] {
            let (s, _) = put_policy(
                &app,
                &admin,
                &device_id,
                serde_json::json!({ "mode": "regex", "pattern": p }),
            )
            .await;
            assert_eq!(s, 400, "{p}");
        }
    }

    /// S4 (P1): a restricted device can neither overwrite nor delete a disallowed key.
    #[tokio::test]
    async fn secrev_s4_restricted_device_cannot_write_disallowed_key() {
        let (app, state) = build_policy_app().await;
        seed_kv(&state.pool, &["ALLOWED", "OPENROUTER_API_KEY"]).await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d, _sec) = insert_device_with_key(&state.pool, "writer").await;
        let d_token = insert_device_session(&state.pool, &d).await;
        restrict(&app, &admin, &d, &["ALLOWED"]).await;

        let (s, b) = call(
            &app,
            "PUT",
            "/kv/OPENROUTER_API_KEY",
            Some(&d_token),
            Some(serde_json::json!({ "value": "attacker-controlled" })),
        )
        .await;
        assert!(s == 403, "S4: overwrote disallowed key (status {s}: {b})");
        assert_banned(s, &b);
        assert_eq!(
            kv_value(&state.pool, "OPENROUTER_API_KEY").await.as_deref(),
            Some("value-of-OPENROUTER_API_KEY")
        );
    }

    /// S4 control: same via the admin KV write endpoint.
    #[tokio::test]
    async fn secrev_s4b_restricted_device_admin_write_kv() {
        let (app, state) = build_policy_app().await;
        seed_kv(&state.pool, &["ALLOWED"]).await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d, _sec) = insert_device_with_key(&state.pool, "writer2").await;
        let d_token = insert_device_session(&state.pool, &d).await;
        restrict(&app, &admin, &d, &["ALLOWED"]).await;

        let (s, b) = call(
            &app,
            "PUT",
            "/api/admin/kv",
            Some(&d_token),
            Some(serde_json::json!({ "key": "OPENROUTER_API_KEY", "value": "x" })),
        )
        .await;
        assert_eq!(s, 403, "S4: wrote disallowed key via /api/admin/kv ({b})");
        assert!(kv_value(&state.pool, "OPENROUTER_API_KEY").await.is_none());
    }

    /// S5 (P1): a token minted by an allow_all device stays attributed to it, so a later
    /// restriction applies to that token too.
    #[tokio::test]
    async fn secrev_s5_minted_token_follows_later_restriction() {
        let (app, state) = build_policy_app().await;
        seed_kv(&state.pool, &["SECRET_DB"]).await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d, _sec) = insert_device_with_key(&state.pool, "sneaky").await;
        let d_token = insert_device_session(&state.pool, &d).await;

        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&d_token),
            Some(serde_json::json!({ "days": 30 })),
        )
        .await;
        assert_eq!(s, 200, "cli-token mint failed: {b}");
        let minted = json(&b).as_str().unwrap_or_default().to_string();
        assert!(!minted.is_empty(), "no token minted");

        restrict(&app, &admin, &d, &["NOTHING_USEFUL"]).await;

        let (rs, rb) = call(
            &app,
            "GET",
            "/api/admin/kv/SECRET_DB/value",
            Some(&minted),
            None,
        )
        .await;
        assert_ne!(
            rs, 200,
            "S5: minted token still reads forbidden keys ({rb})"
        );
        assert_banned(rs, &rb);
        assert_eq!(ban_row(&state.pool, &d).await.unwrap().1, 1);
    }

    // ── C1: identity / credential management from a restricted device ───────────

    #[tokio::test]
    async fn restricted_device_refused_identity_management() {
        let (app, state, admin, device_id, dt) = fixture().await;
        restrict(&app, &admin, &device_id, &["FOO"]).await;
        sqlx::query(
            "INSERT INTO zero_trust_credentials (id, owner_id, credential_id, public_key_cose, device_label)
             VALUES ('cred-1', ?, 'Y3JlZA', '{}', 'yubikey')",
        )
        .bind(TEST_OWNER)
        .execute(&state.pool)
        .await
        .unwrap();

        let b64 = "AAAA";
        let reg_credential = serde_json::json!({
            "id": b64, "rawId": b64, "type": "public-key", "extensions": {},
            "response": { "attestationObject": b64, "clientDataJSON": b64 },
        });
        let assertion = serde_json::json!({
            "id": b64, "rawId": b64, "type": "public-key", "extensions": {},
            "response": {
                "authenticatorData": b64, "clientDataJSON": b64,
                "signature": b64, "userHandle": null,
            },
        });
        let calls: Vec<(&str, String, Option<serde_json::Value>)> = vec![
            (
                "POST",
                "/api/admin/webauthn/register/begin".into(),
                Some(serde_json::json!({ "device_label": "evil" })),
            ),
            (
                "POST",
                "/api/admin/webauthn/register/finish".into(),
                Some(serde_json::json!({ "challenge_id": "c", "credential": reg_credential })),
            ),
            (
                "DELETE",
                "/api/admin/webauthn/credentials/cred-1".into(),
                None,
            ),
            (
                "POST",
                "/api/devices/register/begin".into(),
                Some(
                    serde_json::json!({ "name": "twin", "public_key": "AAAA", "key_type": "x25519" }),
                ),
            ),
            (
                "POST",
                "/api/devices/register/finish".into(),
                Some(serde_json::json!({ "challenge_id": "c", "assertion": assertion })),
            ),
            (
                "POST",
                "/api/admin/device-proposals/some-proposal/link".into(),
                Some(serde_json::json!({ "device_id": device_id, "token": "t" })),
            ),
        ];
        for (m, p, b) in &calls {
            let (s, body) = call(&app, m, p, Some(&dt), b.clone()).await;
            assert_eq!(s, 403, "{m} {p}: {body}");
            assert_eq!(
                json(&body)["error"],
                "not permitted for this device",
                "{m} {p}: {body}"
            );
        }
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM zero_trust_credentials")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "credential must not be deleted");
        assert!(ban_row(&state.pool, &device_id).await.is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            rate_count(&state),
            0,
            "plain 403 carries no AuthFailed marker"
        );
        assert_eq!(block_count(&state.pool).await, 0);

        // An unrestricted device keeps today's behaviour (handler logic runs; here WebAuthn
        // isn't configured in tests, so it's not a 403 from the guard) and may delete creds.
        let free = insert_device(&state.pool, "free").await;
        let ft = insert_device_session(&state.pool, &free).await;
        for (m, p, b) in calls.iter().filter(|(_, p, _)| p.ends_with("/begin")) {
            let (s, body) = call(&app, m, p, Some(&ft), b.clone()).await;
            assert_ne!(json(&body)["error"], "not permitted for this device", "{p}");
            assert_ne!(s, 403, "{p}: {body}");
        }
        let (s, _) = call(
            &app,
            "DELETE",
            "/api/admin/webauthn/credentials/cred-1",
            Some(&ft),
            None,
        )
        .await;
        assert_eq!(s, 204);
    }

    #[tokio::test]
    async fn session_approve_other_device_only_for_unrestricted_callers() {
        let (app, state) = build_policy_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d1, d1_sec) = insert_device_with_key(&state.pool, "phone").await;
        let d1_token = insert_device_session(&state.pool, &d1).await;
        let (d2, d2_sec) = insert_device_with_key(&state.pool, "laptop").await;

        // allow_all device (the Android app) approves another device's request: allowed.
        let (id, _, tok) = session_request(&app, &d2, &d2_sec).await;
        let (s, b) = approve(&app, &d1_token, &id, &tok).await;
        assert_eq!(s, 204, "{b}");

        // Restricted: other device refused (no ban), own device still allowed.
        restrict(&app, &admin, &d1, &["FOO"]).await;
        let (id, _, tok) = session_request(&app, &d2, &d2_sec).await;
        let (s, b) = approve(&app, &d1_token, &id, &tok).await;
        assert_refused_not_banned(&state.pool, &d1, s, &b).await;
        let (id, poll_secret, tok) = session_request(&app, &d1, &d1_sec).await;
        let (s, b) = approve(&app, &d1_token, &id, &tok).await;
        assert_eq!(s, 204, "own device: {b}");
        // The new session is bound to d1 and therefore restricted like d1.
        let (_, pb) = poll(&app, &id, &poll_secret).await;
        let new_token =
            String::from_utf8(decrypt_envelope(&d1_sec, &json(&pb)["envelope"])).unwrap();
        let (s, b) = call(
            &app,
            "GET",
            "/api/admin/session/whoami",
            Some(&new_token),
            None,
        )
        .await;
        assert_eq!(s, 200);
        assert_eq!(json(&b)["device_id"], d1.as_str());
    }

    // ── H1: device-minted credentials stay attributed ───────────────────────────

    #[tokio::test]
    async fn device_minted_tokens_inherit_ban_and_policy() {
        let (app, state, admin, device_id, dt) = fixture().await;

        // While allow_all, the device mints a standard X-Api-Key and a CLI (approval) token.
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/keys",
            Some(&dt),
            Some(serde_json::json!({
                "label": "minted", "key_type": "standard",
                "allowed_keys": ["FOO", "OTHER_KEY"],
            })),
        )
        .await;
        assert_eq!(s, 201, "{b}");
        let x_api_key = json(&b)["key"].as_str().unwrap().to_string();
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&dt),
            Some(serde_json::json!({ "days": 1 })),
        )
        .await;
        assert_eq!(s, 200);
        let cli = json(&b).as_str().unwrap().to_string();
        let attributed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE device_id = ?")
                .bind(&device_id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(attributed, 3, "session + 2 minted keys carry the device id");

        // A device-attributed approval token is still a device credential: no policy admin.
        let (s, _) = call(&app, "GET", "/api/admin/device-policies", Some(&cli), None).await;
        assert_eq!(s, 403);
        let (_, b) = call(&app, "GET", "/api/admin/session/whoami", Some(&cli), None).await;
        assert_eq!(json(&b)["device_id"], device_id.as_str());

        restrict(&app, &admin, &device_id, &["FOO"]).await;

        let x_get = |path: &'static str, key: String| {
            let app = app.clone();
            async move {
                let resp = app.oneshot(get_req(path, None, Some(key))).await.unwrap();
                let s = resp.status().as_u16();
                let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
                (s, String::from_utf8_lossy(&b).to_string())
            }
        };
        // X-Api-Key: allowed by both key scope and device policy.
        let (s, b) = x_get("/kv/FOO", x_api_key.clone()).await;
        assert_eq!((s, b.as_str()), (200, "value-of-FOO"));
        // In key scope, but the minting device's policy refuses it → device banned.
        let (s, b) = x_get("/kv/OTHER_KEY", x_api_key.clone()).await;
        assert_banned(s, &b);
        assert_eq!(ban_row(&state.pool, &device_id).await.unwrap().1, 1);
        // While banned every attributed credential is refused, even for allowed keys.
        let (s, b) = x_get("/kv/FOO", x_api_key.clone()).await;
        assert_banned(s, &b);
        let (s, b) = call(&app, "GET", "/api/admin/session/whoami", Some(&cli), None).await;
        assert_banned(s, &b);
        let (s, b) = call(&app, "GET", "/kv/FOO", Some(&dt), None).await;
        assert_banned(s, &b);

        // Bearer: a session key minted by the device (unban first; minted while allow_all).
        let unban = format!("/api/admin/device-policies/{device_id}/ban");
        assert_eq!(
            call(&app, "DELETE", &unban, Some(&admin), None).await.0,
            204
        );
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "allow_all" }),
        )
        .await;
        let (s, b) = call(&app, "POST", "/api/admin/session-key", Some(&dt), None).await;
        assert_eq!(s, 201, "{b}");
        let session_key = json(&b)["key"].as_str().unwrap().to_string();
        restrict(&app, &admin, &device_id, &["FOO"]).await;
        let (s, _) = call(&app, "GET", "/kv/FOO", Some(&session_key), None).await;
        assert_eq!(s, 200);
        let (s, b) = call(&app, "GET", "/kv/OTHER_KEY", Some(&session_key), None).await;
        assert_banned(s, &b);
        assert_eq!(ban_row(&state.pool, &device_id).await.unwrap().1, 2);

        // Non-device admin credentials are never attributed.
        let (_, b) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&admin),
            Some(serde_json::json!({ "days": 1 })),
        )
        .await;
        let plain = json(&b).as_str().unwrap().to_string();
        let (s, b) = call(&app, "GET", "/api/admin/session/whoami", Some(&plain), None).await;
        assert_eq!(s, 200);
        assert!(json(&b)["device_id"].is_null());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(rate_count(&state), 0);
        assert_eq!(block_count(&state.pool).await, 0);
    }

    // ── H2: writes / deletes / imports ──────────────────────────────────────────

    #[tokio::test]
    async fn restricted_device_writes_deletes_imports_enforced() {
        let (app, state, admin, _device_id, _dt) = fixture().await;
        let free = insert_device(&state.pool, "rcpt").await;
        let recipients = serde_json::json!([{
            "device_id": free, "key_type": "x25519", "ephemeral_pub": "AA",
            "dek_nonce": "AA", "encrypted_dek": "AA",
        }]);
        let device_write = |key: &str| {
            serde_json::json!({
                "key": key, "nonce": "AA", "ciphertext": "AA", "aad": "AA",
                "recipients": recipients,
            })
        };
        // Allowed operations succeed.
        let (d, t) = restricted_device(&app, &state.pool, &admin, &["FOO", "P_A", "NEW"]).await;
        let ok: Vec<(&str, &str, Option<serde_json::Value>, u16)> = vec![
            (
                "PUT",
                "/kv/FOO",
                Some(serde_json::json!({ "value": "v2" })),
                204,
            ),
            (
                "PUT",
                "/api/admin/kv",
                Some(serde_json::json!({ "key": "NEW", "value": "n" })),
                204,
            ),
            (
                "POST",
                "/api/admin/kv/device",
                Some(device_write("NEW")),
                201,
            ),
            (
                "POST",
                "/api/admin/kv/import",
                Some(serde_json::json!({ "content": "A=1\n# c", "prefix": "P_" })),
                200,
            ),
            ("DELETE", "/kv/FOO", None, 204),
            ("DELETE", "/api/admin/kv/P_A", None, 204),
        ];
        for (m, p, b, want) in ok {
            let (s, body) = call(&app, m, p, Some(&t), b).await;
            assert_eq!(s, want, "{m} {p}: {body}");
        }
        assert!(ban_row(&state.pool, &d).await.is_none());

        // Each disallowed operation bans a fresh device and changes nothing.
        let bad: Vec<(&str, &str, Option<serde_json::Value>)> = vec![
            (
                "PUT",
                "/kv/OTHER_KEY",
                Some(serde_json::json!({ "value": "evil" })),
            ),
            ("DELETE", "/kv/OTHER_KEY", None),
            (
                "PUT",
                "/api/admin/kv",
                Some(serde_json::json!({ "key": "OTHER_KEY", "value": "evil" })),
            ),
            ("DELETE", "/api/admin/kv/OTHER_KEY", None),
            (
                "POST",
                "/api/admin/kv/device",
                Some(device_write("OTHER_KEY")),
            ),
            // The prefix is part of the checked name: P_B is not allowed, so nothing
            // (not even the allowed P_A) is imported.
            (
                "POST",
                "/api/admin/kv/import",
                Some(serde_json::json!({ "content": "A=1\nB=2", "prefix": "P_" })),
            ),
            // Allowed bare name, disallowed once prefixed.
            (
                "POST",
                "/api/admin/kv/import",
                Some(serde_json::json!({ "content": "FOO=1", "prefix": "X_" })),
            ),
        ];
        for (m, p, b) in bad {
            let (d, t) = restricted_device(&app, &state.pool, &admin, &["FOO", "P_A"]).await;
            let (s, body) = call(&app, m, p, Some(&t), b).await;
            assert_banned(s, &body);
            assert_eq!(ban_row(&state.pool, &d).await.unwrap().1, 1, "{m} {p}");
        }
        assert_eq!(
            kv_value(&state.pool, "OTHER_KEY").await.as_deref(),
            Some("value-of-OTHER_KEY")
        );
        for k in ["P_A", "P_B", "X_FOO"] {
            assert!(kv_value(&state.pool, k).await.is_none(), "{k} imported");
        }
        let dkv: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_kv_bodies WHERE kv_key = 'OTHER_KEY'")
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(dkv, 0);
    }

    // ── C2: device deletion removes every credential attributed to it ───────────

    #[tokio::test]
    async fn deleting_device_deletes_all_its_credentials() {
        let (app, state) = build_policy_app().await;
        seed_kv(&state.pool, &["FOO"]).await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d, d_sec) = insert_device_with_key(&state.pool, "stolen").await;
        let session = insert_device_session(&state.pool, &d).await;
        restrict(&app, &admin, &d, &["FOO"]).await;
        put_policy(&app, &admin, &d, serde_json::json!({ "mode": "allow_all" })).await;
        let (_, b) = call(
            &app,
            "POST",
            "/api/admin/keys",
            Some(&session),
            Some(serde_json::json!({ "label": "m", "key_type": "standard", "allowed_keys": ["FOO"] })),
        )
        .await;
        let x_api_key = json(&b)["key"].as_str().unwrap().to_string();
        let (_, b) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&session),
            Some(serde_json::json!({ "days": 1 })),
        )
        .await;
        let cli = json(&b).as_str().unwrap().to_string();
        // Pending + approved session requests and a dangling challenge reference the device.
        let (id1, _, tok1) = session_request(&app, &d, &d_sec).await;
        assert_eq!(approve(&app, &admin, &id1, &tok1).await.0, 204);
        let _ = session_request(&app, &d, &d_sec).await;
        let _ = challenge(&app, &d, &d_sec).await;
        sqlx::query(
            "INSERT INTO device_proposals (id, name, public_key, key_type, poll_secret_hash, expires_at, confirm_token_hash, status, resulting_device_id)
             VALUES ('p1', 'stolen', 'AAAA', 'x25519', 'h', datetime('now', '+1 hour'), 'h', 'confirmed', ?)",
        )
        .bind(&d)
        .execute(&state.pool)
        .await
        .unwrap();
        // The admin's own (non-device) key survives.
        let other = insert_api_key(&state.pool, "active", None, &["FOO"]).await;

        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/devices/{d}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");

        for tok in [&session, &cli] {
            let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(tok), None).await;
            assert_eq!(s, 401);
        }
        let (s, _) = call(&app, "GET", "/kv/FOO", Some(&session), None).await;
        assert_eq!(s, 401);
        let resp = app
            .clone()
            .oneshot(get_req("/kv/FOO", None, Some(x_api_key)))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        let resp = app
            .clone()
            .oneshot(get_req("/kv/FOO", None, Some(other)))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "unrelated key unaffected");

        for (table, col) in [
            ("api_keys", "device_id"),
            ("session_requests", "device_id"),
            ("session_request_challenges", "device_id"),
            ("device_proposals", "resulting_device_id"),
            ("device_policies", "device_id"),
        ] {
            let n: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {col} = ?"))
                    .bind(&d)
                    .fetch_one(&state.pool)
                    .await
                    .unwrap();
            assert_eq!(n, 0, "{table} row left behind");
        }
        // Deleted, never detached: only the admin session + unrelated key remain.
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(n, 2);
        let orphans: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_key_allowed_keys WHERE api_key_id NOT IN (SELECT id FROM api_keys)",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        assert_eq!(orphans, 0);
    }

    // ── L1 / L2 / L3 ────────────────────────────────────────────────────────────

    #[test]
    fn device_ban_base_secs_clamped_to_minimum() {
        use crate::config::{clamp_device_ban_base_secs, MIN_DEVICE_BAN_BASE_SECS};
        assert_eq!(MIN_DEVICE_BAN_BASE_SECS, 60);
        assert_eq!(clamp_device_ban_base_secs(0), 60);
        assert_eq!(clamp_device_ban_base_secs(59), 60);
        assert_eq!(clamp_device_ban_base_secs(60), 60);
        assert_eq!(clamp_device_ban_base_secs(86400), 86400);
    }

    #[tokio::test]
    async fn session_request_flow_refused_while_banned() {
        let (app, state) = build_policy_app().await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d, sec) = insert_device_with_key(&state.pool, "banned-phone").await;

        // Requests created / approved before the ban.
        let (pre_approved, pre_secret, tok) = session_request(&app, &d, &sec).await;
        assert_eq!(approve(&app, &admin, &pre_approved, &tok).await.0, 204);
        let (pending, _, pending_tok) = session_request(&app, &d, &sec).await;
        let (cid, nonce) = challenge(&app, &d, &sec).await;

        ban_now(&state.pool, &d).await;

        // L2: the unauthenticated challenge endpoint answers exactly as for an unbanned
        // device (no ban-status oracle) …
        let (s, b) = call(
            &app,
            "POST",
            "/session-request/challenge",
            None,
            Some(serde_json::json!({ "device_id": d })),
        )
        .await;
        assert_eq!(s, 201, "{b}");
        assert!(json(&b)["envelope"].is_object());
        // … but possession-proven request creation, polling/claiming and approval are refused.
        let (s, b) = create_request(&app, &cid, &nonce).await;
        assert_banned(s, &b);
        let (s, b) = poll(&app, &pre_approved, &pre_secret).await;
        assert_banned(s, &b);
        assert!(!b.contains("envelope"));
        let (s, b) = approve(&app, &admin, &pending, &pending_tok).await;
        assert_banned(s, &b);
        let status: String = sqlx::query_scalar("SELECT status FROM session_requests WHERE id = ?")
            .bind(&pre_approved)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(status, "approved", "token not delivered while banned");
    }

    #[tokio::test]
    async fn restricted_device_listings_are_filtered_never_banned() {
        let (app, state, admin, device_id, dt) = fixture().await;
        restrict(&app, &admin, &device_id, &["FOO", "MISSING"]).await;
        let names = |v: serde_json::Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|e| e.get("key").unwrap_or(e).as_str().unwrap().to_string())
                .collect()
        };
        for path in [
            "/kv",
            "/kv?prefix=FOO",
            "/api/admin/kv",
            "/api/admin/kv?prefix=F",
            "/api/admin/kv/keys",
        ] {
            let (s, b) = call(&app, "GET", path, Some(&dt), None).await;
            assert_eq!(s, 200, "{path}: {b}");
            assert_eq!(names(json(&b)), vec!["FOO"], "{path}");
        }
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "regex", "pattern": "FOO.*" }),
        )
        .await;
        let (_, b) = call(&app, "GET", "/api/admin/kv/keys", Some(&dt), None).await;
        assert_eq!(names(json(&b)), vec!["FOO", "FOO_BAR"]);
        put_policy(
            &app,
            &admin,
            &device_id,
            serde_json::json!({ "mode": "deny_list", "keys": ["OTHER_KEY"] }),
        )
        .await;
        let (_, b) = call(&app, "GET", "/kv", Some(&dt), None).await;
        assert_eq!(
            names(json(&b)),
            vec!["FOO", "FOO_BAR", "OPENROUTER_API_KEY"]
        );
        // Admin (non-device) sees everything; listing never bans.
        let (_, b) = call(&app, "GET", "/api/admin/kv/keys", Some(&admin), None).await;
        assert_eq!(names(json(&b)).len(), 4);
        assert!(ban_row(&state.pool, &device_id).await.is_none());
    }

    // ── Envelope endpoints ──────────────────────────────────────────────────────

    async fn seed_management_key(pool: &SqlitePool, device_ids: &[&str]) -> String {
        let mk = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO management_keys (id, owner_id, provider, label) VALUES (?, ?, 'openrouter', 'mk')",
        )
        .bind(&mk)
        .bind(TEST_OWNER)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO management_key_bodies (management_key_id, nonce, ciphertext, aad) VALUES (?, 'n', 'c', 'a')",
        )
        .bind(&mk)
        .execute(pool)
        .await
        .unwrap();
        for d in device_ids {
            sqlx::query(
                "INSERT INTO management_key_recipients (id, management_key_id, device_id, key_type, ephemeral_pub, dek_nonce, encrypted_dek)
                 VALUES (?, ?, ?, 'x25519', 'e', 'n', 'k')",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&mk)
            .bind(d)
            .execute(pool)
            .await
            .unwrap();
        }
        mk
    }

    /// Provisioned key `pk` under `mk`, wrapped to `device_ids`; if `linked_kv` is set, a
    /// KV entry of that name is generated from it.
    async fn seed_provisioned_key(
        pool: &SqlitePool,
        mk: &str,
        device_ids: &[&str],
        linked_kv: Option<&str>,
    ) -> String {
        let pk = Uuid::new_v4().to_string();
        let provider_key_id = format!("prov-{pk}");
        sqlx::query(
            "INSERT INTO provisioned_keys (id, management_key_id, provider, provider_key_id, label) VALUES (?, ?, 'openrouter', ?, 'pk')",
        )
        .bind(&pk)
        .bind(mk)
        .bind(&provider_key_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO provisioned_key_bodies (provisioned_key_id, nonce, ciphertext, aad) VALUES (?, 'n', 'c', 'a')",
        )
        .bind(&pk)
        .execute(pool)
        .await
        .unwrap();
        for d in device_ids {
            sqlx::query(
                "INSERT INTO provisioned_key_recipients (id, provisioned_key_id, device_id, key_type, ephemeral_pub, dek_nonce, encrypted_dek)
                 VALUES (?, ?, ?, 'x25519', 'e', 'n', 'k')",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&pk)
            .bind(d)
            .execute(pool)
            .await
            .unwrap();
        }
        if let Some(k) = linked_kv {
            sqlx::query(
                "INSERT INTO kv_entries (key, owner_id, value, source_management_key_id, source_provider_key_id)
                 VALUES (?, ?, 'secret', ?, ?)",
            )
            .bind(k)
            .bind(TEST_OWNER)
            .bind(mk)
            .bind(&provider_key_id)
            .execute(pool)
            .await
            .unwrap();
        }
        pk
    }

    #[tokio::test]
    async fn provisioned_key_envelope_enforced() {
        let (app, state, admin, _device_id, _dt) = fixture().await;
        let (ok_d, ok_t) = restricted_device(&app, &state.pool, &admin, &["LINKED"]).await;
        let (bad_d, bad_t) = restricted_device(&app, &state.pool, &admin, &["FOO"]).await;
        let (unl_d, unl_t) = restricted_device(&app, &state.pool, &admin, &["LINKED"]).await;
        let free_d = insert_device(&state.pool, "free").await;
        let free_t = insert_device_session(&state.pool, &free_d).await;
        let all = [
            ok_d.as_str(),
            bad_d.as_str(),
            unl_d.as_str(),
            free_d.as_str(),
        ];
        let mk = seed_management_key(&state.pool, &all).await;
        let linked = seed_provisioned_key(&state.pool, &mk, &all, Some("LINKED")).await;
        let unlinked = seed_provisioned_key(&state.pool, &mk, &all, None).await;
        let path = |pk: &str, d: &str| {
            format!("/api/admin/management-keys/{mk}/provisioned-keys/{pk}/devices/{d}")
        };

        let (s, b) = call(&app, "GET", &path(&linked, &ok_d), Some(&ok_t), None).await;
        assert_eq!(s, 200, "allowed linked entry: {b}");
        // Linked KV entry not allowed by the policy → violation → ban.
        let (s, b) = call(&app, "GET", &path(&linked, &bad_d), Some(&bad_t), None).await;
        assert_banned(s, &b);
        assert_eq!(
            ban_row(&state.pool, &bad_d).await.unwrap().2.as_deref(),
            Some("LINKED")
        );
        // Restricted device, provisioned key with no KV entry: plain 403, no ban.
        let (s, b) = call(&app, "GET", &path(&unlinked, &unl_d), Some(&unl_t), None).await;
        assert_refused_not_banned(&state.pool, &unl_d, s, &b).await;
        // Unrestricted device and non-device admin: unaffected.
        let (s, _) = call(&app, "GET", &path(&unlinked, &free_d), Some(&free_t), None).await;
        assert_eq!(s, 200);
        let (s, _) = call(&app, "GET", &path(&unlinked, &unl_d), Some(&admin), None).await;
        assert_eq!(s, 200);
    }

    #[tokio::test]
    async fn management_key_envelope_refused_for_restricted_device() {
        let (app, state, admin, _device_id, _dt) = fixture().await;
        let (r_d, r_t) = restricted_device(&app, &state.pool, &admin, &["FOO"]).await;
        let free_d = insert_device(&state.pool, "free").await;
        let free_t = insert_device_session(&state.pool, &free_d).await;
        let mk = seed_management_key(&state.pool, &[&r_d, &free_d]).await;

        let (s, b) = call(
            &app,
            "GET",
            &format!("/api/admin/management-keys/{mk}/devices/{r_d}"),
            Some(&r_t),
            None,
        )
        .await;
        assert_refused_not_banned(&state.pool, &r_d, s, &b).await;
        for (d, t) in [(&free_d, &free_t), (&r_d, &admin)] {
            let (s, b) = call(
                &app,
                "GET",
                &format!("/api/admin/management-keys/{mk}/devices/{d}"),
                Some(t),
                None,
            )
            .await;
            assert_eq!(s, 200, "{b}");
        }
    }

    /// A restricted device can't revoke management keys or change their defaults (it could
    /// otherwise cut off or redirect the provider keys every other consumer relies on).
    #[tokio::test]
    async fn management_key_mutations_refused_for_restricted_device() {
        let (app, state, admin, _device_id, _dt) = fixture().await;
        let (r_d, r_t) = restricted_device(&app, &state.pool, &admin, &["FOO"]).await;
        let mk = seed_management_key(&state.pool, &[&r_d]).await;

        let (s, b) = call(
            &app,
            "PATCH",
            &format!("/api/admin/management-keys/{mk}"),
            Some(&r_t),
            Some(serde_json::json!({ "default_limit": 1.0 })),
        )
        .await;
        assert_refused_not_banned(&state.pool, &r_d, s, &b).await;
        let (s, b) = call(
            &app,
            "POST",
            &format!("/api/admin/management-keys/{mk}/revoke"),
            Some(&r_t),
            None,
        )
        .await;
        assert_refused_not_banned(&state.pool, &r_d, s, &b).await;
        let status: String = sqlx::query_scalar("SELECT status FROM management_keys WHERE id = ?")
            .bind(&mk)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(status, "active");

        // The non-device admin session still can.
        let (s, b) = call(
            &app,
            "POST",
            &format!("/api/admin/management-keys/{mk}/revoke"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");
    }

    /// M3: a non-device caller (e.g. kv_cli with an approval token minted from a non-device
    /// session) fetching a device-encrypted envelope for path device D gets D's ban and policy
    /// applied as a plain refusal — it never records a ban (a path parameter can't ban).
    #[tokio::test]
    async fn device_kv_non_device_caller_checks_path_device() {
        let (app, state, admin, _device_id, _dt) = fixture().await;
        let d = insert_device(&state.pool, "cli-host").await;
        for k in ["FOO", "OTHER_KEY"] {
            sqlx::query(
                "INSERT INTO device_kv_bodies (kv_key, owner_id, nonce, ciphertext, aad) VALUES (?, ?, 'n', 'c', 'a')",
            )
            .bind(k)
            .bind(TEST_OWNER)
            .execute(&state.pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO device_kv_recipients (id, kv_key, owner_id, device_id, key_type, ephemeral_pub, dek_nonce, encrypted_dek)
                 VALUES (?, ?, ?, ?, 'x25519', 'e', 'n', 'k')",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(k)
            .bind(TEST_OWNER)
            .bind(&d)
            .execute(&state.pool)
            .await
            .unwrap();
        }
        let path = |k: &str| format!("/api/devices/{d}/kv/{k}");
        let (s, _) = call(&app, "GET", &path("OTHER_KEY"), Some(&admin), None).await;
        assert_eq!(s, 200, "allow_all path device");

        restrict(&app, &admin, &d, &["FOO"]).await;
        let (s, b) = call(&app, "GET", &path("FOO"), Some(&admin), None).await;
        assert_eq!(s, 200, "{b}");
        let (s, b) = call(&app, "GET", &path("OTHER_KEY"), Some(&admin), None).await;
        assert_refused_not_banned(&state.pool, &d, s, &b).await;

        ban_now(&state.pool, &d).await;
        let (s, b) = call(&app, "GET", &path("FOO"), Some(&admin), None).await;
        assert_banned(s, &b);
        assert_eq!(
            ban_row(&state.pool, &d).await.unwrap().1,
            1,
            "no escalation"
        );
    }

    // ── Races / housekeeping ────────────────────────────────────────────────────

    #[tokio::test]
    async fn concurrent_violations_ban_exactly_once() {
        let path = std::env::temp_dir().join(format!("kv-race-{}.db", Uuid::new_v4()));
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .unwrap();
        let (app, state) = build_policy_app_with_pool(pool).await;
        seed_kv(
            &state.pool,
            &["FOO", "A", "B", "C", "D", "E", "F", "G", "H"],
        )
        .await;
        let admin = insert_session_key(&state.pool, "active", None).await;
        let (d, t) = restricted_device(&app, &state.pool, &admin, &["FOO"]).await;

        let mut set = tokio::task::JoinSet::new();
        for k in ["A", "B", "C", "D", "E", "F", "G", "H"] {
            let app = app.clone();
            let t = t.clone();
            set.spawn(async move { call(&app, "GET", &format!("/kv/{k}"), Some(&t), None).await });
        }
        while let Some(r) = set.join_next().await {
            let (s, b) = r.unwrap();
            assert_banned(s, &b);
        }
        assert_eq!(
            ban_row(&state.pool, &d).await.unwrap().1,
            1,
            "escalated more than once"
        );
        state.pool.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn ttl_cleanup_clears_expired_bans_keeping_count() {
        let (_app, state, _admin, expired_d, _dt) = fixture().await;
        let active_d = insert_device(&state.pool, "still-banned").await;
        sqlx::query(
            "INSERT INTO device_bans (device_id, owner_id, banned_at, unban_at, ban_count, last_key)
             VALUES (?, ?, datetime('now', '-2 hours'), datetime('now', '-1 second'), 3, 'K1'),
                    (?, ?, datetime('now'), datetime('now', '+1 hour'), 2, 'K2')",
        )
        .bind(&expired_d)
        .bind(TEST_OWNER)
        .bind(&active_d)
        .bind(TEST_OWNER)
        .execute(&state.pool)
        .await
        .unwrap();

        crate::tasks::ttl_cleanup::cleanup(&state.pool)
            .await
            .unwrap();

        let row = |d: String| {
            let pool = state.pool.clone();
            async move {
                sqlx::query_as::<_, (Option<String>, Option<String>, i64, Option<String>)>(
                    "SELECT banned_at, unban_at, ban_count, last_key FROM device_bans WHERE device_id = ?",
                )
                .bind(d)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let (banned_at, unban_at, count, last_key) = row(expired_d.clone()).await;
        assert!(banned_at.is_none() && unban_at.is_none());
        assert_eq!((count, last_key.as_deref()), (3, Some("K1")));
        let (banned_at, unban_at, count, _) = row(active_d.clone()).await;
        assert!(banned_at.is_some() && unban_at.is_some());
        assert_eq!(count, 2);
    }

    // ── secrev2: owner lockout, secret requests, listings ────────────────────

    fn assert_device_forbidden(status: u16, body: &str) {
        assert_eq!(status, 403, "body: {body}");
        assert!(body.contains("not permitted for this device"), "{body}");
    }

    async fn insert_key_for_device(
        pool: &SqlitePool,
        device_id: Option<&str>,
        status: &str,
    ) -> String {
        let (_plaintext, hash) = generate_api_key();
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, label, type, status, owner_id, device_id)
             VALUES (?, ?, 'k', 'standard', ?, ?, ?)",
        )
        .bind(&id)
        .bind(&hash)
        .bind(status)
        .bind(TEST_OWNER)
        .bind(device_id)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    /// A restricted device can list keys but cannot revoke/delete the owner's credentials
    /// (no lockout); it may still revoke/delete keys attributed to itself. An allow_all
    /// device keeps full behaviour.
    #[tokio::test]
    async fn secrev2_restricted_device_cannot_revoke_admin_credentials() {
        let (app, state, admin, d, dt) = fixture().await;
        restrict(&app, &admin, &d, &["FOO"]).await;
        let (s, b) = call(&app, "GET", "/api/admin/keys", Some(&dt), None).await;
        assert_eq!(s, 200, "{b}");
        let ids: Vec<String> = json(&b)
            .as_array()
            .unwrap()
            .iter()
            .filter(|k| k["label"] == "test-session")
            .map(|k| k["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids.len(), 1);
        let (s, b) = call(
            &app,
            "POST",
            &format!("/api/admin/keys/{}/revoke", ids[0]),
            Some(&dt),
            None,
        )
        .await;
        assert_device_forbidden(s, &b);
        // Unknown id: same 403 (no existence oracle).
        let (s, b) = call(&app, "POST", "/api/admin/keys/nope/revoke", Some(&dt), None).await;
        assert_device_forbidden(s, &b);
        // Deleting another (revoked) key: refused too.
        let revoked_admin = insert_key_for_device(&state.pool, None, "revoked").await;
        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/keys/{revoked_admin}"),
            Some(&dt),
            None,
        )
        .await;
        assert_device_forbidden(s, &b);
        // The owner is not locked out.
        let (s, _) = call(
            &app,
            "GET",
            "/api/admin/device-policies",
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 200, "admin must keep access");
        assert!(ban_row(&state.pool, &d).await.is_none(), "403 is not a ban");

        // Own keys: allowed.
        let own = insert_key_for_device(&state.pool, Some(&d), "active").await;
        let (s, b) = call(
            &app,
            "POST",
            &format!("/api/admin/keys/{own}/revoke"),
            Some(&dt),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");
        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/keys/{own}"),
            Some(&dt),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");

        // allow_all device: unchanged, may revoke and delete a non-device key.
        let free = insert_device(&state.pool, "free").await;
        let free_tok = insert_device_session(&state.pool, &free).await;
        let other = insert_key_for_device(&state.pool, None, "active").await;
        let (s, b) = call(
            &app,
            "POST",
            &format!("/api/admin/keys/{other}/revoke"),
            Some(&free_tok),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");
        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/keys/{other}"),
            Some(&free_tok),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");
    }

    /// A restricted device cannot delete another device; an allow_all device still can.
    #[tokio::test]
    async fn secrev2_restricted_device_cannot_delete_other_device() {
        let (app, state, admin, d, dt) = fixture().await;
        restrict(&app, &admin, &d, &["FOO"]).await;
        let other = insert_device(&state.pool, "owner-phone").await;
        let other_tok = insert_device_session(&state.pool, &other).await;
        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/devices/{other}"),
            Some(&dt),
            None,
        )
        .await;
        assert_device_forbidden(s, &b);
        let (s, _) = call(
            &app,
            "GET",
            "/api/admin/session/whoami",
            Some(&other_tok),
            None,
        )
        .await;
        assert_eq!(s, 200);
        assert!(ban_row(&state.pool, &d).await.is_none());

        // Unrestricted device: unchanged.
        let free = insert_device(&state.pool, "free").await;
        let free_tok = insert_device_session(&state.pool, &free).await;
        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/devices/{other}"),
            Some(&free_tok),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");
        let (s, _) = call(
            &app,
            "GET",
            "/api/admin/session/whoami",
            Some(&other_tok),
            None,
        )
        .await;
        assert_eq!(s, 401);
    }

    /// A restricted device cannot create (or revoke/delete) a secret-request link, so it
    /// can't use the public collect endpoint to write a name its policy forbids.
    #[tokio::test]
    async fn secrev2_secret_request_refused_for_restricted_device() {
        let (app, state, admin, d, dt) = fixture().await;
        restrict(&app, &admin, &d, &["FOO"]).await;
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/secret-requests",
            Some(&dt),
            Some(serde_json::json!({"description": "x", "key_prefix": "OPENROUTER_"})),
        )
        .await;
        assert_device_forbidden(s, &b);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secret_requests")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(kv_value(&state.pool, "OPENROUTER_EVIL").await, None);

        // Owner-created request: the restricted device can neither revoke nor delete it.
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/secret-requests",
            Some(&admin),
            Some(serde_json::json!({"description": "x"})),
        )
        .await;
        assert_eq!(s, 201, "{b}");
        let id = json(&b)["id"].as_str().unwrap().to_string();
        let (s, b) = call(
            &app,
            "POST",
            &format!("/api/admin/secret-requests/{id}/revoke"),
            Some(&dt),
            None,
        )
        .await;
        assert_device_forbidden(s, &b);
        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/secret-requests/{id}"),
            Some(&dt),
            None,
        )
        .await;
        assert_device_forbidden(s, &b);
        assert!(ban_row(&state.pool, &d).await.is_none());

        // allow_all device: unchanged.
        let free = insert_device(&state.pool, "free").await;
        let free_tok = insert_device_session(&state.pool, &free).await;
        let (s, b) = call(
            &app,
            "POST",
            &format!("/api/admin/secret-requests/{id}/revoke"),
            Some(&free_tok),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/secret-requests",
            Some(&free_tok),
            Some(serde_json::json!({"description": "y"})),
        )
        .await;
        assert_eq!(s, 201, "{b}");
    }

    /// Secret-request and faux-approval listings hide names a restricted device's policy
    /// refuses (never a ban); non-device callers see everything.
    #[tokio::test]
    async fn secrev2_secret_request_listings_filtered() {
        let (app, state, admin, d, dt) = fixture().await;
        restrict(&app, &admin, &d, &["FOO"]).await;
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/secret-requests",
            Some(&admin),
            Some(
                serde_json::json!({"description": "x", "required_keys": ["SECRET_PROD_DB", "FOO"]}),
            ),
        )
        .await;
        assert_eq!(s, 201, "{b}");
        let sr = json(&b)["id"].as_str().unwrap().to_string();
        let (s, b) = call(&app, "POST", "/api/admin/secret-requests", Some(&admin),
            Some(serde_json::json!({"description": "p", "key_prefix": "HIDDEN_NS_", "required_keys": ["FOO"]}))).await;
        assert_eq!(s, 201, "{b}");
        for (msg, id) in [
            ("Recipient bypassed required key 'SECRET_PROD_DB'", "fa1"),
            (
                "Recipient bypassed required key 'FOO' — note: \"later 'SECRET_X'\"",
                "fa2",
            ),
            ("something unparseable SECRET_Y", "fa3"),
        ] {
            sqlx::query("INSERT INTO faux_approvals (id, owner_id, secret_request_id, message) VALUES (?, ?, ?, ?)")
                .bind(id).bind(TEST_OWNER).bind(&sr).bind(msg)
                .execute(&state.pool).await.unwrap();
        }

        let (s, b) = call(&app, "GET", "/api/admin/secret-requests", Some(&dt), None).await;
        assert_eq!(s, 200);
        assert!(!b.contains("SECRET_PROD_DB"), "{b}");
        assert!(!b.contains("HIDDEN_NS_"), "{b}");
        let rows = json(&b);
        let first = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["description"] == "x")
            .unwrap();
        assert_eq!(first["required_keys"], "[\"FOO\"]");
        // FOO under prefix HIDDEN_NS_ would be stored as HIDDEN_NS_FOO, which isn't allowed.
        let second = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["description"] == "p")
            .unwrap();
        assert_eq!(second["required_keys"], "[]");
        assert!(second["key_prefix"].is_null());

        let (s, b) = call(&app, "GET", "/api/admin/faux-approvals", Some(&dt), None).await;
        assert_eq!(s, 200);
        let ids: Vec<String> = json(&b)
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, vec!["fa2".to_string()], "{b}");
        assert!(ban_row(&state.pool, &d).await.is_none());

        // Non-device caller: unfiltered.
        let (_, b) = call(
            &app,
            "GET",
            "/api/admin/secret-requests",
            Some(&admin),
            None,
        )
        .await;
        assert!(
            b.contains("SECRET_PROD_DB") && b.contains("HIDDEN_NS_"),
            "{b}"
        );
        let (_, b) = call(&app, "GET", "/api/admin/faux-approvals", Some(&admin), None).await;
        assert_eq!(json(&b).as_array().unwrap().len(), 3);
    }

    /// Restricted device logout revokes only its own token; an unrestricted caller's logout
    /// still revokes every owner session.
    #[tokio::test]
    async fn secrev2_restricted_device_logout_revokes_only_itself() {
        let (app, state, admin, d, dt) = fixture().await;
        restrict(&app, &admin, &d, &["FOO"]).await;
        let other = insert_device(&state.pool, "phone").await;
        let other_tok = insert_device_session(&state.pool, &other).await;
        let (s, _) = call(&app, "POST", "/api/admin/session/logout", Some(&dt), None).await;
        assert_eq!(s, 303);
        let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(&dt), None).await;
        assert_eq!(s, 401, "caller's own token revoked");
        for t in [&admin, &other_tok] {
            let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(t), None).await;
            assert_eq!(s, 200, "other sessions survive");
        }
        // Unrestricted (allow_all) device: unchanged — all owner sessions revoked.
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/session/logout",
            Some(&other_tok),
            None,
        )
        .await;
        assert_eq!(s, 303);
        let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(&admin), None).await;
        assert_eq!(s, 401);
    }

    /// Every other credential/device-revoking or approving route is fenced for restricted
    /// devices (plain 403, no ban) and unchanged for the owner.
    #[tokio::test]
    async fn secrev2_restricted_device_fenced_routes() {
        let (app, state, admin, d, dt) = fixture().await;
        restrict(&app, &admin, &d, &["FOO"]).await;
        let calls: Vec<(&str, &str, Option<serde_json::Value>)> = vec![
            ("DELETE", "/api/admin/keys/revoked-sessions", None),
            (
                "POST",
                "/api/admin/approvals/x/approve",
                Some(serde_json::json!({"confirm": "x"})),
            ),
            ("POST", "/api/admin/approvals/x/reject", None),
            ("DELETE", "/api/admin/blocked-ips/203.0.113.9", None),
            ("POST", "/api/admin/device-proposals/x/reject", None),
            ("POST", "/api/admin/session-requests/x/reject", None),
            ("DELETE", "/api/admin/faux-approvals/x", None),
        ];
        for (m, path, body) in &calls {
            let (s, b) = call(&app, m, path, Some(&dt), body.clone()).await;
            assert_device_forbidden(s, &format!("{m} {path}: {b}"));
        }
        assert!(ban_row(&state.pool, &d).await.is_none());
        let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(&dt), None).await;
        assert_eq!(s, 200, "no ban, device still works");
        // Owner: unchanged (not 403).
        for (m, path, body) in &calls {
            let (s, b) = call(&app, m, path, Some(&admin), body.clone()).await;
            assert_ne!(s, 403, "{m} {path}: {b}");
        }
    }

    /// H1 regression: one-time key minted by a (then allow_all) device, device later banned:
    /// refused before consumption; after unban it still works once.
    #[tokio::test]
    async fn secrev2_one_time_key_not_consumed_while_banned() {
        let (app, state, admin, d, dt) = fixture().await;
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/keys",
            Some(&dt),
            Some(
                serde_json::json!({"label": "ot", "key_type": "one_time", "allowed_keys": ["FOO"]}),
            ),
        )
        .await;
        assert_eq!(s, 201, "{b}");
        let key = json(&b)["key"].as_str().unwrap().to_string();
        ban_now(&state.pool, &d).await;
        let resp = app
            .clone()
            .oneshot(get_req("/kv/FOO", None, Some(key.clone())))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403);
        let (s, _) = call(
            &app,
            "DELETE",
            &format!("/api/admin/device-policies/{d}/ban"),
            Some(&admin),
            None,
        )
        .await;
        assert!(s == 204 || s == 200, "unban {s}");
        let resp = app
            .clone()
            .oneshot(get_req("/kv/FOO", None, Some(key)))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
    }

    /// C2 regression: deleting a device that minted keys with allowlists + approval
    /// requests works, and leaves other devices' / non-device keys alone.
    #[tokio::test]
    async fn secrev2_delete_device_with_minted_dependents() {
        let (app, state, admin, d, dt) = fixture().await;
        let other = insert_device(&state.pool, "other").await;
        let other_tok = insert_device_session(&state.pool, &other).await;
        let (s, b) = call(&app, "POST", "/api/admin/keys", Some(&dt),
            Some(serde_json::json!({"label": "ar", "key_type": "approval_required", "allowed_keys": ["FOO"]}))).await;
        assert_eq!(s, 201, "{b}");
        let ar_id = json(&b)["id"].as_str().unwrap().to_string();
        let _ = call(
            &app,
            "POST",
            &format!("/api/admin/keys/{ar_id}/request-approval"),
            None,
            None,
        )
        .await;
        let (s, b) = call(
            &app,
            "POST",
            "/api/admin/session/cli-token",
            Some(&dt),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(s, 200, "{b}");
        let cli: String = serde_json::from_str(&b).unwrap();
        let (s, b) = call(
            &app,
            "DELETE",
            &format!("/api/admin/devices/{d}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(s, 204, "{b}");
        for t in [&dt, &cli] {
            let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(t), None).await;
            assert_eq!(s, 401);
        }
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE device_id IS NULL AND id != ?")
                .bind(&ar_id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert!(n >= 1, "admin key survived");
        let (s, _) = call(
            &app,
            "GET",
            "/api/admin/session/whoami",
            Some(&other_tok),
            None,
        )
        .await;
        assert_eq!(s, 200);
        let (s, _) = call(&app, "GET", "/api/admin/session/whoami", Some(&admin), None).await;
        assert_eq!(s, 200);
    }
}
