use crate::{config::Config, devices, keys::generate::generate_api_key, kv, middleware, state::AppState};
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
#[case(2,  "/kv/protected-key", Cred::BearerUnknown,  false, true )]
#[case(3,  "/kv/protected-key", Cred::BearerValid,    false, false)]
#[case(4,  "/kv/protected-key", Cred::BearerExpired,  false, true )]
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
/// Unauthenticated requests are redirected (303) to the error page.
/// Authenticated requests reach the handler and return the expected status.
#[rstest]
// ── unauthenticated → 303 redirect ──────────────────────────────────────────
#[case("POST",   "/api/devices",                   Some(r#"{"name":"t","public_key":"dGVzdA=="}"#), false, 303)]
#[case("GET",    "/api/admin/devices",             None,                                             false, 303)]
#[case("DELETE", "/api/admin/devices/nonexistent", None,                                             false, 303)]
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
