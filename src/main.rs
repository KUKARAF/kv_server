mod admin;
mod auth;
mod config;
mod db;
mod error;
mod keys;
mod kv;
mod middleware;
mod state;
mod tasks;

use anyhow::Result;
use axum::{
    body::Body,
    http::{Response, StatusCode},
    middleware as axum_middleware,
    routing::get,
    Router,
};
use include_dir::{include_dir, Dir};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static ADMIN_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/admin");

#[tokio::main]
async fn main() -> Result<()> {
    let use_json = std::env::var("LOG_FORMAT").as_deref() == Ok("json");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "kv_manager=info".into());

    if use_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    let config = config::Config::from_env()?;
    let pool = db::create_pool(&config.database_url).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    let oidc_client = auth::oidc::init_client(
        &config.oidc_issuer_url,
        &config.oidc_client_id,
        &config.oidc_client_secret,
        &config.oidc_redirect_uri,
    )
    .await
    .map_err(|e| {
        tracing::warn!("OIDC init failed (admin login disabled): {e:#}");
    })
    .ok();

    let state = state::AppState::new(pool, config.clone(), oidc_client);

    // Spawn background tasks
    tokio::spawn(tasks::ttl_cleanup::run(
        Arc::clone(&state).pool.clone(),
        config.ttl_cleanup_interval_secs,
    ));
    tokio::spawn(tasks::rate_limit_reset::run(Arc::clone(&state)));

    let app = Router::new()
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .nest("/kv", kv::router())
        .nest("/auth", auth::router())
        .nest("/api/admin", admin::router())
        .route("/admin/", get(serve_dashboard))
        .route("/admin/{*path}", get(serve_admin_static))
        .route("/", get(serve_index))
        .layer(axum_middleware::from_fn_with_state(
            Arc::clone(&state),
            middleware::rate_limit::layer,
        ))
        .with_state(Arc::clone(&state));

    let listener = TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("listening on {}", config.listen_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn healthz(
    axum::extract::State(state): axum::extract::State<Arc<state::AppState>>,
) -> Response<Body> {
    match sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(&state.pool).await {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"status":"ok"}"#))
            .unwrap(),
        Err(e) => {
            tracing::error!("health check DB error: {e}");
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"status":"degraded","reason":"db unreachable"}"#))
                .unwrap()
        }
    }
}

async fn version() -> &'static str {
    env!("APP_VERSION")
}

async fn serve_index() -> Response<Body> {
    serve_file("index.html", "text/html")
}

async fn serve_dashboard() -> Response<Body> {
    serve_file("dashboard.html", "text/html")
}

async fn serve_admin_static(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response<Body> {
    let mime = if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else {
        "text/html"
    };
    serve_file(&path, mime)
}

fn serve_file(path: &str, content_type: &str) -> Response<Body> {
    match ADMIN_DIR.get_file(path) {
        Some(file) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .body(Body::from(file.contents()))
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap(),
    }
}
