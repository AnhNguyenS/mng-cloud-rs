#![forbid(unsafe_code)]

//! Native edge service for MNG Cloud.
//!
//! The service serves the immutable PWA, health probes, session authentication
//! and read-only library APIs. Mutations and the Seafile E2EE bridge are added
//! in later slices; the PHP application remains the only database writer.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::Context;
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderName, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use mng_core::config::Config;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod auth;
mod db;
mod http;
mod rbac;
mod read;

use auth::AuthState;
use db::DatabaseState;

/// Enforced for the new immutable app. The legacy PHP UI keeps its own,
/// report-only policy until it is retired.
const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types mng-ui;";

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    started: Instant,
    db: DatabaseState,
    auth: AuthState,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = config_path();
    let config = Config::load(config_path.as_deref()).context("load mngd configuration")?;
    init_tracing(&config.log_filter);
    let db = DatabaseState::load(&config);
    let auth = AuthState::load(&config, db.clone());

    let state = AppState {
        config: Arc::new(config),
        started: Instant::now(),
        db,
        auth,
    };

    let address: SocketAddr = state
        .config
        .bind
        .parse()
        .with_context(|| format!("invalid bind address: {}", state.config.bind))?;

    tracing::info!(
        %address,
        web_root = %state.config.web_root.display(),
        data_dir = %state.config.data_dir.display(),
        database = %state.db.path.display(),
        database_mode = state.db.mode_name(),
        auth_available = state.auth.available(),
        version = env!("CARGO_PKG_VERSION"),
        "mngd starting"
    );

    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind {address}"))?;
    axum::serve(
        listener,
        router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("serve HTTP")?;
    Ok(())
}

fn router(state: AppState) -> Router {
    let static_files =
        ServeDir::new(state.config.web_root.clone()).append_index_html_on_directories(true);

    let admin_api = Router::new()
        .route("/users", get(read::admin_users))
        .route("/users/{id}", get(read::admin_user))
        .layer(middleware::from_fn(rbac::require_admin));

    let protected_api = Router::new()
        .route("/v1/auth/me", get(auth::me))
        .route("/v1/auth/logout", axum::routing::post(auth::logout))
        .route("/v1/bootstrap", get(read::bootstrap))
        .route("/v1/clouds", get(read::clouds))
        .route("/v1/counts", get(read::counts))
        .route("/v1/items", get(read::items))
        .route("/v1/items/{id}", get(read::item))
        .route("/v1/years", get(read::years))
        .route("/v1/months", get(read::months))
        .route("/v1/albums", get(read::albums))
        .route("/v1/stats", get(read::stats))
        .nest("/v1/admin", admin_api)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));
    let api = auth::api_layers(
        Router::new()
            .route("/v1/auth/login", axum::routing::post(auth::login))
            .merge(protected_api),
    );

    Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/health", get(health))
        .route("/readyz", get(ready))
        .nest("/api", api)
        .nest_service("/app", static_files)
        .fallback(not_found)
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http())
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "mngd",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_s": state.started.elapsed().as_secs(),
    }))
}

async fn ready(State(state): State<AppState>) -> Response {
    let web_root = tokio::fs::metadata(&state.config.web_root)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false);
    let data_dir = tokio::fs::metadata(&state.config.data_dir)
        .await
        .map(|meta| meta.is_dir())
        .unwrap_or(false);

    let (probe, db_error) = match state.db.database.clone() {
        Some(database) => match tokio::task::spawn_blocking(move || database.probe()).await {
            Ok(Ok(probe)) => (Some(probe), None),
            Ok(Err(error)) => (None, Some(error.to_string())),
            Err(error) => (None, Some(format!("database probe task failed: {error}"))),
        },
        None => (None, state.db.startup_error.clone()),
    };
    let db_available = probe.is_some();
    let auth_available = state.auth.available();
    let ready = web_root && data_dir;
    let status = if !ready {
        "not_ready"
    } else if db_available && auth_available {
        "ready"
    } else {
        "degraded"
    };
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "status": status,
            "web_root": web_root,
            "data_dir": data_dir,
            "database": {
                "path": state.db.path.display().to_string(),
                "mode": state.db.mode_name(),
                "available": db_available,
                "schema_version": probe.map(|probe| probe.schema_version),
                "users": probe.map(|probe| probe.users),
                "error": db_error,
            },
            "auth": {
                "available": auth_available,
                "error": state.auth.error(),
            },
        })),
    )
        .into_response()
}

async fn not_found(request: Request<Body>) -> Response {
    if request.uri().path().starts_with("/api/") {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
    } else {
        (StatusCode::NOT_FOUND, "not found").into_response()
    }
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );

    // App URLs are stable across releases (the service worker provides the
    // immutable cache after a verified install), so the network copy must
    // always be revalidated. This prevents a new app.js from being masked by a
    // stale year-long browser cache during an update.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    response
}

fn init_tracing(filter: &str) {
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn config_path() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = arg
            .to_str()
            .and_then(|value| value.strip_prefix("--config="))
        {
            return Some(PathBuf::from(value));
        }
    }
    if let Some(path) = std::env::var_os("MNGD_CONFIG") {
        return Some(PathBuf::from(path));
    }
    let default = PathBuf::from("/etc/mng-cloud/mngd.toml");
    default.is_file().then_some(default)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
