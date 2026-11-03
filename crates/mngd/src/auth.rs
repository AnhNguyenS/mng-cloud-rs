//! Session authentication for `/api/v1/*`.
//!
//! Credentials are checked against the legacy SQLite `users` row (bcrypt or
//! Argon2). Sessions are stateless HMAC-signed cookies from `mng-auth`, so a
//! restart only invalidates tokens if the operator rotates the secret. The
//! database remains read-only: `last_login_at` is not written.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::{rejection::JsonRejection, ConnectInfo, DefaultBodyLimit, Extension, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use mng_auth::{
    dummy_verify, load_secret, unix_now, verify_password, RateLimiter, Session, SessionConfig,
};
use mng_core::config::Config;
use mng_db::{user_by_id, user_by_username, User};
use serde::Deserialize;
use serde_json::json;

use crate::{db::DatabaseState, http::json_error, AppState};

/// Marker inserted by [`require_session`] after the cookie signature, lifetime,
/// CSRF token and fresh `users` row have been checked.
#[derive(Clone)]
pub struct AuthenticatedUser {
    pub session: Session,
    pub user: User,
}

struct AuthInner {
    session: Option<SessionConfig>,
    limiter: RateLimiter,
    db: DatabaseState,
    error: Option<String>,
}

/// Shared authentication state. Kept separate from `AppState` so tests can
/// build it with an explicit secret instead of touching the filesystem.
#[derive(Clone)]
pub struct AuthState {
    inner: Arc<AuthInner>,
}

impl AuthState {
    pub fn load(config: &Config, db: DatabaseState) -> Self {
        let (secret, mut error) = resolve_secret(config);
        let session = match secret {
            Some(secret) => match SessionConfig::new(
                &secret,
                config.session_ttl_secs,
                config.session_cookie.clone(),
                config.session_cookie_secure,
            ) {
                Ok(session) => Some(session),
                Err(source) => {
                    error = Some(format!("session configuration is invalid: {source}"));
                    None
                }
            },
            None => None,
        };
        if let Some(message) = &error {
            tracing::warn!(error = %message, "authentication is not configured");
        }
        Self::build(config, db, session, error)
    }

    fn build(
        config: &Config,
        db: DatabaseState,
        session: Option<SessionConfig>,
        error: Option<String>,
    ) -> Self {
        Self {
            inner: Arc::new(AuthInner {
                session,
                limiter: RateLimiter::new(
                    config.login_max_attempts,
                    Duration::from_secs(config.login_window_secs),
                ),
                db,
                error,
            }),
        }
    }

    pub fn available(&self) -> bool {
        self.inner.session.is_some()
    }

    pub fn error(&self) -> Option<&str> {
        self.inner.error.as_deref()
    }

    fn session(&self) -> Option<&SessionConfig> {
        self.inner.session.as_ref()
    }
}

fn resolve_secret(config: &Config) -> (Option<Vec<u8>>, Option<String>) {
    if let Ok(value) = std::env::var("MNGD_SESSION_SECRET") {
        // Environment injection wins so a process manager can keep the secret
        // out of the filesystem entirely.
        return (Some(value.trim().as_bytes().to_vec()), None);
    }
    let path = std::env::var_os("MNGD_SESSION_SECRET_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| config.session_key_file.clone());
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => match load_secret(&path) {
            Ok(secret) => (Some(secret), None),
            Err(source) => (
                None,
                Some(format!(
                    "cannot read session secret {}: {source}",
                    path.display()
                )),
            ),
        },
        Ok(_) => (
            None,
            Some(format!(
                "session secret path is not a file: {}",
                path.display()
            )),
        ),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => (
            None,
            Some(format!(
                "session secret is not configured: set MNGD_SESSION_SECRET or create {}",
                path.display()
            )),
        ),
        Err(source) => (
            None,
            Some(format!(
                "cannot read session secret {}: {source}",
                path.display()
            )),
        ),
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Require a valid session cookie for every protected API route and enforce a
/// matching `X-CSRF-Token` on state-changing requests.
pub async fn require_session(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(session_config) = state.auth.session() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth_unavailable",
            Some("Dịch vụ đăng nhập chưa được cấu hình.".to_owned()),
        );
    };
    let Some(token) = cookie_value(request.headers(), &session_config.cookie().name) else {
        return auth_required();
    };
    let session = match session_config.verify(&token, unix_now()) {
        Ok(session) => session,
        Err(_) => return auth_required(),
    };

    let method = request.method().clone();
    if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        let token = request
            .headers()
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !session.csrf_matches(token) {
            return json_error(StatusCode::FORBIDDEN, "csrf", None);
        }
    }

    // Re-read the account on every request. The cookie carries identity, not
    // privileges: deactivation and role changes in the snapshot take effect
    // immediately instead of lasting until the session expires.
    let user = match load_user(&state, session.uid).await {
        Ok(Some(user)) if user.active => user,
        Ok(Some(_)) | Ok(None) => {
            tracing::info!(uid = session.uid, "session user is no longer active");
            return clear_session_cookie(&state, auth_required());
        }
        Err(()) => {
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                None,
            )
        }
    };

    let mut request = request;
    request
        .extensions_mut()
        .insert(AuthenticatedUser { session, user });
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginRequest {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Response {
    let Some(session_config) = state.auth.session().cloned() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth_unavailable",
            Some("Dịch vụ đăng nhập chưa được cấu hình.".to_owned()),
        );
    };
    let Json(payload) = match payload {
        Ok(payload) => payload,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("Dữ liệu đăng nhập không hợp lệ.".to_owned()),
            )
        }
    };

    let username = normalize_username(&payload.username);
    if username.is_empty()
        || username.len() > 128
        || payload.password.is_empty()
        || payload.password.len() > 1024
    {
        return bad_credentials();
    }

    let ip = client_ip(peer, &headers);
    let ip_key = format!("ip:{ip}");
    let user_key = format!("ip:{ip}|user:{username}");
    for key in [&ip_key, &user_key] {
        let decision = state.auth.inner.limiter.try_acquire(key);
        if !decision.allowed {
            return rate_limited(decision.retry_after);
        }
    }

    let Some(database) = state.auth.inner.db.database.clone() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            Some("Cơ sở dữ liệu người dùng chưa sẵn sàng.".to_owned()),
        );
    };

    let password = payload.password;
    let lookup_name = username.clone();
    let result =
        tokio::task::spawn_blocking(move || -> Result<Option<User>, mng_db::read::Error> {
            let conn = database.connect()?;
            let user = user_by_username(&conn, &lookup_name)?;
            let Some(user) = user else {
                dummy_verify(&password);
                return Ok(None);
            };
            let verified = match verify_password(&user.password_hash, &password) {
                Ok(verified) => verified,
                Err(error) => {
                    tracing::warn!(
                        username = %user.username,
                        error = %error,
                        "stored password hash is not supported"
                    );
                    false
                }
            };
            if verified && user.active {
                Ok(Some(user))
            } else {
                Ok(None)
            }
        })
        .await;

    let user = match result {
        Ok(Ok(Some(user))) => user,
        Ok(Ok(None)) => {
            tracing::info!(ip = %ip, username = %username, "login rejected");
            return bad_credentials();
        }
        Ok(Err(error)) => {
            tracing::error!(ip = %ip, error = %error, "login database lookup failed");
            return json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                None,
            );
        }
        Err(error) => {
            tracing::error!(ip = %ip, error = %error, "login verification task failed");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", None);
        }
    };

    let now = unix_now();
    let (session, token) = match session_config.issue(user.id, &user.username, now) {
        Ok(issued) => issued,
        Err(error) => {
            tracing::error!(error = %error, "cannot issue session");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", None);
        }
    };

    state.auth.inner.limiter.reset(&ip_key);
    state.auth.inner.limiter.reset(&user_key);
    tracing::info!(ip = %ip, username = %user.username, uid = user.id, "login succeeded");

    let mut response = Json(json!({
        "ok": true,
        "csrf": session.csrf,
        "expires_at": session.exp,
        "me": user.public(),
    }))
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&session_config.cookie_header(&token)) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

pub async fn me(Extension(authenticated): Extension<AuthenticatedUser>) -> Response {
    let AuthenticatedUser { session, user } = authenticated;
    Json(json!({
        "ok": true,
        "csrf": session.csrf,
        "expires_at": session.exp,
        "me": user.public(),
    }))
    .into_response()
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(_authenticated): Extension<AuthenticatedUser>,
) -> Response {
    clear_session_cookie(&state, Json(json!({ "ok": true })).into_response())
}

async fn load_user(state: &AppState, uid: i64) -> Result<Option<User>, ()> {
    let Some(database) = state.auth.inner.db.database.clone() else {
        return Err(());
    };
    match tokio::task::spawn_blocking(move || {
        let conn = database.connect()?;
        user_by_id(&conn, uid)
    })
    .await
    {
        Ok(Ok(user)) => Ok(user),
        Ok(Err(error)) => {
            tracing::error!(uid, error = %error, "session user lookup failed");
            Err(())
        }
        Err(error) => {
            tracing::error!(uid, error = %error, "session user task failed");
            Err(())
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn normalize_username(username: &str) -> String {
    // Mirrors the PHP layer's `strtolower(trim($username))`.
    username.trim().to_ascii_lowercase()
}

fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    // Only honour forwarding headers from a local reverse proxy. nginx appends
    // the address it saw, so the right-most entry is the one we can trust.
    if peer.ip().is_loopback() {
        if let Some(value) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        {
            if let Some(ip) = value
                .split(',')
                .rev()
                .find_map(|part| part.trim().parse::<IpAddr>().ok())
            {
                return ip;
            }
        }
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for header in headers.get_all(header::COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for part in text.split(';') {
            if let Some((key, value)) = part.split_once('=') {
                if key.trim() == name {
                    let value = value.trim();
                    if !value.is_empty() {
                        return Some(value.to_owned());
                    }
                }
            }
        }
    }
    None
}

fn clear_session_cookie(state: &AppState, mut response: Response) -> Response {
    if let Some(session) = state.auth.session() {
        if let Ok(value) = HeaderValue::from_str(&session.clear_cookie_header()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

fn auth_required() -> Response {
    let mut body = json!({ "ok": false, "error": "auth_required", "login": true });
    body["message"] = json!("Phiên đăng nhập đã hết hạn.");
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

fn bad_credentials() -> Response {
    json_error(
        StatusCode::UNAUTHORIZED,
        "bad_credentials",
        Some("Tên đăng nhập hoặc mật khẩu không đúng.".to_owned()),
    )
}

fn rate_limited(retry_after: Duration) -> Response {
    let seconds = retry_after.as_secs().max(1);
    let mut response = json_error(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        Some(format!(
            "Quá nhiều lần thử. Vui lòng thử lại sau {seconds} giây."
        )),
    );
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// Apply the small JSON body limit only to the API router.
pub fn api_layers(router: axum::Router<AppState>) -> axum::Router<AppState> {
    router.layer(DefaultBodyLimit::max(16 * 1024))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{router, AppState};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::time::Instant;
    use tempfile::TempDir;
    use tower::ServiceExt;

    pub(crate) const PASSWORD: &str = "mng-dummy-password";
    const PASSWORD_HASH: &str = "$2b$10$/zz.uCobJ8PliYRPoujpHuQQ1RCjHFQe2YjMxcdsealWSlCQfHbLi";
    const SECRET: &[u8] = b"a-test-session-secret-with-32-bytes!";
    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 50000);

    pub(crate) struct Fixture {
        _dir: TempDir,
        pub(crate) state: AppState,
        pub(crate) db_path: std::path::PathBuf,
    }

    pub(crate) fn fixture(configured: bool, active: bool, max_attempts: u32) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("mng-cloud.sqlite");
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                last_login_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE user_clouds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                cloud TEXT NOT NULL,
                username TEXT NOT NULL,
                base_url TEXT NOT NULL,
                root TEXT NOT NULL DEFAULT '/',
                import_path TEXT NOT NULL DEFAULT '',
                provisioned INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                UNIQUE (user_id, cloud)
            );
            CREATE TABLE items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL DEFAULT 1,
                cloud TEXT NOT NULL,
                path TEXT NOT NULL,
                parent TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL,
                stem TEXT NOT NULL DEFAULT '',
                ext TEXT NOT NULL DEFAULT '',
                media_type TEXT NOT NULL DEFAULT 'photo',
                mime TEXT NOT NULL DEFAULT 'application/octet-stream',
                size INTEGER NOT NULL DEFAULT 0,
                etag TEXT NOT NULL DEFAULT '',
                mtime INTEGER NOT NULL DEFAULT 0,
                taken_at INTEGER NOT NULL DEFAULT 0,
                taken_src TEXT NOT NULL DEFAULT '',
                width INTEGER NOT NULL DEFAULT 0,
                height INTEGER NOT NULL DEFAULT 0,
                duration REAL NOT NULL DEFAULT 0,
                live INTEGER NOT NULL DEFAULT 0,
                live_name TEXT NOT NULL DEFAULT '',
                hidden INTEGER NOT NULL DEFAULT 0,
                favorite INTEGER NOT NULL DEFAULT 0,
                deleted INTEGER NOT NULL DEFAULT 0,
                thumb_state INTEGER NOT NULL DEFAULT 0,
                thumb_error TEXT NOT NULL DEFAULT '',
                indexed_at INTEGER NOT NULL DEFAULT 0,
                lat REAL NOT NULL DEFAULT 0,
                lng REAL NOT NULL DEFAULT 0,
                phash TEXT NOT NULL DEFAULT '',
                ahash TEXT NOT NULL DEFAULT '',
                phash_state INTEGER NOT NULL DEFAULT 0,
                faces_state INTEGER NOT NULL DEFAULT 0,
                place_state INTEGER NOT NULL DEFAULT 0,
                place_road TEXT NOT NULL DEFAULT '',
                place_ward TEXT NOT NULL DEFAULT '',
                place_district TEXT NOT NULL DEFAULT '',
                place_province TEXT NOT NULL DEFAULT '',
                place_display TEXT NOT NULL DEFAULT '',
                search_text TEXT NOT NULL DEFAULT '',
                UNIQUE (owner_id, cloud, path)
            );
            CREATE TABLE vaults (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                uid TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL DEFAULT '',
                kdf TEXT NOT NULL DEFAULT 'PBKDF2-SHA256',
                kdf_salt TEXT NOT NULL DEFAULT '',
                kdf_iterations INTEGER NOT NULL DEFAULT 310000,
                verifier TEXT NOT NULL DEFAULT '',
                bytes INTEGER NOT NULL DEFAULT 0,
                manifest_size INTEGER NOT NULL DEFAULT 0,
                manifest_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (id, username, display_name, password_hash, is_admin, active)
             VALUES (1, 'alice', 'Alice', ?1, 1, ?2),
                    (2, 'bob', 'Bob', ?1, 0, 1),
                    (3, 'carol', 'Carol', ?1, 0, 0)",
            rusqlite::params![PASSWORD_HASH, if active { 1 } else { 0 }],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_clouds (user_id, cloud, username, base_url, root, import_path, provisioned)
             VALUES (1, 'seafile', 'alice', 'http://127.0.0.1:8082', '/', '/Camera Uploads', 1),
                    (1, 'nextcloud', 'alice', 'http://127.0.0.1:8080', '/photos', '/import', 1),
                    (2, 'seafile', 'bob', 'http://127.0.0.1:8082', '/', '/Camera Uploads', 1),
                    (3, 'seafile', 'carol', 'http://127.0.0.1:8082', '/', '/Camera Uploads', 1)",
            [],
        )
        .unwrap();
        for (
            id,
            owner,
            cloud,
            path,
            name,
            media,
            size,
            taken,
            favorite,
            hidden,
            deleted,
            thumb,
            live,
        ) in [
            (
                1, 1, "seafile", "/a.jpg", "a.jpg", "photo", 100, 100, 1, 0, 0, 0, 0,
            ),
            (
                2, 1, "seafile", "/b.mp4", "b.mp4", "video", 200, 200, 0, 0, 0, 0, 0,
            ),
            (
                3,
                1,
                "nextcloud",
                "/c.jpg",
                "c.jpg",
                "photo",
                300,
                300,
                0,
                0,
                0,
                0,
                0,
            ),
            (
                4, 2, "seafile", "/d.jpg", "d.jpg", "photo", 400, 400, 0, 0, 0, 0, 0,
            ),
            (
                5, 1, "seafile", "/e.jpg", "e.jpg", "photo", 500, 500, 0, 0, 1, 0, 0,
            ),
            (
                6, 1, "seafile", "/f.jpg", "f.jpg", "photo", 600, 600, 0, 1, 0, 0, 0,
            ),
            (
                7, 1, "seafile", "/g.jpg", "g.jpg", "photo", 700, 700, 0, 0, 0, 3, 0,
            ),
            (
                8, 3, "seafile", "/h.jpg", "h.jpg", "photo", 800, 800, 0, 0, 0, 0, 0,
            ),
            (
                9,
                1,
                "seafile",
                "/live.heic",
                "live.heic",
                "photo",
                900,
                900,
                0,
                0,
                0,
                0,
                1,
            ),
        ] {
            conn.execute(
                "INSERT INTO items (id, owner_id, cloud, path, name, stem, ext, media_type, size, \
                 taken_at, favorite, hidden, deleted, thumb_state, live) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 'jpg', ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                rusqlite::params![
                    id, owner, cloud, path, name, media, size, taken, favorite, hidden, deleted,
                    thumb, live
                ],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO vaults (id, owner_id, uid, name, kdf_salt, kdf_iterations, verifier, \
             bytes, manifest_size, manifest_at, created_at, updated_at) \
             VALUES (1, 1, 'v-alice', 'Kho Alice', 'c2FsdA==', 310000, 'dmVyaWZpZXI=', 2048, 512, \
                     1700000000, 1700000000, 1700000100), \
                    (2, 2, 'v-bob', 'Kho Bob', '', 310000, '', 0, 0, 0, 0, 0)",
            [],
        )
        .unwrap();
        drop(conn);

        let config = Config {
            web_root: dir.path().to_path_buf(),
            data_dir: dir.path().to_path_buf(),
            database: Some(db_path.clone()),
            session_cookie_secure: false,
            login_max_attempts: max_attempts,
            ..Config::default()
        };

        let db = DatabaseState::load(&config);
        assert!(
            db.database.is_some(),
            "test database failed: {:?}",
            db.startup_error
        );
        let session = configured.then(|| {
            SessionConfig::new(
                SECRET,
                config.session_ttl_secs,
                config.session_cookie.clone(),
                false,
            )
            .unwrap()
        });
        let error = (!configured).then(|| "not configured".to_owned());
        let auth = AuthState::build(&config, db.clone(), session, error);
        Fixture {
            _dir: dir,
            db_path,
            state: AppState {
                config: Arc::new(config),
                started: Instant::now(),
                db,
                auth,
            },
        }
    }

    #[allow(dead_code)]
    pub(crate) fn json_request(
        method: Method,
        uri: &str,
        body: serde_json::Value,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(PEER))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    pub(crate) fn cookie_request(
        method: Method,
        uri: &str,
        cookie: &str,
        csrf: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::COOKIE, cookie)
            .extension(ConnectInfo(PEER));
        if let Some(csrf) = csrf {
            builder = builder.header("x-csrf-token", csrf);
        }
        builder.body(Body::empty()).unwrap()
    }

    pub(crate) async fn call(
        state: &AppState,
        request: Request<Body>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let response = router(state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, headers, body)
    }

    pub(crate) async fn login_as(
        state: &AppState,
        username: &str,
        password: &str,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        call(
            state,
            json_request(
                Method::POST,
                "/api/v1/auth/login",
                json!({ "username": username, "password": password }),
            ),
        )
        .await
    }

    pub(crate) async fn login(
        state: &AppState,
        password: &str,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        login_as(state, " Alice ", password).await
    }

    pub(crate) fn set_cookie(headers: &HeaderMap) -> String {
        headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    pub(crate) fn exec(fixture: &Fixture, sql: &str) {
        let conn = rusqlite::Connection::open(&fixture.db_path).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    #[tokio::test]
    async fn login_issues_httponly_cookie_and_csrf() {
        let fixture = fixture(true, true, 5);
        let (status, headers, body) = login(&fixture.state, PASSWORD).await;
        assert_eq!(status, StatusCode::OK);
        let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("mng_session="));
        assert_eq!(body["me"]["username"], "alice");
        assert!(body["csrf"].as_str().unwrap().len() >= 32);
        assert!(body["expires_at"].as_u64().unwrap() > unix_now());
    }

    #[tokio::test]
    async fn wrong_password_and_inactive_users_are_rejected() {
        let fixture = fixture(true, true, 5);
        let (status, headers, body) = login(&fixture.state, "wrong").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "bad_credentials");
        assert!(headers.get(header::SET_COOKIE).is_none());

        let inactive = fixture_with_active(false);
        let (status, _, body) = login(&inactive.state, PASSWORD).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "bad_credentials");
    }

    fn fixture_with_active(active: bool) -> Fixture {
        fixture(true, active, 5)
    }

    #[tokio::test]
    async fn me_requires_a_valid_session() {
        let fixture = fixture(true, true, 5);
        let (_, headers, _) = login(&fixture.state, PASSWORD).await;
        let cookie = set_cookie(&headers);

        let (status, _, body) = call(
            &fixture.state,
            cookie_request(Method::GET, "/api/v1/auth/me", &cookie, None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["me"]["username"], "alice");
        assert_eq!(body["me"]["is_admin"], true);

        let (status, _, body) = call(
            &fixture.state,
            cookie_request(Method::GET, "/api/v1/auth/me", "mng_session=bad", None),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "auth_required");

        let (status, _, body) = call(
            &fixture.state,
            json_request(Method::GET, "/api/v1/auth/me", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "auth_required");
    }

    #[tokio::test]
    async fn logout_requires_csrf_and_clears_the_cookie() {
        let fixture = fixture(true, true, 5);
        let (_, headers, body) = login(&fixture.state, PASSWORD).await;
        let cookie = set_cookie(&headers);
        let csrf = body["csrf"].as_str().unwrap().to_owned();

        let (status, _, body) = call(
            &fixture.state,
            cookie_request(Method::POST, "/api/v1/auth/logout", &cookie, None),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "csrf");

        let (status, headers, body) = call(
            &fixture.state,
            cookie_request(Method::POST, "/api/v1/auth/logout", &cookie, Some(&csrf)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        let cleared = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cleared.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn repeated_failures_are_rate_limited() {
        let fixture = fixture(true, true, 2);
        for _ in 0..2 {
            let (status, _, _) = login(&fixture.state, "wrong").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, headers, body) = login(&fixture.state, "wrong").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"], "rate_limited");
        assert!(headers.get(header::RETRY_AFTER).is_some());
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let fixture = fixture(false, true, 5);
        let (status, _, body) = login(&fixture.state, PASSWORD).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "auth_unavailable");

        let (status, _, body) = call(
            &fixture.state,
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["auth"]["available"], false);
    }
}
