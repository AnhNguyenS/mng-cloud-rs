//! Read-only library API.
//!
//! Every handler uses the owner id from the freshly loaded session user. Item
//! and count queries are scoped by `owner_id`; a cloud key must also exist in
//! `user_clouds` for that owner. An unowned or unknown cloud returns `404`
//! rather than `403` so the response does not confirm another user's library
//! names. Admins do **not** bypass this boundary.

use axum::{
    extract::{rejection::QueryRejection, Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mng_db::{
    album_count, album_items, all_users, cloud_for_user, clouds_for_user, count_items, item_by_id,
    item_by_path, item_counts, list_items, month_buckets, period_covers, thumb_state_counts,
    vault_by_id, vaults_for_user, year_buckets, AlbumKind, Cloud, Item, ItemCount, ItemQuery,
    PublicUser, Vault, DEFAULT_LIMIT, MAX_LIMIT, MAX_OFFSET,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{auth::AuthenticatedUser, db::ReadError, http::json_error, rbac, AppState};

#[derive(Debug, Default, Deserialize)]
pub struct ItemsParams {
    cloud: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    favorite: Option<bool>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CountsParams {
    cloud: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct TimelineParams {
    cloud: Option<String>,
    year: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PlaceView {
    road: String,
    ward: String,
    district: String,
    province: String,
    display: String,
}

#[derive(Debug, Serialize)]
pub struct ItemView {
    id: i64,
    cloud: String,
    name: String,
    path: String,
    parent: String,
    #[serde(rename = "type")]
    media_type: String,
    mime: String,
    size: i64,
    etag: String,
    taken_at: i64,
    width: i64,
    height: i64,
    duration: f64,
    live: bool,
    live_name: String,
    favorite: bool,
    thumb_state: i64,
    lat: f64,
    lng: f64,
    place: PlaceView,
}

impl From<&Item> for ItemView {
    fn from(item: &Item) -> Self {
        Self {
            id: item.id,
            cloud: item.cloud.clone(),
            name: item.name.clone(),
            path: item.path.clone(),
            parent: item.parent.clone(),
            media_type: item.media_type.clone(),
            mime: item.mime.clone(),
            size: item.size,
            etag: item.etag.clone(),
            taken_at: item.taken_at,
            width: item.width,
            height: item.height,
            duration: item.duration,
            live: item.live,
            live_name: item.live_name.clone(),
            favorite: item.favorite,
            thumb_state: item.thumb_state,
            lat: item.lat,
            lng: item.lng,
            place: PlaceView {
                road: item.place_road.clone(),
                ward: item.place_ward.clone(),
                district: item.place_district.clone(),
                province: item.place_province.clone(),
                display: item.place_display.clone(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AdminUserView {
    #[serde(flatten)]
    user: PublicUser,
    total: i64,
    bytes: i64,
    counts: Vec<ItemCount>,
}

#[derive(Debug, Serialize)]
pub struct AdminUserDetail {
    #[serde(flatten)]
    user: PublicUser,
    total: i64,
    bytes: i64,
    counts: Vec<ItemCount>,
    clouds: Vec<Cloud>,
}

#[derive(Debug, Serialize)]
pub struct YearEntry {
    year: i64,
    count: i64,
    covers: Vec<ItemView>,
}

#[derive(Debug, Serialize)]
pub struct MonthEntry {
    key: String,
    year: i64,
    month: i64,
    label: String,
    count: i64,
    covers: Vec<ItemView>,
}

#[derive(Debug, Serialize)]
pub struct AlbumEntry {
    key: String,
    title: String,
    sub: String,
    count: i64,
    covers: Vec<ItemView>,
}

/// Vault metadata the browser needs to derive the vault key. The salt and
/// verifier are not secrets: without the user's passphrase they are useless.
#[derive(Debug, Serialize)]
pub struct VaultView {
    id: i64,
    uid: String,
    name: String,
    kdf: String,
    salt: String,
    iterations: i64,
    verifier: String,
    bytes: i64,
    manifest_size: i64,
    manifest_at: i64,
    manifest_ready: bool,
    created_at: i64,
    updated_at: i64,
}

impl From<&Vault> for VaultView {
    fn from(vault: &Vault) -> Self {
        Self {
            id: vault.id,
            uid: vault.uid.clone(),
            name: vault.name.clone(),
            kdf: vault.kdf.clone(),
            salt: vault.kdf_salt.clone(),
            iterations: vault.kdf_iterations,
            verifier: vault.verifier.clone(),
            bytes: vault.bytes,
            manifest_size: vault.manifest_size,
            manifest_at: vault.manifest_at,
            manifest_ready: vault.manifest_size > 0,
            created_at: vault.created_at,
            updated_at: vault.updated_at,
        }
    }
}

/// The legacy UI shows at most four covers per timeline bucket or album.
const COVER_LIMIT: u32 = 4;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Everything the PWA needs for its first render: identity, CSRF token,
/// libraries and grouped counters.
pub async fn bootstrap(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
) -> Response {
    let owner_id = rbac::item_owner_id(&authenticated);
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        let clouds = clouds_for_user(&conn, owner_id)?;
        let counts = item_counts(&conn, owner_id, None)?;
        Ok((clouds, counts))
    })
    .await;

    match result {
        Ok((clouds, counts)) => {
            let (total, bytes) = totals(&counts);
            Json(json!({
                "ok": true,
                "me": authenticated.user.public(),
                "csrf": authenticated.session.csrf,
                "clouds": clouds,
                "counts": counts,
                "total": total,
                "bytes": bytes,
            }))
            .into_response()
        }
        Err(response) => response,
    }
}

pub async fn clouds(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
) -> Response {
    let owner_id = rbac::item_owner_id(&authenticated);
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        let clouds = clouds_for_user(&conn, owner_id)?;
        let counts = item_counts(&conn, owner_id, None)?;
        Ok((clouds, counts))
    })
    .await;

    match result {
        Ok((clouds, counts)) => {
            let (total, bytes) = totals(&counts);
            Json(json!({
                "ok": true,
                "clouds": clouds,
                "counts": counts,
                "total": total,
                "bytes": bytes,
            }))
            .into_response()
        }
        Err(response) => response,
    }
}

pub async fn counts(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    params: Result<Query<CountsParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = params else {
        return invalid_query();
    };
    let cloud = match normalize_cloud(params.cloud) {
        Ok(cloud) => cloud,
        Err(response) => return response,
    };
    let owner_id = rbac::item_owner_id(&authenticated);
    let filter_cloud = cloud.clone();

    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        if let Some(cloud) = &filter_cloud {
            if cloud_for_user(&conn, owner_id, cloud)?.is_none() {
                return Ok(None);
            }
        }
        Ok(Some(item_counts(&conn, owner_id, filter_cloud.as_deref())?))
    })
    .await;

    match result {
        Ok(Some(counts)) => {
            let (total, bytes) = totals(&counts);
            Json(json!({
                "ok": true,
                "cloud": cloud,
                "counts": counts,
                "total": total,
                "bytes": bytes,
            }))
            .into_response()
        }
        Ok(None) => not_found("Thư viện không tồn tại."),
        Err(response) => response,
    }
}

pub async fn items(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    params: Result<Query<ItemsParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = params else {
        return invalid_query();
    };
    let cloud = match normalize_cloud(params.cloud) {
        Ok(cloud) => cloud,
        Err(response) => return response,
    };
    let kind = match normalize_kind(params.kind) {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0).min(MAX_OFFSET);
    let favorite = if params.favorite.is_some() {
        params.favorite
    } else {
        kind.favorite
    };
    let query = ItemQuery {
        cloud: cloud.clone(),
        media_type: kind.media_type,
        favorite,
        live: kind.live,
        limit: Some(limit),
        offset: Some(offset),
    };
    let owner_id = rbac::item_owner_id(&authenticated);

    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        if let Some(cloud) = &query.cloud {
            if cloud_for_user(&conn, owner_id, cloud)?.is_none() {
                return Ok(None);
            }
        }
        let total = count_items(&conn, owner_id, &query)?;
        let items = list_items(&conn, owner_id, &query)?;
        Ok(Some((items, total)))
    })
    .await;

    match result {
        Ok(Some((items, total))) => {
            let seen = offset as i64 + items.len() as i64;
            Json(json!({
                "ok": true,
                "cloud": cloud,
                "items": items.iter().map(ItemView::from).collect::<Vec<_>>(),
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": seen < total,
            }))
            .into_response()
        }
        Ok(None) => not_found("Thư viện không tồn tại."),
        Err(response) => response,
    }
}

pub async fn item(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    Path(id): Path<i64>,
) -> Response {
    if id <= 0 {
        return not_found("Mục không tồn tại.");
    }
    let owner_id = rbac::item_owner_id(&authenticated);
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        let Some(item) = item_by_id(&conn, owner_id, id)? else {
            return Ok(None);
        };
        let live_item = if item.live_name.is_empty() {
            None
        } else {
            item_by_path(&conn, owner_id, &item.cloud, &item.live_name)?
        };
        Ok(Some((item, live_item)))
    })
    .await;

    match result {
        Ok(Some((item, live_item))) => Json(json!({
            "ok": true,
            "item": ItemView::from(&item),
            "live_item": live_item.as_ref().map(ItemView::from),
        }))
        .into_response(),
        Ok(None) => not_found("Mục không tồn tại."),
        Err(response) => response,
    }
}

pub async fn stats(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
) -> Response {
    let owner_id = rbac::item_owner_id(&authenticated);
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        let counts = item_counts(&conn, owner_id, None)?;
        let thumbs = thumb_state_counts(&conn, owner_id)?;
        Ok((counts, thumbs))
    })
    .await;

    match result {
        Ok((counts, thumbs)) => {
            let (total, bytes) = totals(&counts);
            Json(json!({
                "ok": true,
                "counts": counts,
                "thumbs": thumbs,
                "total": total,
                "bytes": bytes,
            }))
            .into_response()
        }
        Err(response) => response,
    }
}

/// Years that have at least one visible item with a capture date, newest
/// first, with up to four covers each.
pub async fn years(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    params: Result<Query<CountsParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = params else {
        return invalid_query();
    };
    let cloud = match normalize_cloud(params.cloud) {
        Ok(cloud) => cloud,
        Err(response) => return response,
    };
    let owner_id = rbac::item_owner_id(&authenticated);
    let filter_cloud = cloud.clone();

    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        if let Some(cloud) = &filter_cloud {
            if cloud_for_user(&conn, owner_id, cloud)?.is_none() {
                return Ok(None);
            }
        }
        let mut years = Vec::new();
        for bucket in year_buckets(&conn, owner_id, filter_cloud.as_deref())? {
            let covers = period_covers(
                &conn,
                owner_id,
                filter_cloud.as_deref(),
                bucket.year,
                None,
                COVER_LIMIT,
            )?;
            years.push(YearEntry {
                year: bucket.year,
                count: bucket.count,
                covers: covers.iter().map(ItemView::from).collect(),
            });
        }
        Ok(Some(years))
    })
    .await;

    match result {
        Ok(Some(years)) => Json(json!({
            "ok": true,
            "cloud": cloud,
            "years": years,
        }))
        .into_response(),
        Ok(None) => not_found("Thư viện không tồn tại."),
        Err(response) => response,
    }
}

/// Months in the timeline, newest first. `year` limits the result to one year.
pub async fn months(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    params: Result<Query<TimelineParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = params else {
        return invalid_query();
    };
    let cloud = match normalize_cloud(params.cloud) {
        Ok(cloud) => cloud,
        Err(response) => return response,
    };
    let year = match normalize_year(params.year) {
        Ok(year) => year,
        Err(response) => return response,
    };
    let owner_id = rbac::item_owner_id(&authenticated);
    let filter_cloud = cloud.clone();

    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        if let Some(cloud) = &filter_cloud {
            if cloud_for_user(&conn, owner_id, cloud)?.is_none() {
                return Ok(None);
            }
        }
        let mut months = Vec::new();
        for bucket in month_buckets(&conn, owner_id, filter_cloud.as_deref(), year)? {
            let covers = period_covers(
                &conn,
                owner_id,
                filter_cloud.as_deref(),
                bucket.year,
                Some(bucket.month),
                COVER_LIMIT,
            )?;
            months.push(MonthEntry {
                key: bucket.key,
                year: bucket.year,
                month: bucket.month,
                label: month_label(bucket.month, bucket.year),
                count: bucket.count,
                covers: covers.iter().map(ItemView::from).collect(),
            });
        }
        Ok(Some(months))
    })
    .await;

    match result {
        Ok(Some(months)) => Json(json!({
            "ok": true,
            "cloud": cloud,
            "year": year,
            "months": months,
        }))
        .into_response(),
        Ok(None) => not_found("Thư viện không tồn tại."),
        Err(response) => response,
    }
}

/// Fixed albums followed by one album per capture year, matching the legacy
/// payload. Empty non-`all` albums are omitted.
pub async fn albums(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    params: Result<Query<CountsParams>, QueryRejection>,
) -> Response {
    let Ok(Query(params)) = params else {
        return invalid_query();
    };
    let cloud = match normalize_cloud(params.cloud) {
        Ok(cloud) => cloud,
        Err(response) => return response,
    };
    let owner_id = rbac::item_owner_id(&authenticated);
    let filter_cloud = cloud.clone();

    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        if let Some(cloud) = &filter_cloud {
            if cloud_for_user(&conn, owner_id, cloud)?.is_none() {
                return Ok(None);
            }
        }
        let mut albums = Vec::new();
        for kind in AlbumKind::ALL {
            let (title, sub) = album_labels(kind);
            let count = album_count(&conn, owner_id, filter_cloud.as_deref(), kind)?;
            if count == 0 && kind != AlbumKind::All {
                continue;
            }
            let covers = album_items(&conn, owner_id, filter_cloud.as_deref(), kind, COVER_LIMIT)?;
            albums.push(AlbumEntry {
                key: kind.key().to_owned(),
                title: title.to_owned(),
                sub: sub.to_owned(),
                count,
                covers: covers.iter().map(ItemView::from).collect(),
            });
        }
        for bucket in year_buckets(&conn, owner_id, filter_cloud.as_deref())? {
            let covers = period_covers(
                &conn,
                owner_id,
                filter_cloud.as_deref(),
                bucket.year,
                None,
                COVER_LIMIT,
            )?;
            albums.push(AlbumEntry {
                key: format!("year:{}", bucket.year),
                title: format!("Năm {}", bucket.year),
                sub: format!("{} mục", bucket.count),
                count: bucket.count,
                covers: covers.iter().map(ItemView::from).collect(),
            });
        }
        Ok(Some(albums))
    })
    .await;

    match result {
        Ok(Some(albums)) => Json(json!({
            "ok": true,
            "cloud": cloud,
            "albums": albums,
        }))
        .into_response(),
        Ok(None) => not_found("Thư viện không tồn tại."),
        Err(response) => response,
    }
}

/// Vault metadata for the session user. File content and the vault key never
/// enter this service.
pub async fn vaults(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
) -> Response {
    let owner_id = rbac::item_owner_id(&authenticated);
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        vaults_for_user(&conn, owner_id)
    })
    .await;

    match result {
        Ok(vaults) => Json(json!({
            "ok": true,
            "vaults": vaults.iter().map(VaultView::from).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(response) => response,
    }
}

pub async fn vault(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    Path(id): Path<i64>,
) -> Response {
    if id <= 0 {
        return not_found("Kho không tồn tại.");
    }
    let owner_id = rbac::item_owner_id(&authenticated);
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        vault_by_id(&conn, owner_id, id)
    })
    .await;

    match result {
        Ok(Some(vault)) => Json(json!({
            "ok": true,
            "vault": VaultView::from(&vault),
        }))
        .into_response(),
        Ok(None) => not_found("Kho không tồn tại."),
        Err(response) => response,
    }
}

/// Administrative metadata. This lists every account and its aggregate counts
/// but never returns another owner's item rows or password hashes.
pub async fn admin_users(
    State(state): State<AppState>,
    Extension(_authenticated): Extension<AuthenticatedUser>,
) -> Response {
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        let mut users = Vec::new();
        for user in all_users(&conn)? {
            let counts = item_counts(&conn, user.id, None)?;
            let (total, bytes) = totals(&counts);
            users.push(AdminUserView {
                user: user.public(),
                total,
                bytes,
                counts,
            });
        }
        Ok(users)
    })
    .await;

    match result {
        Ok(users) => Json(json!({ "ok": true, "users": users })).into_response(),
        Err(response) => response,
    }
}

pub async fn admin_user(
    State(state): State<AppState>,
    Extension(_authenticated): Extension<AuthenticatedUser>,
    Path(id): Path<i64>,
) -> Response {
    if id <= 0 {
        return not_found("Người dùng không tồn tại.");
    }
    let result = read_db(&state, move |database| {
        let conn = database.connect()?;
        let Some(user) = mng_db::user_by_id(&conn, id)? else {
            return Ok(None);
        };
        let counts = item_counts(&conn, id, None)?;
        let clouds = clouds_for_user(&conn, id)?;
        let (total, bytes) = totals(&counts);
        Ok(Some(AdminUserDetail {
            user: user.public(),
            total,
            bytes,
            counts,
            clouds,
        }))
    })
    .await;

    match result {
        Ok(Some(user)) => Json(json!({ "ok": true, "user": user })).into_response(),
        Ok(None) => not_found("Người dùng không tồn tại."),
        Err(response) => response,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct KindFilter {
    media_type: Option<String>,
    live: Option<bool>,
    favorite: Option<bool>,
}

#[allow(clippy::result_large_err)]
fn normalize_kind(kind: Option<String>) -> Result<KindFilter, Response> {
    let kind = kind.unwrap_or_default();
    let kind = kind.trim();
    if kind.is_empty() {
        return Ok(KindFilter {
            media_type: None,
            live: None,
            favorite: None,
        });
    }
    if kind.eq_ignore_ascii_case("live") {
        return Ok(KindFilter {
            media_type: None,
            live: Some(true),
            favorite: None,
        });
    }
    if kind.eq_ignore_ascii_case("favorite") {
        return Ok(KindFilter {
            media_type: None,
            live: None,
            favorite: Some(true),
        });
    }
    if kind.len() > 32
        || kind
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(invalid_query());
    }
    Ok(KindFilter {
        media_type: Some(kind.to_owned()),
        live: None,
        favorite: None,
    })
}

#[allow(clippy::result_large_err)]
fn normalize_cloud(cloud: Option<String>) -> Result<Option<String>, Response> {
    let Some(cloud) = cloud else {
        return Ok(None);
    };
    let cloud = cloud.trim();
    if cloud.is_empty() || cloud.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    if cloud.len() > 64
        || !cloud
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(invalid_query());
    }
    Ok(Some(cloud.to_owned()))
}

#[allow(clippy::result_large_err)]
fn normalize_year(year: Option<String>) -> Result<Option<i64>, Response> {
    let Some(year) = year else {
        return Ok(None);
    };
    let year = year.trim();
    if year.is_empty() {
        return Ok(None);
    }
    if year.len() > 4 || !year.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_query());
    }
    let year: i64 = year.parse().map_err(|_| invalid_query())?;
    if !(1..=9999).contains(&year) {
        return Err(invalid_query());
    }
    Ok(Some(year))
}

fn month_label(month: i64, year: i64) -> String {
    match month {
        1 => format!("Tháng 1 {year}"),
        2 => format!("Tháng 2 {year}"),
        3 => format!("Tháng 3 {year}"),
        4 => format!("Tháng 4 {year}"),
        5 => format!("Tháng 5 {year}"),
        6 => format!("Tháng 6 {year}"),
        7 => format!("Tháng 7 {year}"),
        8 => format!("Tháng 8 {year}"),
        9 => format!("Tháng 9 {year}"),
        10 => format!("Tháng 10 {year}"),
        11 => format!("Tháng 11 {year}"),
        12 => format!("Tháng 12 {year}"),
        _ => format!("{month} {year}"),
    }
}

fn album_labels(kind: AlbumKind) -> (&'static str, &'static str) {
    match kind {
        AlbumKind::All => ("Tất cả", "Toàn bộ thư viện"),
        AlbumKind::Favorites => ("Yêu thích", "Ảnh và video đã thích"),
        AlbumKind::Videos => ("Video", "Tất cả video"),
        AlbumKind::Live => ("Live Photo", "Ảnh có chuyển động"),
        AlbumKind::Screenshots => ("Ảnh chụp màn hình", "Screenshot"),
    }
}

fn totals(counts: &[ItemCount]) -> (i64, i64) {
    counts.iter().fold((0, 0), |(total, bytes), row| {
        (total + row.count, bytes + row.bytes)
    })
}

#[allow(clippy::result_large_err)]
async fn read_db<T, F>(state: &AppState, operation: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce(&mng_db::Database) -> Result<T, mng_db::read::Error> + Send + 'static,
{
    state.db.read(operation).await.map_err(|error| {
        tracing::error!(error = %error, "read API database query failed");
        match error {
            ReadError::Unavailable(_) => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                Some("Cơ sở dữ liệu chưa sẵn sàng.".to_owned()),
            ),
            _ => json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "database_unavailable",
                None,
            ),
        }
    })
}

fn invalid_query() -> Response {
    json_error(
        StatusCode::BAD_REQUEST,
        "invalid_query",
        Some("Tham số truy vấn không hợp lệ.".to_owned()),
    )
}

fn not_found(message: &str) -> Response {
    json_error(StatusCode::NOT_FOUND, "not_found", Some(message.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{call, cookie_request, exec, fixture, login_as, set_cookie, PASSWORD};
    use axum::{
        body::Body,
        http::{header, Method, Request},
    };

    async fn session_cookie(fixture: &crate::auth::tests::Fixture, username: &str) -> String {
        session(fixture, username).await.0
    }

    async fn session(fixture: &crate::auth::tests::Fixture, username: &str) -> (String, String) {
        let (status, headers, body) = login_as(&fixture.state, username, PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "login failed for {username}");
        (
            set_cookie(&headers),
            body["csrf"].as_str().expect("csrf token").to_owned(),
        )
    }

    async fn get(
        fixture: &crate::auth::tests::Fixture,
        cookie: &str,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        call(
            &fixture.state,
            cookie_request(Method::GET, uri, cookie, None),
        )
        .await
    }

    fn ids(value: &serde_json::Value) -> Vec<i64> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_i64().unwrap())
            .collect()
    }

    fn album_keys(albums: &[serde_json::Value]) -> Vec<&str> {
        albums
            .iter()
            .map(|album| album["key"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn read_endpoints_require_a_session() {
        let fixture = fixture(true, true, 5);
        for uri in [
            "/api/v1/bootstrap",
            "/api/v1/clouds",
            "/api/v1/counts",
            "/api/v1/items",
            "/api/v1/items/1",
            "/api/v1/years",
            "/api/v1/months",
            "/api/v1/albums",
            "/api/v1/vaults",
            "/api/v1/vaults/1",
            "/api/v1/stats",
            "/api/v1/admin/users",
        ] {
            let (status, _, body) = call(
                &fixture.state,
                Request::builder().uri(uri).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(body["error"], "auth_required", "{uri}");
        }
    }

    #[tokio::test]
    async fn bootstrap_and_clouds_are_owner_scoped() {
        let fixture = fixture(true, true, 5);
        let bob = session_cookie(&fixture, "bob").await;

        let (status, _, body) = get(&fixture, &bob, "/api/v1/bootstrap").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["me"]["username"], "bob");
        assert_eq!(body["clouds"].as_array().unwrap().len(), 1);
        assert_eq!(body["clouds"][0]["cloud"], "seafile");
        assert_eq!(body["total"], 1);
        assert_eq!(body["bytes"], 400);
        assert!(body["csrf"].as_str().unwrap().len() >= 32);

        let (status, _, body) = get(&fixture, &bob, "/api/v1/clouds").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["clouds"].as_array().unwrap().len(), 1);
        assert_eq!(body["counts"][0]["cloud"], "seafile");
        assert_eq!(body["counts"][0]["count"], 1);
        assert_eq!(body["total"], 1);

        let alice = session_cookie(&fixture, "alice").await;
        let (status, _, body) = get(&fixture, &alice, "/api/v1/bootstrap").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["clouds"].as_array().unwrap().len(), 2);
        assert_eq!(body["total"], 5);
        assert_eq!(body["bytes"], 2200);
    }

    #[tokio::test]
    async fn items_and_counts_enforce_owner_and_library_acl() {
        let fixture = fixture(true, true, 5);
        let bob = session_cookie(&fixture, "bob").await;

        let (status, _, body) = get(&fixture, &bob, "/api/v1/items").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["id"], 4);
        assert_eq!(body["items"][0]["cloud"], "seafile");

        let (status, _, body) = get(&fixture, &bob, "/api/v1/items/1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");

        let (status, _, body) = get(&fixture, &bob, "/api/v1/items/4").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["item"]["id"], 4);
        assert_eq!(body["item"]["name"], "d.jpg");
        assert!(body["live_item"].is_null());

        let (status, _, body) = get(&fixture, &bob, "/api/v1/items?cloud=nextcloud").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");

        let (status, _, _) = get(&fixture, &bob, "/api/v1/counts?cloud=nextcloud").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let alice = session_cookie(&fixture, "alice").await;

        // Admin status does not grant access to another owner's item rows.
        let (status, _, _) = get(&fixture, &alice, "/api/v1/items/4").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/items?cloud=seafile").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["id"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![9, 7, 2, 1]
        );
        assert_eq!(body["total"], 4);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/items?type=video").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], 2);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/items?type=favorite").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], 1);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/items?type=live").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], 9);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/items?limit=1&offset=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 5);
        assert_eq!(body["items"][0]["id"], 7);
        assert_eq!(body["has_more"], true);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/counts?cloud=seafile").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 4);
        assert_eq!(body["bytes"], 1900);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/stats").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 5);
        assert_eq!(body["thumbs"][0]["thumb_state"], 0);
    }

    #[tokio::test]
    async fn timeline_and_albums_are_owner_and_cloud_scoped() {
        let fixture = fixture(true, true, 5);
        let alice = session_cookie(&fixture, "alice").await;

        let (status, _, body) = get(&fixture, &alice, "/api/v1/years").await;
        assert_eq!(status, StatusCode::OK);
        let years = body["years"].as_array().unwrap();
        assert_eq!(years.len(), 1);
        assert_eq!(years[0]["year"], 1970);
        assert_eq!(years[0]["count"], 5);
        assert_eq!(ids(&years[0]["covers"]), vec![9, 7, 3, 2]);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/years?cloud=seafile").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["years"][0]["count"], 4);
        assert_eq!(ids(&body["years"][0]["covers"]), vec![9, 7, 2, 1]);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/months").await;
        assert_eq!(status, StatusCode::OK);
        let months = body["months"].as_array().unwrap();
        assert_eq!(months.len(), 1);
        assert_eq!(months[0]["key"], "1970-01");
        assert_eq!(months[0]["year"], 1970);
        assert_eq!(months[0]["month"], 1);
        assert_eq!(months[0]["label"], "Tháng 1 1970");
        assert_eq!(months[0]["count"], 5);
        assert_eq!(ids(&months[0]["covers"]), vec![9, 7, 3, 2]);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/months?year=1970").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["year"], 1970);
        assert_eq!(body["months"].as_array().unwrap().len(), 1);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/months?year=1971").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["months"].as_array().unwrap().is_empty());

        let (status, _, body) = get(&fixture, &alice, "/api/v1/months?year=").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["months"].as_array().unwrap().len(), 1);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/months?year=abcd").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_query");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/albums").await;
        assert_eq!(status, StatusCode::OK);
        let albums = body["albums"].as_array().unwrap();
        assert_eq!(
            album_keys(albums),
            vec!["all", "favorites", "videos", "live", "year:1970"]
        );
        assert_eq!(albums[0]["count"], 5);
        assert_eq!(ids(&albums[0]["covers"]), vec![9, 7, 3, 2]);
        assert_eq!(albums[1]["count"], 1);
        assert_eq!(ids(&albums[1]["covers"]), vec![1]);
        assert_eq!(albums[2]["count"], 1);
        assert_eq!(ids(&albums[2]["covers"]), vec![2]);
        assert_eq!(albums[3]["count"], 1);
        assert_eq!(ids(&albums[3]["covers"]), vec![9]);
        assert_eq!(albums[4]["title"], "Năm 1970");
        assert_eq!(albums[4]["sub"], "5 mục");
        assert_eq!(albums[4]["count"], 5);

        let (status, _, body) = get(&fixture, &alice, "/api/v1/albums?cloud=seafile").await;
        assert_eq!(status, StatusCode::OK);
        let albums = body["albums"].as_array().unwrap();
        assert_eq!(
            album_keys(albums),
            vec!["all", "favorites", "videos", "live", "year:1970"]
        );
        assert_eq!(albums[0]["count"], 4);
        assert_eq!(ids(&albums[0]["covers"]), vec![9, 7, 2, 1]);
        assert_eq!(albums[4]["count"], 4);
        assert_eq!(ids(&albums[4]["covers"]), vec![9, 7, 2, 1]);

        let bob = session_cookie(&fixture, "bob").await;
        for uri in [
            "/api/v1/years?cloud=nextcloud",
            "/api/v1/months?cloud=nextcloud",
            "/api/v1/albums?cloud=nextcloud",
        ] {
            let (status, _, body) = get(&fixture, &bob, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(body["error"], "not_found", "{uri}");
        }

        let (status, _, body) = get(&fixture, &bob, "/api/v1/years").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["years"][0]["count"], 1);
        assert_eq!(ids(&body["years"][0]["covers"]), vec![4]);

        let (status, _, body) = get(&fixture, &bob, "/api/v1/albums").await;
        assert_eq!(status, StatusCode::OK);
        let albums = body["albums"].as_array().unwrap();
        assert_eq!(album_keys(albums), vec!["all", "year:1970"]);
        assert_eq!(albums[0]["count"], 1);
        assert_eq!(ids(&albums[0]["covers"]), vec![4]);
    }

    #[tokio::test]
    async fn vault_metadata_is_owner_scoped_and_read_only() {
        let fixture = fixture(true, true, 5);
        let (alice, csrf) = session(&fixture, "alice").await;

        let (status, _, body) = get(&fixture, &alice, "/api/v1/vaults").await;
        assert_eq!(status, StatusCode::OK);
        let vaults = body["vaults"].as_array().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0]["id"], 1);
        assert_eq!(vaults[0]["uid"], "v-alice");
        assert_eq!(vaults[0]["name"], "Kho Alice");
        assert_eq!(vaults[0]["kdf"], "PBKDF2-SHA256");
        assert_eq!(vaults[0]["salt"], "c2FsdA==");
        assert_eq!(vaults[0]["iterations"], 310000);
        assert_eq!(vaults[0]["verifier"], "dmVyaWZpZXI=");
        assert_eq!(vaults[0]["bytes"], 2048);
        assert_eq!(vaults[0]["manifest_size"], 512);
        assert_eq!(vaults[0]["manifest_ready"], true);
        assert!(vaults[0].get("owner_id").is_none());

        let (status, _, body) = get(&fixture, &alice, "/api/v1/vaults/1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["vault"]["uid"], "v-alice");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/vaults/2").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/vaults/0").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");

        let bob = session_cookie(&fixture, "bob").await;
        let (status, _, body) = get(&fixture, &bob, "/api/v1/vaults").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["vaults"].as_array().unwrap().len(), 1);
        assert_eq!(body["vaults"][0]["id"], 2);
        assert_eq!(body["vaults"][0]["manifest_ready"], false);

        let (status, _, _) = get(&fixture, &bob, "/api/v1/vaults/1").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, _) = call(
            &fixture.state,
            cookie_request(Method::POST, "/api/v1/vaults", &alice, Some(&csrf)),
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn admin_routes_require_the_admin_role() {
        let fixture = fixture(true, true, 5);
        let bob = session_cookie(&fixture, "bob").await;

        let (status, _, body) = get(&fixture, &bob, "/api/v1/admin/users").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "forbidden");

        let (status, _, body) = get(&fixture, &bob, "/api/v1/admin/users/1").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "forbidden");

        let alice = session_cookie(&fixture, "alice").await;
        let (status, _, body) = get(&fixture, &alice, "/api/v1/admin/users").await;
        assert_eq!(status, StatusCode::OK);
        let users = body["users"].as_array().unwrap();
        assert_eq!(users.len(), 3);
        let bob_row = users.iter().find(|user| user["username"] == "bob").unwrap();
        assert_eq!(bob_row["total"], 1);
        assert_eq!(bob_row["counts"][0]["count"], 1);
        let alice_row = users
            .iter()
            .find(|user| user["username"] == "alice")
            .unwrap();
        assert_eq!(alice_row["total"], 5);

        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("password_hash"));
        assert!(!serialized.contains("$2b$"));

        let (status, _, body) = get(&fixture, &alice, "/api/v1/admin/users/2").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user"]["username"], "bob");
        assert_eq!(body["user"]["total"], 1);
        assert_eq!(body["user"]["clouds"][0]["cloud"], "seafile");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/admin/users/99").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
    }

    #[tokio::test]
    async fn privilege_and_active_changes_apply_to_the_next_request() {
        let fixture = fixture(true, true, 5);
        let alice = session_cookie(&fixture, "alice").await;

        exec(&fixture, "UPDATE users SET is_admin = 0 WHERE id = 1;");
        let (status, _, body) = get(&fixture, &alice, "/api/v1/admin/users").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "forbidden");

        exec(&fixture, "UPDATE users SET active = 0 WHERE id = 1;");
        let (status, headers, body) = get(&fixture, &alice, "/api/v1/clouds").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "auth_required");
        let cleared = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cleared.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn malformed_queries_and_unknown_routes_return_json_errors() {
        let fixture = fixture(true, true, 5);
        let alice = session_cookie(&fixture, "alice").await;

        let (status, _, body) = get(&fixture, &alice, "/api/v1/items?limit=abc").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_query");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/items?cloud=../etc").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_query");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/months?year=0").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_query");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/months?year=10000").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_query");

        let (status, _, body) = get(&fixture, &alice, "/api/v1/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
    }
}
