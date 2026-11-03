use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, params_from_iter, types::Value, Connection, OpenFlags, Row};

use crate::model::{Cloud, Item, ItemCount, ItemQuery, ThumbStateCount, User};

pub const DEFAULT_LIMIT: u32 = 100;
pub const MAX_LIMIT: u32 = 500;
pub const MAX_OFFSET: u32 = 1_000_000;

const USER_COLUMNS: &str = "id, username, display_name, password_hash, is_admin, active, \
                             created_at, updated_at, last_login_at";

const CLOUD_COLUMNS: &str = "id, user_id, cloud, username, base_url, root, import_path, \
                             provisioned, created_at, updated_at";

const ITEM_COLUMNS: &str = "id, owner_id, cloud, path, parent, name, stem, ext, media_type, \
                            mime, size, etag, mtime, taken_at, taken_src, width, height, duration, \
                            live, live_name, hidden, favorite, deleted, thumb_state, thumb_error, \
                            indexed_at, lat, lng, phash, ahash, phash_state, faces_state, \
                            place_state, place_road, place_ward, place_district, place_province, \
                            place_display, search_text";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database path is empty")]
    EmptyPath,
}

pub type Result<T> = std::result::Result<T, Error>;

/// How a database file is opened. A snapshot is copied outside the live WAL
/// directory and opened with SQLite's `immutable=1` URI flag, so a reader never
/// needs write access to the PHP process's `-shm` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    LiveReadOnly,
    Snapshot,
}

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
    mode: OpenMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbProbe {
    pub schema_version: i64,
    pub users: i64,
}

impl Database {
    pub fn open_live(path: impl Into<PathBuf>) -> Result<Self> {
        Self::new(path.into(), OpenMode::LiveReadOnly)
    }

    pub fn open_snapshot(path: impl Into<PathBuf>) -> Result<Self> {
        Self::new(path.into(), OpenMode::Snapshot)
    }

    fn new(path: PathBuf, mode: OpenMode) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(Error::EmptyPath);
        }
        Ok(Self { path, mode })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    /// Open a fresh connection. Connections are cheap and this keeps a slow
    /// query from blocking other requests through a shared mutex.
    pub fn connect(&self) -> Result<Connection> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = match self.mode {
            OpenMode::LiveReadOnly => Connection::open_with_flags(&self.path, flags)?,
            OpenMode::Snapshot => {
                let uri = format!("file:{}?immutable=1", uri_path(&self.path));
                Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)?
            }
        };
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "query_only", true)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        Ok(conn)
    }

    pub fn probe(&self) -> Result<DbProbe> {
        let conn = self.connect()?;
        let schema_version = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let users = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        Ok(DbProbe {
            schema_version,
            users,
        })
    }
}

fn uri_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('%', "%25")
        .replace('?', "%3F")
        .replace('#', "%23")
        .replace(' ', "%20")
}

pub fn user_by_id(conn: &Connection, id: i64) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1");
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query([id])?;
    Ok(rows.next()?.map(user_from_row).transpose()?)
}

pub fn user_by_username(conn: &Connection, username: &str) -> Result<Option<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1");
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query([username])?;
    Ok(rows.next()?.map(user_from_row).transpose()?)
}

pub fn clouds_for_user(conn: &Connection, user_id: i64) -> Result<Vec<Cloud>> {
    let sql = format!("SELECT {CLOUD_COLUMNS} FROM user_clouds WHERE user_id = ?1 ORDER BY id");
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([user_id], cloud_from_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)
}

pub fn cloud_for_user(conn: &Connection, user_id: i64, cloud: &str) -> Result<Option<Cloud>> {
    let sql = format!("SELECT {CLOUD_COLUMNS} FROM user_clouds WHERE user_id = ?1 AND cloud = ?2");
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query(params![user_id, cloud])?;
    Ok(rows.next()?.map(cloud_from_row).transpose()?)
}

pub fn item_counts(
    conn: &Connection,
    owner_id: i64,
    cloud: Option<&str>,
) -> Result<Vec<ItemCount>> {
    let mut sql = String::from(
        "SELECT cloud, media_type, COUNT(*), COALESCE(SUM(size), 0) \
         FROM items WHERE owner_id = ?1 AND deleted = 0 AND hidden = 0",
    );
    let mut args: Vec<Value> = vec![owner_id.into()];
    if let Some(cloud) = cloud {
        sql.push_str(" AND cloud = ?2");
        args.push(Value::Text(cloud.to_owned()));
    }
    sql.push_str(" GROUP BY cloud, media_type ORDER BY cloud, media_type");
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), |row| {
        Ok(ItemCount {
            cloud: row.get(0)?,
            media_type: row.get(1)?,
            count: row.get(2)?,
            bytes: row.get(3)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)
}

pub fn thumb_state_counts(conn: &Connection, owner_id: i64) -> Result<Vec<ThumbStateCount>> {
    let mut stmt = conn.prepare_cached(
        "SELECT thumb_state, COUNT(*) FROM items \
         WHERE owner_id = ?1 AND deleted = 0 GROUP BY thumb_state ORDER BY thumb_state",
    )?;
    let rows = stmt.query_map([owner_id], |row| {
        Ok(ThumbStateCount {
            thumb_state: row.get(0)?,
            count: row.get(1)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)
}

pub fn list_items(conn: &Connection, owner_id: i64, query: &ItemQuery) -> Result<Vec<Item>> {
    let (filter, mut args) = item_filter(owner_id, query);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = query.offset.unwrap_or(0).min(MAX_OFFSET);
    let limit_index = args.len() + 1;
    let offset_index = args.len() + 2;
    let sql = format!(
        "SELECT {ITEM_COLUMNS} FROM items WHERE {filter} \
         ORDER BY taken_at DESC, id DESC LIMIT ?{limit_index} OFFSET ?{offset_index}"
    );
    args.push(i64::from(limit).into());
    args.push(i64::from(offset).into());

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), item_from_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)
}

/// Count the rows that [`list_items`] would paginate with the same filters.
pub fn count_items(conn: &Connection, owner_id: i64, query: &ItemQuery) -> Result<i64> {
    let (filter, args) = item_filter(owner_id, query);
    let sql = format!("SELECT COUNT(*) FROM items WHERE {filter}");
    conn.query_row(&sql, params_from_iter(args.iter()), |row| row.get(0))
        .map_err(Error::from)
}

fn item_filter(owner_id: i64, query: &ItemQuery) -> (String, Vec<Value>) {
    let mut filter = String::from("owner_id = ?1 AND deleted = 0 AND hidden = 0");
    let mut args: Vec<Value> = vec![owner_id.into()];

    if let Some(cloud) = &query.cloud {
        args.push(Value::Text(cloud.clone()));
        filter.push_str(&format!(" AND cloud = ?{}", args.len()));
    }
    if let Some(media_type) = &query.media_type {
        args.push(Value::Text(media_type.clone()));
        filter.push_str(&format!(" AND media_type = ?{}", args.len()));
    }
    if let Some(favorite) = query.favorite {
        args.push(Value::Integer(i64::from(favorite)));
        filter.push_str(&format!(" AND favorite = ?{}", args.len()));
    }
    if let Some(live) = query.live {
        args.push(Value::Integer(i64::from(live)));
        filter.push_str(&format!(" AND live = ?{}", args.len()));
    }

    (filter, args)
}

pub fn all_users(conn: &Connection) -> Result<Vec<User>> {
    let sql = format!("SELECT {USER_COLUMNS} FROM users ORDER BY id");
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map([], user_from_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::from)
}

pub fn item_by_id(conn: &Connection, owner_id: i64, id: i64) -> Result<Option<Item>> {
    let sql =
        format!("SELECT {ITEM_COLUMNS} FROM items WHERE id = ?1 AND owner_id = ?2 AND deleted = 0");
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query([id, owner_id])?;
    Ok(rows.next()?.map(item_from_row).transpose()?)
}

pub fn item_by_path(
    conn: &Connection,
    owner_id: i64,
    cloud: &str,
    path: &str,
) -> Result<Option<Item>> {
    let sql = format!(
        "SELECT {ITEM_COLUMNS} FROM items \
         WHERE owner_id = ?1 AND cloud = ?2 AND path = ?3 AND deleted = 0"
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query(params![owner_id, cloud, path])?;
    Ok(rows.next()?.map(item_from_row).transpose()?)
}

fn user_from_row(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        password_hash: row.get(3)?,
        is_admin: row.get::<_, i64>(4)? != 0,
        active: row.get::<_, i64>(5)? != 0,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        last_login_at: row.get(8)?,
    })
}

fn cloud_from_row(row: &Row<'_>) -> rusqlite::Result<Cloud> {
    Ok(Cloud {
        id: row.get(0)?,
        user_id: row.get(1)?,
        cloud: row.get(2)?,
        username: row.get(3)?,
        base_url: row.get(4)?,
        root: row.get(5)?,
        import_path: row.get(6)?,
        provisioned: row.get::<_, i64>(7)? != 0,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

fn item_from_row(row: &Row<'_>) -> rusqlite::Result<Item> {
    Ok(Item {
        id: row.get(0)?,
        owner_id: row.get(1)?,
        cloud: row.get(2)?,
        path: row.get(3)?,
        parent: row.get(4)?,
        name: row.get(5)?,
        stem: row.get(6)?,
        ext: row.get(7)?,
        media_type: row.get(8)?,
        mime: row.get(9)?,
        size: row.get(10)?,
        etag: row.get(11)?,
        mtime: row.get(12)?,
        taken_at: row.get(13)?,
        taken_src: row.get(14)?,
        width: row.get(15)?,
        height: row.get(16)?,
        duration: row.get(17)?,
        live: row.get::<_, i64>(18)? != 0,
        live_name: row.get(19)?,
        hidden: row.get::<_, i64>(20)? != 0,
        favorite: row.get::<_, i64>(21)? != 0,
        deleted: row.get::<_, i64>(22)? != 0,
        thumb_state: row.get(23)?,
        thumb_error: row.get(24)?,
        indexed_at: row.get(25)?,
        lat: row.get(26)?,
        lng: row.get(27)?,
        phash: row.get(28)?,
        ahash: row.get(29)?,
        phash_state: row.get(30)?,
        faces_state: row.get(31)?,
        place_state: row.get(32)?,
        place_road: row.get(33)?,
        place_ward: row.get(34)?,
        place_district: row.get(35)?,
        place_province: row.get(36)?,
        place_display: row.get(37)?,
        search_text: row.get(38)?,
    })
}
