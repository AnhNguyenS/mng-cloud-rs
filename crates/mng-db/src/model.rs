use serde::{Deserialize, Serialize};

/// Internal account row. `password_hash` is never serialised; API handlers
/// must use [`User::public`] instead of returning this type directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub password_hash: String,
    pub is_admin: bool,
    pub active: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicUser {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    pub active: bool,
    pub created_at: i64,
    pub last_login_at: i64,
}

impl User {
    pub fn public(&self) -> PublicUser {
        PublicUser {
            id: self.id,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            is_admin: self.is_admin,
            active: self.active,
            created_at: self.created_at,
            last_login_at: self.last_login_at,
        }
    }
}

/// Per-user mapping to one upstream cloud. Credentials are deliberately not
/// part of the read model; they stay in root/www-data secret files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cloud {
    pub id: i64,
    pub user_id: i64,
    pub cloud: String,
    pub username: String,
    pub base_url: String,
    pub root: String,
    pub import_path: String,
    pub provisioned: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Item {
    pub id: i64,
    pub owner_id: i64,
    pub cloud: String,
    pub path: String,
    pub parent: String,
    pub name: String,
    pub stem: String,
    pub ext: String,
    #[serde(rename = "type")]
    pub media_type: String,
    pub mime: String,
    pub size: i64,
    pub etag: String,
    pub mtime: i64,
    pub taken_at: i64,
    pub taken_src: String,
    pub width: i64,
    pub height: i64,
    pub duration: f64,
    pub live: bool,
    pub live_name: String,
    pub hidden: bool,
    pub favorite: bool,
    pub deleted: bool,
    pub thumb_state: i64,
    pub thumb_error: String,
    pub indexed_at: i64,
    pub lat: f64,
    pub lng: f64,
    pub phash: String,
    pub ahash: String,
    pub phash_state: i64,
    pub faces_state: i64,
    pub place_state: i64,
    pub place_road: String,
    pub place_ward: String,
    pub place_district: String,
    pub place_province: String,
    pub place_display: String,
    pub search_text: String,
}

/// Result of the grouped library counter query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemCount {
    pub cloud: String,
    #[serde(rename = "type")]
    pub media_type: String,
    pub count: i64,
    pub bytes: i64,
}

/// One row from `GROUP BY thumb_state`. Used by operations checks; the service
/// never resets a failed thumbnail state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThumbStateCount {
    pub thumb_state: i64,
    pub count: i64,
}

/// Client-side encrypted vault metadata. The KDF salt and verifier are returned
/// to the owner because the browser needs them to derive the vault key; neither
/// is a secret on its own, and no plaintext file content is stored here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vault {
    pub id: i64,
    pub owner_id: i64,
    pub uid: String,
    pub name: String,
    pub kdf: String,
    pub kdf_salt: String,
    pub kdf_iterations: i64,
    pub verifier: String,
    pub bytes: i64,
    pub manifest_size: i64,
    pub manifest_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

/// One year in the timeline. Items without a capture date are excluded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YearBucket {
    pub year: i64,
    pub count: i64,
}

/// One month in the timeline. `key` is `YYYY-MM`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonthBucket {
    pub key: String,
    pub year: i64,
    pub month: i64,
    pub count: i64,
}

/// Fixed album predicates. The SQL is static; callers cannot inject a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlbumKind {
    All,
    Favorites,
    Videos,
    Live,
    Screenshots,
}

impl AlbumKind {
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::Favorites,
        Self::Videos,
        Self::Live,
        Self::Screenshots,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Favorites => "favorites",
            Self::Videos => "videos",
            Self::Live => "live",
            Self::Screenshots => "screenshots",
        }
    }

    pub(crate) fn predicate(self) -> &'static str {
        match self {
            Self::All => "1=1",
            Self::Favorites => "favorite = 1",
            Self::Videos => "media_type = 'video'",
            Self::Live => "live = 1",
            Self::Screenshots => "(name LIKE 'Screenshot%' OR name LIKE 'Screen_%')",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ItemQuery {
    pub cloud: Option<String>,
    pub media_type: Option<String>,
    pub favorite: Option<bool>,
    pub live: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}
