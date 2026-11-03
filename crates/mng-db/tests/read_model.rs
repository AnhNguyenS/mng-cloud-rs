use mng_db::{
    album_count, album_items, all_users, cloud_for_user, clouds_for_user, count_items, item_by_id,
    item_counts, list_items, month_buckets, period_covers, thumb_state_counts, user_by_id,
    user_by_username, vault_by_id, vaults_for_user, year_buckets, AlbumKind, Database, ItemQuery,
    MonthBucket, OpenMode, YearBucket,
};
use rusqlite::{params, Connection};

const SCHEMA: &str = r#"
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    last_login_at INTEGER NOT NULL DEFAULT 0,
    icloud_apple_id TEXT NOT NULL DEFAULT '',
    icloud_settings TEXT NOT NULL DEFAULT '{}',
    icloud_authenticated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE user_clouds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    cloud TEXT NOT NULL,
    username TEXT NOT NULL,
    base_url TEXT NOT NULL,
    root TEXT NOT NULL DEFAULT '/',
    import_path TEXT NOT NULL DEFAULT '',
    secret_file TEXT NOT NULL DEFAULT '',
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
    phash_src TEXT NOT NULL DEFAULT '',
    phash_at INTEGER NOT NULL DEFAULT 0,
    faces_state INTEGER NOT NULL DEFAULT 0,
    faces_at INTEGER NOT NULL DEFAULT 0,
    place_state INTEGER NOT NULL DEFAULT 0,
    place_at INTEGER NOT NULL DEFAULT 0,
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
);
"#;

fn seeded() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    conn.execute(
        "INSERT INTO users (id, username, display_name, password_hash, is_admin, active) \
         VALUES (1, 'admin', 'Quản trị', '$2y$10$hash', 1, 1), \
                (2, 'alice', 'Alice', '$2y$10$hash', 0, 1), \
                (3, 'disabled', 'Disabled', '', 0, 0)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_clouds (user_id, cloud, username, base_url, root, import_path, provisioned) \
         VALUES (1, 'seafile', 'admin', 'http://127.0.0.1:8082', '/', '/Camera Uploads', 1), \
                (1, 'nextcloud', 'admin', 'http://127.0.0.1:8080', '/photos', '/import', 1), \
                (2, 'seafile', 'alice', 'http://127.0.0.1:8082', '/', '/Camera Uploads', 1)",
        [],
    )
    .unwrap();
    for (id, owner, cloud, path, name, media, size, taken, favorite, hidden, deleted, thumb) in [
        (
            1, 1, "seafile", "/a.jpg", "a.jpg", "photo", 100, 100, 1, 0, 0, 0,
        ),
        (
            2, 1, "seafile", "/b.mp4", "b.mp4", "video", 200, 200, 0, 0, 0, 0,
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
        ),
        (
            4, 2, "seafile", "/d.jpg", "d.jpg", "photo", 400, 400, 0, 0, 0, 0,
        ),
        (
            5, 1, "seafile", "/e.jpg", "e.jpg", "photo", 500, 500, 0, 0, 1, 0,
        ),
        (
            6, 1, "seafile", "/f.jpg", "f.jpg", "photo", 600, 600, 0, 1, 0, 0,
        ),
        (
            7, 1, "seafile", "/g.jpg", "g.jpg", "photo", 700, 700, 0, 0, 0, 3,
        ),
    ] {
        conn.execute(
            "INSERT INTO items (id, owner_id, cloud, path, name, stem, ext, media_type, size, \
             taken_at, favorite, hidden, deleted, thumb_state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, 'jpg', ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                id, owner, cloud, path, name, media, size, taken, favorite, hidden, deleted, thumb
            ],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO items (id, owner_id, cloud, path, name, stem, ext, media_type, size, \
         taken_at, live) VALUES (9, 1, 'seafile', '/live.heic', 'live.heic', 'live.heic', 'heic', \
         'photo', 900, 900, 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO vaults (id, owner_id, uid, name, kdf_salt, kdf_iterations, verifier, \
         bytes, manifest_size, manifest_at, created_at, updated_at) \
         VALUES (1, 1, 'v-admin', 'Kho Admin', 'c2FsdA==', 310000, 'dmVyaWZpZXI=', 2048, 512, \
                 1700000000, 1700000000, 1700000100), \
                (2, 2, 'v-alice', 'Kho Alice', '', 310000, '', 0, 0, 0, 0, 0)",
        [],
    )
    .unwrap();
    conn
}

#[test]
fn users_are_case_insensitive_and_boolean_columns_decode() {
    let conn = seeded();
    let admin = user_by_username(&conn, "ADMIN").unwrap().unwrap();
    assert_eq!(admin.id, 1);
    assert!(admin.is_admin);
    assert!(admin.active);
    assert_eq!(admin.display_name, "Quản trị");

    let alice = user_by_id(&conn, 2).unwrap().unwrap();
    assert!(!alice.is_admin);
    assert_eq!(alice.username, "alice");

    let disabled = user_by_id(&conn, 3).unwrap().unwrap();
    assert!(!disabled.active);
    assert!(user_by_id(&conn, 99).unwrap().is_none());
}

#[test]
fn clouds_are_scoped_to_the_owner() {
    let conn = seeded();
    let clouds = clouds_for_user(&conn, 1).unwrap();
    assert_eq!(clouds.len(), 2);
    assert_eq!(clouds[0].cloud, "seafile");
    assert_eq!(clouds[1].cloud, "nextcloud");
    assert!(cloud_for_user(&conn, 1, "seafile").unwrap().is_some());
    assert!(cloud_for_user(&conn, 2, "nextcloud").unwrap().is_none());
    assert!(clouds_for_user(&conn, 99).unwrap().is_empty());
}

#[test]
fn counts_exclude_deleted_hidden_and_other_owners() {
    let conn = seeded();
    let counts = item_counts(&conn, 1, None).unwrap();
    let seafile_photo = counts
        .iter()
        .find(|row| row.cloud == "seafile" && row.media_type == "photo")
        .unwrap();
    assert_eq!(seafile_photo.count, 3);
    assert_eq!(seafile_photo.bytes, 1700);
    let seafile_video = counts
        .iter()
        .find(|row| row.cloud == "seafile" && row.media_type == "video")
        .unwrap();
    assert_eq!(seafile_video.count, 1);

    let only_nextcloud = item_counts(&conn, 1, Some("nextcloud")).unwrap();
    assert_eq!(only_nextcloud.len(), 1);
    assert_eq!(only_nextcloud[0].count, 1);

    let states = thumb_state_counts(&conn, 1).unwrap();
    assert_eq!(
        states,
        vec![
            mng_db::ThumbStateCount {
                thumb_state: 0,
                count: 5
            },
            mng_db::ThumbStateCount {
                thumb_state: 3,
                count: 1
            }
        ]
    );
}

#[test]
fn list_items_orders_filters_and_paginates() {
    let conn = seeded();
    let all = list_items(&conn, 1, &ItemQuery::default()).unwrap();
    assert_eq!(
        all.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![9, 7, 3, 2, 1]
    );

    let page = list_items(
        &conn,
        1,
        &ItemQuery {
            limit: Some(2),
            offset: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        page.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![7, 3]
    );

    let seafile_photos = list_items(
        &conn,
        1,
        &ItemQuery {
            cloud: Some("seafile".to_owned()),
            media_type: Some("photo".to_owned()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        seafile_photos
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        vec![9, 7, 1]
    );

    let favorites = list_items(
        &conn,
        1,
        &ItemQuery {
            favorite: Some(true),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(favorites.len(), 1);
    assert_eq!(favorites[0].id, 1);

    let clamped = list_items(
        &conn,
        1,
        &ItemQuery {
            limit: Some(10_000),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(clamped.len(), 5);
}

#[test]
fn item_lookup_never_crosses_owner_boundary() {
    let conn = seeded();
    assert!(item_by_id(&conn, 1, 4).unwrap().is_none());
    let alice_item = item_by_id(&conn, 2, 4).unwrap().unwrap();
    assert_eq!(alice_item.cloud, "seafile");
    assert_eq!(alice_item.taken_at, 400);
    assert!(item_by_id(&conn, 1, 5).unwrap().is_none(), "deleted row");
    assert_eq!(
        item_by_id(&conn, 1, 6).unwrap().unwrap().id,
        6,
        "hidden rows remain addressable"
    );
}

#[test]
fn counts_match_the_listing_filters() {
    let conn = seeded();
    let all = ItemQuery::default();
    assert_eq!(count_items(&conn, 1, &all).unwrap(), 5);

    let favorites = ItemQuery {
        favorite: Some(true),
        ..Default::default()
    };
    assert_eq!(count_items(&conn, 1, &favorites).unwrap(), 1);
    assert_eq!(list_items(&conn, 1, &favorites).unwrap().len(), 1);

    let videos = ItemQuery {
        media_type: Some("video".to_owned()),
        ..Default::default()
    };
    assert_eq!(count_items(&conn, 1, &videos).unwrap(), 1);
    assert_eq!(count_items(&conn, 2, &videos).unwrap(), 0);

    let live = ItemQuery {
        live: Some(true),
        ..Default::default()
    };
    assert_eq!(count_items(&conn, 1, &live).unwrap(), 1);
    assert_eq!(count_items(&conn, 1, &all).unwrap(), 5);
}

#[test]
fn all_users_preserves_password_hashes_for_auth_only() {
    let conn = seeded();
    let users = all_users(&conn).unwrap();
    assert_eq!(
        users.iter().map(|user| user.id).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(users[0].password_hash, "$2y$10$hash");
    assert!(users[0].is_admin);
    assert!(!users[1].is_admin);
}

#[test]
fn timeline_buckets_and_covers_are_owner_and_cloud_scoped() {
    let conn = seeded();

    assert_eq!(
        year_buckets(&conn, 1, None).unwrap(),
        vec![YearBucket {
            year: 1970,
            count: 5
        }]
    );
    assert_eq!(
        year_buckets(&conn, 1, Some("seafile")).unwrap(),
        vec![YearBucket {
            year: 1970,
            count: 4
        }]
    );
    assert!(year_buckets(&conn, 2, Some("nextcloud"))
        .unwrap()
        .is_empty());

    assert_eq!(
        month_buckets(&conn, 1, None, None).unwrap(),
        vec![MonthBucket {
            key: "1970-01".to_owned(),
            year: 1970,
            month: 1,
            count: 5
        }]
    );
    assert_eq!(month_buckets(&conn, 1, None, Some(1970)).unwrap().len(), 1);
    assert!(month_buckets(&conn, 1, None, Some(1971))
        .unwrap()
        .is_empty());

    let covers = period_covers(&conn, 1, Some("seafile"), 1970, Some(1), 4).unwrap();
    assert_eq!(
        covers.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![9, 7, 2, 1]
    );
    assert!(period_covers(&conn, 1, None, 1970, Some(1), 4)
        .unwrap()
        .iter()
        .all(|item| item.cloud != "nextcloud" || item.id == 3));
    assert!(period_covers(&conn, 2, Some("seafile"), 1970, None, 4)
        .unwrap()
        .iter()
        .all(|item| item.owner_id == 2));
}

#[test]
fn album_predicates_are_fixed_and_owner_scoped() {
    let conn = seeded();

    assert_eq!(album_count(&conn, 1, None, AlbumKind::All).unwrap(), 5);
    assert_eq!(
        album_count(&conn, 1, Some("seafile"), AlbumKind::All).unwrap(),
        4
    );
    assert_eq!(
        album_count(&conn, 1, None, AlbumKind::Favorites).unwrap(),
        1
    );
    assert_eq!(album_count(&conn, 1, None, AlbumKind::Videos).unwrap(), 1);
    assert_eq!(album_count(&conn, 1, None, AlbumKind::Live).unwrap(), 1);
    assert_eq!(
        album_count(&conn, 1, None, AlbumKind::Screenshots).unwrap(),
        0
    );
    assert_eq!(album_count(&conn, 2, None, AlbumKind::All).unwrap(), 1);

    let videos = album_items(&conn, 1, None, AlbumKind::Videos, 4).unwrap();
    assert_eq!(videos.len(), 1);
    assert_eq!(videos[0].id, 2);

    let live = album_items(&conn, 1, Some("seafile"), AlbumKind::Live, 4).unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id, 9);

    let all = album_items(&conn, 1, None, AlbumKind::All, 4).unwrap();
    assert_eq!(
        all.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![9, 7, 3, 2]
    );
    assert!(album_items(&conn, 3, None, AlbumKind::All, 4)
        .unwrap()
        .iter()
        .all(|item| item.owner_id == 3));
}

#[test]
fn vault_metadata_is_owner_scoped() {
    let conn = seeded();

    let admin_vaults = vaults_for_user(&conn, 1).unwrap();
    assert_eq!(admin_vaults.len(), 1);
    assert_eq!(admin_vaults[0].uid, "v-admin");
    assert_eq!(admin_vaults[0].kdf_salt, "c2FsdA==");
    assert_eq!(admin_vaults[0].kdf_iterations, 310000);
    assert_eq!(admin_vaults[0].manifest_size, 512);

    let alice_vaults = vaults_for_user(&conn, 2).unwrap();
    assert_eq!(alice_vaults.len(), 1);
    assert_eq!(alice_vaults[0].name, "Kho Alice");
    assert!(vaults_for_user(&conn, 3).unwrap().is_empty());

    assert!(vault_by_id(&conn, 1, admin_vaults[0].id).unwrap().is_some());
    assert!(vault_by_id(&conn, 2, admin_vaults[0].id).unwrap().is_none());
    assert!(vault_by_id(&conn, 1, 99).unwrap().is_none());
}

#[test]
fn live_and_snapshot_connections_are_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("with space.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    conn.execute(
        "INSERT INTO users (id, username, display_name, password_hash, is_admin, active) \
         VALUES (1, 'admin', 'Admin', '', 1, 1)",
        [],
    )
    .unwrap();
    drop(conn);

    let live = Database::open_live(&path).unwrap();
    assert_eq!(live.mode(), OpenMode::LiveReadOnly);
    assert_eq!(live.probe().unwrap().users, 1);
    let read_only = live.connect().unwrap();
    assert!(read_only
        .execute_batch("CREATE TABLE should_fail (id INTEGER)")
        .is_err());

    let snapshot = Database::open_snapshot(&path).unwrap();
    assert_eq!(snapshot.mode(), OpenMode::Snapshot);
    let conn = snapshot.connect().unwrap();
    let username: String = conn
        .query_row("SELECT username FROM users WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(username, "admin");
}

#[test]
fn empty_database_path_is_rejected() {
    assert!(Database::open_live("").is_err());
    assert!(Database::open_snapshot("").is_err());
}
