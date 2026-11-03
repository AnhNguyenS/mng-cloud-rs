#![forbid(unsafe_code)]

//! Read-only SQLite access for the MNG Cloud edge.
//!
//! This crate intentionally does not run migrations or write to the legacy
//! database. The PHP application remains the only writer until the cutover.

pub mod model;
pub mod read;

pub use model::{Cloud, Item, ItemCount, ItemQuery, PublicUser, ThumbStateCount, User};
pub use read::{
    all_users, cloud_for_user, clouds_for_user, count_items, item_by_id, item_by_path, item_counts,
    list_items, thumb_state_counts, user_by_id, user_by_username, Database, DbProbe, OpenMode,
    DEFAULT_LIMIT, MAX_LIMIT, MAX_OFFSET,
};
