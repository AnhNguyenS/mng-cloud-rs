//! Seafile-compatible encryption and content-addressed chunk helpers.

pub mod e2ee;

pub use e2ee::{block_id, RepoKey, BLOCK_BYTES, FIXED_SALT};
