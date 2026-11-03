#![forbid(unsafe_code)]

//! Authentication primitives for `mngd`.
//!
//! The crate deliberately contains no database access and no HTTP framework
//! types. `mngd` supplies the user row and the client address, then uses these
//! primitives to verify a password, issue a signed session cookie and enforce
//! login throttling.

mod password;
mod rate_limit;
mod session;

pub use password::{dummy_verify, verify_password, PasswordError, DUMMY_BCRYPT_HASH};
pub use rate_limit::{Decision, RateLimiter};
pub use session::{
    load_secret, unix_now, CookieConfig, Session, SessionConfig, SessionError, MIN_SECRET_BYTES,
};
