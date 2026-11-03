use argon2::{Argon2, PasswordHash, PasswordVerifier};
use bcrypt::BcryptError;

/// A fixed hash used to equalise the work done for an unknown username. The
/// plaintext is public and never matches a real account.
pub const DUMMY_BCRYPT_HASH: &str = "$2b$10$/zz.uCobJ8PliYRPoujpHuQQ1RCjHFQe2YjMxcdsealWSlCQfHbLi";

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("unsupported password hash algorithm")]
    Unsupported,
    #[error("invalid password hash encoding")]
    InvalidEncoding,
    #[error("bcrypt verification failed: {0}")]
    Bcrypt(#[from] BcryptError),
    #[error("argon2 verification failed")]
    Argon2,
}

/// Verify a password against a stored PHP-compatible hash.
///
/// Supported formats:
/// - bcrypt `$2y$`, `$2b$` and `$2a$` (Seafile/PHP `password_hash`)
/// - Argon2 `$argon2id$`, `$argon2i$`, `$argon2d$` with parameters encoded in
///   the hash
///
/// Unknown formats are an error rather than a silent `false`: an operator must
/// migrate them deliberately instead of locking a user out without a reason.
pub fn verify_password(hash: &str, password: &str) -> Result<bool, PasswordError> {
    let hash = hash.trim();
    if hash.is_empty() || password.is_empty() {
        return Ok(false);
    }
    if hash.starts_with("$2y$") || hash.starts_with("$2b$") || hash.starts_with("$2a$") {
        // The bcrypt crate expects the `$2b$` marker; `$2y$` is the same
        // algorithm with a different historical prefix.
        let normalized = if let Some(rest) = hash.strip_prefix("$2y$") {
            format!("$2b${rest}")
        } else {
            hash.to_owned()
        };
        return bcrypt::verify(password, &normalized).map_err(PasswordError::from);
    }
    if hash.starts_with("$argon2") {
        let parsed = PasswordHash::new(hash).map_err(|_| PasswordError::InvalidEncoding)?;
        return Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok());
    }
    Err(PasswordError::Unsupported)
}

/// Perform the same bcrypt work as a real verification, then always fail.
/// Use this when the username is unknown or inactive so response timing does
/// not reveal account existence.
pub fn dummy_verify(password: &str) -> bool {
    if password.is_empty() {
        return false;
    }
    bcrypt::verify(password, DUMMY_BCRYPT_HASH).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        PasswordHasher,
    };

    #[test]
    fn verifies_bcrypt_2b_and_2y() {
        let hash = bcrypt::hash("correct horse", 4).unwrap();
        assert!(verify_password(&hash, "correct horse").unwrap());
        assert!(!verify_password(&hash, "wrong").unwrap());

        let two_y = format!("$2y${}", hash.trim_start_matches("$2b$"));
        assert!(verify_password(&two_y, "correct horse").unwrap());
    }

    #[test]
    fn verifies_argon2id() {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(b"secret", &salt)
            .unwrap()
            .to_string();
        assert!(verify_password(&hash, "secret").unwrap());
        assert!(!verify_password(&hash, "nope").unwrap());
    }

    #[test]
    fn rejects_unknown_and_empty_hashes() {
        assert!(matches!(
            verify_password("plaintext", "x"),
            Err(PasswordError::Unsupported)
        ));
        assert!(!verify_password("", "x").unwrap());
        assert!(!verify_password(DUMMY_BCRYPT_HASH, "").unwrap());
    }

    #[test]
    fn dummy_hash_is_valid_and_never_matches() {
        assert!(bcrypt::verify("mng-dummy-password", DUMMY_BCRYPT_HASH).unwrap());
        assert!(!dummy_verify("anything"));
    }
}
