use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Minimum entropy accepted for the session secret. Shorter values are almost
/// always an accidental password rather than a generated key.
pub const MIN_SECRET_BYTES: usize = 32;
const TOKEN_VERSION: &str = "v1";
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_USERNAME_BYTES: usize = 128;
const CLOCK_SKEW_SECS: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session secret must be at least {MIN_SECRET_BYTES} bytes")]
    WeakSecret,
    #[error("session cookie name is invalid")]
    InvalidCookieName,
    #[error("session token is malformed")]
    Malformed,
    #[error("session signature is invalid")]
    BadSignature,
    #[error("session has expired")]
    Expired,
    #[error("session timestamp is in the future")]
    NotYetValid,
    #[error("session payload is invalid")]
    InvalidPayload,
    #[error("cannot encode session")]
    Encode,
    #[error("session secret is empty")]
    EmptySecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieConfig {
    pub name: String,
    pub secure: bool,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    key: [u8; 32],
    ttl_secs: u64,
    cookie: CookieConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub uid: i64,
    pub username: String,
    pub iat: u64,
    pub exp: u64,
    pub nonce: String,
    pub csrf: String,
}

impl SessionConfig {
    /// Derive a fixed-length HMAC key from an operator-provided secret. Hashing
    /// the input means callers can store raw bytes or a long passphrase without
    /// changing the token format.
    pub fn new(
        secret: &[u8],
        ttl_secs: u64,
        cookie_name: impl Into<String>,
        secure: bool,
    ) -> Result<Self, SessionError> {
        if secret.len() < MIN_SECRET_BYTES {
            return Err(SessionError::WeakSecret);
        }
        if !(60..=30 * 24 * 60 * 60).contains(&ttl_secs) {
            return Err(SessionError::InvalidPayload);
        }
        let name = cookie_name.into();
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(SessionError::InvalidCookieName);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&Sha256::digest(secret));
        Ok(Self {
            key,
            ttl_secs,
            cookie: CookieConfig { name, secure },
        })
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    pub fn cookie(&self) -> &CookieConfig {
        &self.cookie
    }

    pub fn issue(
        &self,
        uid: i64,
        username: &str,
        now: u64,
    ) -> Result<(Session, String), SessionError> {
        let session = Session {
            uid,
            username: username.to_owned(),
            iat: now,
            exp: now.saturating_add(self.ttl_secs),
            nonce: random_token(18),
            csrf: random_token(24),
        };
        self.validate(&session, now)?;
        let token = self.sign(&session)?;
        Ok((session, token))
    }

    /// Re-issue the same user with a fresh CSRF token and a renewed lifetime.
    /// Callers can use this after privilege changes or periodically.
    pub fn rotate(&self, session: &Session, now: u64) -> Result<(Session, String), SessionError> {
        self.issue(session.uid, &session.username, now)
    }

    pub fn verify(&self, token: &str, now: u64) -> Result<Session, SessionError> {
        let token = token.trim();
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
            return Err(SessionError::Malformed);
        }
        let mut parts = token.split('.');
        let (Some(version), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(SessionError::Malformed);
        };
        if version != TOKEN_VERSION {
            return Err(SessionError::Malformed);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| SessionError::Malformed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| SessionError::Malformed)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| SessionError::BadSignature)?;
        mac.update(version.as_bytes());
        mac.update(b".");
        mac.update(payload_b64.as_bytes());
        if mac.verify_slice(&signature).is_err() {
            return Err(SessionError::BadSignature);
        }

        let session: Session =
            serde_json::from_slice(&payload).map_err(|_| SessionError::Malformed)?;
        self.validate(&session, now)?;
        Ok(session)
    }

    fn sign(&self, session: &Session) -> Result<String, SessionError> {
        let payload = serde_json::to_vec(session).map_err(|_| SessionError::Encode)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| SessionError::BadSignature)?;
        mac.update(TOKEN_VERSION.as_bytes());
        mac.update(b".");
        mac.update(payload_b64.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{TOKEN_VERSION}.{payload_b64}.{signature}"))
    }

    fn validate(&self, session: &Session, now: u64) -> Result<(), SessionError> {
        if session.uid <= 0
            || session.username.is_empty()
            || session.username.len() > MAX_USERNAME_BYTES
            || session.username.chars().any(|c| c.is_control())
            || session.exp <= session.iat
            || session.exp - session.iat > self.ttl_secs + CLOCK_SKEW_SECS
            || session.iat > now.saturating_add(CLOCK_SKEW_SECS)
            || session.exp <= now
            || !valid_token(&session.nonce)
            || !valid_token(&session.csrf)
        {
            return Err(if session.exp <= now {
                SessionError::Expired
            } else if session.iat > now.saturating_add(CLOCK_SKEW_SECS) {
                SessionError::NotYetValid
            } else {
                SessionError::InvalidPayload
            });
        }
        Ok(())
    }

    pub fn cookie_header(&self, token: &str) -> String {
        let mut value = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            self.cookie.name, token, self.ttl_secs
        );
        if self.cookie.secure {
            value.push_str("; Secure");
        }
        value
    }

    pub fn clear_cookie_header(&self) -> String {
        let mut value = format!(
            "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            self.cookie.name
        );
        if self.cookie.secure {
            value.push_str("; Secure");
        }
        value
    }
}

impl Session {
    /// Compare a request header with the CSRF value bound to this session.
    pub fn csrf_matches(&self, candidate: &str) -> bool {
        let expected = self.csrf.as_bytes();
        let actual = candidate.trim().as_bytes();
        expected.len() == actual.len() && expected.ct_eq(actual).into()
    }
}

/// Read a session secret from a file. Whitespace is ignored so operators can
/// use `openssl rand -base64 48 > ...` or a hex value with a `hex:` prefix.
pub fn load_secret(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let text = fs::read_to_string(path)?;
    let text = text.trim();
    if text.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "session secret is empty",
        ));
    }
    if let Some(hex) = text.strip_prefix("hex:") {
        return hex::decode(hex.trim()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("session secret is not valid hex: {error}"),
            )
        });
    }
    Ok(text.as_bytes().to_vec())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn random_token(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

// Small local hex decoder to avoid another dependency in this crate.
mod hex {
    pub fn decode(text: &str) -> Result<Vec<u8>, String> {
        if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid hex".to_owned());
        }
        let mut bytes = Vec::with_capacity(text.len() / 2);
        for index in (0..text.len()).step_by(2) {
            bytes.push(
                u8::from_str_radix(&text[index..index + 2], 16)
                    .map_err(|error| error.to_string())?,
            );
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn config() -> SessionConfig {
        SessionConfig::new(
            b"a-very-long-test-secret-that-is-32-bytes!",
            3600,
            "mng_session",
            true,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_and_binds_csrf() {
        let config = config();
        let (session, token) = config.issue(42, "alice", NOW).unwrap();
        let checked = config.verify(&token, NOW + 10).unwrap();
        assert_eq!(checked, session);
        assert!(checked.csrf_matches(&session.csrf));
        assert!(!checked.csrf_matches("nope"));
        assert!(!checked.csrf_matches(&session.csrf[1..]));
    }

    #[test]
    fn rejects_tampering_and_wrong_keys() {
        let config = config();
        let (_, token) = config.issue(1, "alice", NOW).unwrap();
        let mut bytes = token.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(matches!(
            config.verify(&tampered, NOW),
            Err(SessionError::BadSignature)
        ));

        let other = SessionConfig::new(
            b"another-long-test-secret-that-is-32-bytes",
            3600,
            "mng_session",
            true,
        )
        .unwrap();
        let (_, token) = config.issue(1, "alice", NOW).unwrap();
        assert!(matches!(
            other.verify(&token, NOW),
            Err(SessionError::BadSignature)
        ));
    }

    #[test]
    fn rejects_expired_future_and_weak_config() {
        let config = config();
        let (_, token) = config.issue(1, "alice", NOW).unwrap();
        assert!(matches!(
            config.verify(&token, NOW + 3600),
            Err(SessionError::Expired)
        ));
        assert!(matches!(
            config.verify(&token, NOW - 3600),
            Err(SessionError::NotYetValid)
        ));
        assert!(matches!(
            SessionConfig::new(b"short", 3600, "mng_session", true),
            Err(SessionError::WeakSecret)
        ));
        assert!(matches!(
            SessionConfig::new(b"01234567890123456789012345678901", 3600, "bad name", true),
            Err(SessionError::InvalidCookieName)
        ));
    }

    #[test]
    fn rotates_csrf_and_lifetime() {
        let config = config();
        let (session, _) = config.issue(1, "alice", NOW).unwrap();
        let (rotated, token) = config.rotate(&session, NOW + 60).unwrap();
        assert_eq!(rotated.uid, session.uid);
        assert_eq!(rotated.iat, NOW + 60);
        assert_ne!(rotated.csrf, session.csrf);
        assert!(!rotated.csrf_matches(&session.csrf));
        assert_eq!(config.verify(&token, NOW + 60).unwrap(), rotated);
    }

    #[test]
    fn cookie_attributes_are_explicit() {
        let config = config();
        let value = config.cookie_header("token");
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(value.contains("Path=/"));
        assert!(value.contains("Secure"));
        assert!(config.clear_cookie_header().contains("Max-Age=0"));

        let local = SessionConfig::new(
            b"a-very-long-test-secret-that-is-32-bytes!",
            3600,
            "mng_session",
            false,
        )
        .unwrap();
        assert!(!local.cookie_header("token").contains("Secure"));
    }

    #[test]
    fn loads_secret_from_file_and_hex() {
        let path = std::env::temp_dir().join(format!(
            "mng-auth-secret-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::write(&path, "01234567890123456789012345678901\n").unwrap();
        assert_eq!(load_secret(&path).unwrap().len(), 32);
        fs::write(
            &path,
            "hex:3031323334353637383930313233343536373839303132333435363738393031",
        )
        .unwrap();
        assert_eq!(load_secret(&path).unwrap().len(), 32);
        fs::remove_file(&path).ok();
    }
}
