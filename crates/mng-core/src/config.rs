use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;

/// Runtime configuration for `mngd`.
///
/// Values are loaded from a TOML file and can be overridden by environment
/// variables, which keeps secrets out of the file when a process manager
/// injects them.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub bind: String,
    pub web_root: PathBuf,
    pub data_dir: PathBuf,
    pub database: Option<PathBuf>,
    pub database_immutable: bool,
    pub public_url: String,
    pub log_filter: String,
    /// File containing the session signing secret. `MNGD_SESSION_SECRET` takes
    /// precedence and `MNGD_SESSION_SECRET_FILE` overrides this path.
    pub session_key_file: PathBuf,
    pub session_ttl_secs: u64,
    pub session_cookie: String,
    pub session_cookie_secure: bool,
    pub login_max_attempts: u32,
    pub login_window_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8090".to_owned(),
            web_root: PathBuf::from("/var/www/mng-cloud-app/current"),
            data_dir: PathBuf::from("/var/lib/mng-cloud"),
            database: None,
            database_immutable: false,
            public_url: String::new(),
            log_filter: "info,mngd=debug".to_owned(),
            session_key_file: PathBuf::from("/etc/mng-cloud/session.key"),
            session_ttl_secs: 12 * 60 * 60,
            session_cookie: "mng_session".to_owned(),
            session_cookie_secure: true,
            login_max_attempts: 5,
            login_window_secs: 5 * 60,
        }
    }
}

impl Config {
    /// Load an optional TOML file, then apply `MNGD_*` overrides.
    pub fn load(path: Option<&Path>) -> Result<Self, Error> {
        let mut config = match path {
            Some(path) if path.is_file() => {
                let text = std::fs::read_to_string(path).map_err(|source| Error::ConfigIo {
                    path: path.display().to_string(),
                    source,
                })?;
                toml::from_str(&text)?
            }
            Some(path) => {
                return Err(Error::Config(format!(
                    "configuration file does not exist: {}",
                    path.display()
                )))
            }
            None => Self::default(),
        };
        config.apply_env()?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.bind.trim().is_empty() {
            return Err(Error::Config("bind address is empty".into()));
        }
        if self.web_root.as_os_str().is_empty() {
            return Err(Error::Config("web_root is empty".into()));
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(Error::Config("data_dir is empty".into()));
        }
        if self
            .database
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(Error::Config("database path is empty".into()));
        }
        if self.public_url.contains(' ') {
            return Err(Error::Config("public_url contains a space".into()));
        }
        if self.session_key_file.as_os_str().is_empty() {
            return Err(Error::Config("session_key_file is empty".into()));
        }
        if !(60..=30 * 24 * 60 * 60).contains(&self.session_ttl_secs) {
            return Err(Error::Config(
                "session_ttl_secs must be between 60 and 2592000".into(),
            ));
        }
        if self.session_cookie.is_empty()
            || self.session_cookie.len() > 64
            || !self
                .session_cookie
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(Error::Config(
                "session_cookie must be 1-64 characters of [A-Za-z0-9_-]".into(),
            ));
        }
        if self.login_max_attempts == 0 || self.login_max_attempts > 1000 {
            return Err(Error::Config(
                "login_max_attempts must be between 1 and 1000".into(),
            ));
        }
        if !(1..=86_400).contains(&self.login_window_secs) {
            return Err(Error::Config(
                "login_window_secs must be between 1 and 86400".into(),
            ));
        }
        Ok(())
    }

    /// Explicit database path, or the legacy SQLite file below `data_dir`.
    pub fn database_path(&self) -> PathBuf {
        self.database
            .clone()
            .unwrap_or_else(|| self.data_dir.join("mng-cloud.sqlite"))
    }

    fn apply_env(&mut self) -> Result<(), Error> {
        if let Ok(value) = std::env::var("MNGD_BIND") {
            self.bind = value;
        }
        if let Ok(value) = std::env::var("MNGD_WEB_ROOT") {
            self.web_root = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("MNGD_DATA_DIR") {
            self.data_dir = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("MNGD_DATABASE") {
            self.database = Some(PathBuf::from(value));
        }
        if let Ok(value) = std::env::var("MNGD_DATABASE_IMMUTABLE") {
            self.database_immutable = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Ok(value) = std::env::var("MNGD_PUBLIC_URL") {
            self.public_url = value;
        }
        if let Ok(value) = std::env::var("MNGD_LOG_FILTER") {
            self.log_filter = value;
        }
        if let Ok(value) = std::env::var("MNGD_SESSION_KEY_FILE") {
            self.session_key_file = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("MNGD_SESSION_COOKIE") {
            self.session_cookie = value;
        }
        if let Ok(value) = std::env::var("MNGD_SESSION_COOKIE_SECURE") {
            self.session_cookie_secure = matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        env_number("MNGD_SESSION_TTL_SECS", &mut self.session_ttl_secs)?;
        env_number("MNGD_LOGIN_MAX_ATTEMPTS", &mut self.login_max_attempts)?;
        env_number("MNGD_LOGIN_WINDOW_SECS", &mut self.login_window_secs)?;
        Ok(())
    }
}

fn env_number<T>(name: &str, target: &mut T) -> Result<(), Error>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    if let Ok(value) = std::env::var(name) {
        *target = value
            .trim()
            .parse()
            .map_err(|error| Error::Config(format!("{name} is not a valid number: {error}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn empty_bind_is_rejected() {
        let mut config = Config::default();
        config.bind.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn database_defaults_below_data_dir() {
        let config = Config {
            data_dir: PathBuf::from("/srv/mng"),
            ..Config::default()
        };
        assert_eq!(
            config.database_path(),
            PathBuf::from("/srv/mng/mng-cloud.sqlite")
        );

        let config = Config {
            database: Some(PathBuf::from("/snapshot/mng.sqlite")),
            ..Config::default()
        };
        assert_eq!(
            config.database_path(),
            PathBuf::from("/snapshot/mng.sqlite")
        );
    }

    #[test]
    fn empty_database_is_rejected() {
        let config = Config {
            database: Some(PathBuf::new()),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn auth_defaults_are_conservative() {
        let config = Config::default();
        assert!(config.session_cookie_secure);
        assert_eq!(config.session_cookie, "mng_session");
        assert_eq!(config.session_ttl_secs, 43_200);
        assert_eq!(config.login_max_attempts, 5);
    }

    #[test]
    fn invalid_auth_settings_are_rejected() {
        assert!(Config {
            session_ttl_secs: 10,
            ..Config::default()
        }
        .validate()
        .is_err());

        assert!(Config {
            session_cookie: "bad name".into(),
            ..Config::default()
        }
        .validate()
        .is_err());

        assert!(Config {
            login_max_attempts: 0,
            ..Config::default()
        }
        .validate()
        .is_err());

        assert!(Config {
            login_window_secs: 0,
            ..Config::default()
        }
        .validate()
        .is_err());

        assert!(Config {
            session_key_file: PathBuf::new(),
            ..Config::default()
        }
        .validate()
        .is_err());
    }
}
