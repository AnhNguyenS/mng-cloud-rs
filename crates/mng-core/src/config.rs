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
    pub public_url: String,
    pub log_filter: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8090".to_owned(),
            web_root: PathBuf::from("/var/www/mng-cloud-app/current"),
            data_dir: PathBuf::from("/var/lib/mng-cloud"),
            public_url: String::new(),
            log_filter: "info,mngd=debug".to_owned(),
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
        config.apply_env();
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
        if self.public_url.contains(' ') {
            return Err(Error::Config("public_url contains a space".into()));
        }
        Ok(())
    }

    fn apply_env(&mut self) {
        if let Ok(value) = std::env::var("MNGD_BIND") {
            self.bind = value;
        }
        if let Ok(value) = std::env::var("MNGD_WEB_ROOT") {
            self.web_root = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("MNGD_DATA_DIR") {
            self.data_dir = PathBuf::from(value);
        }
        if let Ok(value) = std::env::var("MNGD_PUBLIC_URL") {
            self.public_url = value;
        }
        if let Ok(value) = std::env::var("MNGD_LOG_FILTER") {
            self.log_filter = value;
        }
    }
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
}
