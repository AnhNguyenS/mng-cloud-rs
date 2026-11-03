use std::{path::PathBuf, sync::Arc};

use mng_core::config::Config;
use mng_db::{Database, OpenMode};

/// Lazy database state. Opening is attempted at startup, but a missing or
/// unreadable legacy file must not take the static edge or health probes down.
#[derive(Clone)]
pub struct DatabaseState {
    pub database: Option<Arc<Database>>,
    pub path: PathBuf,
    pub mode: OpenMode,
    pub startup_error: Option<String>,
}

impl DatabaseState {
    pub fn load(config: &Config) -> Self {
        let path = config.database_path();
        let mode = if config.database_immutable {
            OpenMode::Snapshot
        } else {
            OpenMode::LiveReadOnly
        };
        let opened = if config.database_immutable {
            Database::open_snapshot(&path)
        } else {
            Database::open_live(&path)
        };
        match opened {
            Ok(database) => {
                let startup_error = match database.probe() {
                    Ok(probe) => {
                        tracing::info!(
                            path = %path.display(),
                            mode = ?mode,
                            schema_version = probe.schema_version,
                            users = probe.users,
                            "sqlite read model available"
                        );
                        None
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %path.display(),
                            mode = ?mode,
                            error = %error,
                            "sqlite read model is not usable yet"
                        );
                        Some(error.to_string())
                    }
                };
                Self {
                    database: Some(Arc::new(database)),
                    path,
                    mode,
                    startup_error,
                }
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    mode = ?mode,
                    error = %error,
                    "sqlite read model is unavailable"
                );
                Self {
                    database: None,
                    path,
                    mode,
                    startup_error: Some(error.to_string()),
                }
            }
        }
    }

    pub fn mode_name(&self) -> &'static str {
        match self.mode {
            OpenMode::LiveReadOnly => "live",
            OpenMode::Snapshot => "snapshot",
        }
    }
}
