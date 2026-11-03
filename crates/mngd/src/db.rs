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

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("database is unavailable: {}", .0.as_deref().unwrap_or("not opened"))]
    Unavailable(Option<String>),
    #[error("database query failed: {0}")]
    Query(#[from] mng_db::read::Error),
    #[error("database task failed: {0}")]
    Task(String),
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

    /// Run a read-only query on the connection pool. The connection is opened
    /// inside the blocking task so a slow query never blocks the async runtime.
    pub async fn read<T, F>(&self, operation: F) -> Result<T, ReadError>
    where
        T: Send + 'static,
        F: FnOnce(&Database) -> Result<T, mng_db::read::Error> + Send + 'static,
    {
        let Some(database) = self.database.clone() else {
            return Err(ReadError::Unavailable(self.startup_error.clone()));
        };
        match tokio::task::spawn_blocking(move || operation(&database)).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(ReadError::Query(error)),
            Err(error) => Err(ReadError::Task(error.to_string())),
        }
    }
}
