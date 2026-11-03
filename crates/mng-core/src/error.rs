use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported Seafile encryption version: {0}")]
    UnsupportedVersion(u32),

    #[error("invalid hex value for {0}")]
    InvalidHex(&'static str),

    #[error("wrong library password")]
    WrongPassword,

    #[error("the encrypted library key is invalid")]
    InvalidLibraryKey,

    #[error("the ciphertext is invalid")]
    InvalidCiphertext,

    #[error("a block exceeds the 8 MiB limit: {0} bytes")]
    BlockTooLarge(usize),

    #[error("encryption version 3 requires a 32-byte salt")]
    InvalidSalt,

    #[error("configuration file is invalid: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("cannot read configuration file {path}: {source}")]
    ConfigIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("configuration error: {0}")]
    Config(String),
}
