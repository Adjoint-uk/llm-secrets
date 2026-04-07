use thiserror::Error;

// Variants are declared up-front so the surface is visible and CI doesn't
// thrash as commands are wired up. Remove this allow once every variant is
// constructed somewhere (target: end of v0.2).
#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum Error {
    #[error("secrets store not found — run `llms init` first")]
    StoreNotFound,

    #[error("secret not found: {0}")]
    KeyNotFound(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("policy denied access to '{key}': {reason}")]
    PolicyDenied { key: String, reason: String },

    #[error("lease expired: {0}")]
    LeaseExpired(String),

    #[error("session not active — run `llms session-start` first")]
    NoSession,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
