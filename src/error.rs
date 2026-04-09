use thiserror::Error;

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

    // Reserved for v0.3 (#5). Allowed dead until the policy engine lands.
    #[allow(dead_code)]
    #[error("policy denied access to '{key}': {reason}")]
    PolicyDenied { key: String, reason: String },

    // Reserved for v0.4 (#7).
    #[allow(dead_code)]
    #[error("lease expired: {0}")]
    LeaseExpired(String),

    #[error("no active session — run `llms session-start` (or `llms session-start --ttl 8h`)")]
    NoSession,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
