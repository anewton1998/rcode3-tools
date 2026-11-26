//! Crate-wide error type.
//!
//! Mirrors the workspace convention (see `support-bin`'s `DequeueError`): a
//! domain-specific `thiserror` enum that wraps the underlying sqlx failures with
//! a contextual message rather than leaking `sqlx::Error` at every call site.

use thiserror::Error;

/// The result type returned by every fallible operation in this crate.
pub type Result<T> = std::result::Result<T, DbError>;

/// Errors surfaced by the database layer.
///
/// `#[non_exhaustive]` so new variants can be added without a semver break;
/// downstream matchers must include a catch-all arm.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    /// A query, insert, or connection-pool failure from sqlx.
    #[error("database error: {0}")]
    Sql(#[from] sqlx::Error),

    /// A migration failed to apply (bad SQL, checksum mismatch, lock timeout).
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Configuration was missing or malformed (e.g. `DATABASE_URL` absent).
    #[error("configuration error: {0}")]
    Config(String),
}

impl DbError {
    /// Convenience constructor for [`DbError::Config`].
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
}
