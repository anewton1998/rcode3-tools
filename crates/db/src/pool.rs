//! The [`Db`] handle: a thin, cloneable wrapper over a sqlx `PgPool`.
//!
//! `PgPool` is itself an `Arc`-backed, cheap-to-clone pool, so `Db` can be
//! shared across axum handlers via `State` without further wrapping. Construction
//! always runs migrations so a freshly connected database is at the current
//! schema version.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::config::DbConfig;
use crate::error::Result;

/// Migrations embedded at compile time from `./migrations`.
///
/// The `migrate!` macro reads the SQL files during the build (it does **not**
/// need a live database), which keeps with the runtime-query design: nothing in
/// this crate requires `DATABASE_URL` at compile time.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// A cloneable handle to a Postgres database.
#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Connect using an explicit [`DbConfig`] and apply pending migrations.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Sql`](crate::error::DbError::Sql) if the pool cannot be
    /// established, or [`DbError::Migrate`](crate::error::DbError::Migrate) if a
    /// migration fails to apply.
    ///
    /// [`DbError::Sql`]: crate::error::DbError::Sql
    pub async fn connect(config: &DbConfig) -> Result<Self> {
        // Fail fast with a clear config error rather than a confusing low-level
        // connection failure when the url was never populated.
        if config.url.trim().is_empty() {
            return Err(crate::error::DbError::config("DbConfig.url is empty"));
        }

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
            .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
            .max_lifetime(Duration::from_secs(config.max_lifetime_secs))
            .connect(&config.url)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Connect using configuration read from the environment.
    ///
    /// # Errors
    ///
    /// Propagates [`DbConfig::from_env`](crate::config::DbConfig::from_env)
    /// errors plus the same connect/migrate errors as [`Db::connect`].
    pub async fn connect_from_env() -> Result<Self> {
        let config = DbConfig::from_env()?;
        Self::connect(&config).await
    }

    /// Apply any pending migrations against the connected database.
    ///
    /// Idempotent: already-applied migrations are skipped, so calling this on an
    /// up-to-date database is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Migrate`](crate::error::DbError::Migrate) if a
    /// migration fails (bad SQL, checksum mismatch, lock timeout).
    pub async fn migrate(&self) -> Result<()> {
        MIGRATOR.run(&self.pool).await?;
        // `run` is a no-op when everything is already applied, so this is debug
        // rather than info — it fires on every connect regardless of pending work.
        tracing::debug!("database migrations up to date");
        Ok(())
    }

    /// Escape hatch to the underlying [`PgPool`] for advanced use.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
