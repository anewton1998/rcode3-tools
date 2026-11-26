//! Connection configuration.
//!
//! Follows the workspace env-var convention: a single required `DATABASE_URL`
//! plus optional pool-sizing knobs, each with a sensible `unwrap_or_else` default.
//! A `.env` file is loaded best-effort via `dotenvy` so local dev "just works".

use std::env;

use crate::error::{DbError, Result};

/// Pool + connection settings for [`Db`](crate::pool::Db).
///
/// The only mandatory field is `url`; everything else has a default tuned for a
/// small service. Build one directly, or via [`DbConfig::from_env`].
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Postgres connection string, e.g.
    /// `postgres://user:pass@host:5432/dbname`.
    pub url: String,
    /// Maximum pooled connections.
    pub max_connections: u32,
    /// Minimum idle connections kept warm.
    pub min_connections: u32,
    /// Max time (seconds) a checkout waits for a free connection before erroring.
    pub acquire_timeout_secs: u64,
    /// Max idle (seconds) before a connection is closed.
    pub idle_timeout_secs: u64,
    /// Max lifetime (seconds) of a pooled connection before recycling.
    pub max_lifetime_secs: u64,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: 10,
            min_connections: 0,
            acquire_timeout_secs: 30,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
        }
    }
}

impl DbConfig {
    /// Build a config from environment variables.
    ///
    /// Reads `DATABASE_URL` (required) plus optional `DB_MAX_CONNECTIONS`,
    /// `DB_MIN_CONNECTIONS`, `DB_ACQUIRE_TIMEOUT_SECS`, `DB_IDLE_TIMEOUT_SECS`,
    /// `DB_MAX_LIFETIME_SECS`. A `.env` file is loaded first (errors ignored, as
    /// the file is optional).
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Config`] if `DATABASE_URL` is missing/empty/non-UTF-8,
    /// or if an optional numeric override is not a valid integer.
    pub fn from_env() -> Result<Self> {
        // Best-effort: a missing .env is fine (prod injects real env vars).
        let _ = dotenvy::dotenv();

        let url = match env::var("DATABASE_URL") {
            Ok(v) if !v.trim().is_empty() => v,
            Ok(_) => return Err(DbError::config("DATABASE_URL is empty")),
            Err(env::VarError::NotPresent) => {
                return Err(DbError::config("DATABASE_URL is not set"));
            }
            Err(env::VarError::NotUnicode(_)) => {
                return Err(DbError::config("DATABASE_URL is not valid UTF-8"));
            }
        };

        let base = Self::default();
        let get = |key: &str| env::var(key).ok();
        Ok(Self {
            url,
            max_connections: parse_or("DB_MAX_CONNECTIONS", base.max_connections, get)?,
            min_connections: parse_or("DB_MIN_CONNECTIONS", base.min_connections, get)?,
            acquire_timeout_secs: parse_or(
                "DB_ACQUIRE_TIMEOUT_SECS",
                base.acquire_timeout_secs,
                get,
            )?,
            idle_timeout_secs: parse_or("DB_IDLE_TIMEOUT_SECS", base.idle_timeout_secs, get)?,
            max_lifetime_secs: parse_or("DB_MAX_LIFETIME_SECS", base.max_lifetime_secs, get)?,
        })
    }
}

/// Read `key` through the injected `get` lookup, parsing it as `T` and falling
/// back to `default` when absent.
///
/// The lookup is injected (rather than calling `env::var` directly) so the logic
/// is pure and unit-testable without mutating the process environment — which is
/// unsound to do from a multithreaded test in edition 2024. An empty/whitespace
/// value is treated as "unset"; a non-empty but unparseable value is an error so
/// misconfiguration fails loudly rather than silently.
fn parse_or<T>(key: &str, default: T, get: impl Fn(&str) -> Option<String>) -> Result<T>
where
    T: std::str::FromStr,
{
    match get(key) {
        Some(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<T>()
            .map_err(|_| DbError::config(format!("{key} is invalid: {raw:?}"))),
        _ => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A pure, in-memory env lookup so tests never touch the real environment.
    fn lookup<'a>(pairs: &[(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |key: &str| map.get(key).map(|v| (*v).to_string())
    }

    #[test]
    fn defaults_are_sane() {
        // GIVEN the default config
        let cfg = DbConfig::default();
        // THEN the pool sizing is a reasonable small-service baseline
        assert_eq!(cfg.max_connections, 10);
        assert_eq!(cfg.min_connections, 0);
        assert!(cfg.url.is_empty());
    }

    #[test]
    fn parse_or_falls_back_when_unset() {
        // GIVEN a lookup with no entry for the key
        let get = lookup(&[]);
        // WHEN parsed with a default
        let value = parse_or::<u32>("DB_TEST_UNSET", 42, get).expect("should fall back");
        // THEN the default is returned
        assert_eq!(value, 42);
    }

    #[test]
    fn parse_or_parses_a_valid_value() {
        // GIVEN a lookup holding a valid integer
        let get = lookup(&[("DB_TEST_KEY", "7")]);
        // WHEN parsed
        let value = parse_or::<u32>("DB_TEST_KEY", 1, get).expect("should parse");
        // THEN the parsed value wins over the default
        assert_eq!(value, 7);
    }

    #[test]
    fn parse_or_treats_whitespace_as_unset() {
        // GIVEN a lookup holding a whitespace-only value
        let get = lookup(&[("DB_TEST_KEY", "   ")]);
        // WHEN parsed
        let value = parse_or::<u32>("DB_TEST_KEY", 9, get).expect("whitespace is unset");
        // THEN the default is used
        assert_eq!(value, 9);
    }

    #[test]
    fn parse_or_rejects_garbage() {
        // GIVEN a lookup holding a non-integer value
        let get = lookup(&[("DB_TEST_KEY", "not-a-number")]);
        // WHEN parsed
        let result = parse_or::<u32>("DB_TEST_KEY", 1, get);
        // THEN it errors rather than silently using the default
        assert!(matches!(result, Err(DbError::Config(_))));
    }
}
