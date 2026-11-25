//! Test-only helpers, exposed only with the `testutil` feature.
//!
//! Lets downstream crates (e.g. `support-bin`) reuse the same throwaway-Postgres
//! setup as this crate's own integration tests, instead of duplicating the
//! testcontainers boilerplate. Enable with `db = { ..., features = ["testutil"] }`
//! in a `[dev-dependencies]` section.

use crate::{Db, DbConfig};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// Postgres version to test against. The schemas use core `gen_random_uuid()`
/// (Postgres 13+), so pin a modern image rather than the module's older default.
const POSTGRES_TAG: &str = "16-alpine";

/// A running Postgres container plus a connected, migrated `Db` and the URL used
/// to reach it (so a test can open a second connection without re-deriving it).
///
/// Fields drop in declaration order: `db` (the pool) is dropped **before** the
/// container, so the pool's background reaper shuts down before the database it
/// points at disappears.
pub struct TestDb {
    /// A connected, migrated handle.
    pub db: Db,
    /// The connection URL for the running container.
    pub url: String,
    /// Held last so it is dropped last — keeps the container alive for the test.
    _node: ContainerAsync<Postgres>,
}

/// Spin up a Postgres container and return a connected, migrated handle.
///
/// # Panics
///
/// Panics if the container cannot be started or the database cannot be reached —
/// appropriate for a test fixture.
pub async fn fresh_db() -> TestDb {
    let node = Postgres::default()
        .with_tag(POSTGRES_TAG)
        .start()
        .await
        .expect("start postgres container");

    let url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        node.get_host().await.expect("host"),
        node.get_host_port_ipv4(5432).await.expect("port")
    );

    let config = DbConfig {
        url: url.clone(),
        ..DbConfig::default()
    };
    let db = Db::connect(&config).await.expect("connect + migrate");
    TestDb {
        db,
        url,
        _node: node,
    }
}
