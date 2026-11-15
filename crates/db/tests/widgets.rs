//! Integration tests against a real Postgres via testcontainers.
//!
//! These always run (per project decision) and require a Docker daemon. Each test
//! gets its own throwaway container; the `ryuk` reaper (or the held
//! `ContainerAsync`) cleans it up at test teardown.

use db::widgets::{self, Widget};
use db::{Db, DbConfig};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

/// Postgres version to test against. The crate's example schema uses the core
/// `gen_random_uuid()` (Postgres 13+), so pin a modern image rather than the
/// module's default (an older release that lacks it).
const POSTGRES_TAG: &str = "16-alpine";

/// A running Postgres container plus a connected, migrated `Db` and the URL used
/// to reach it (so a test can open a second connection without re-deriving it).
struct TestDb {
    /// Held only to keep the container alive for the test's lifetime; dropped (and
    /// reaped) when the `TestDb` goes out of scope.
    _node: ContainerAsync<Postgres>,
    db: Db,
    url: String,
}

/// Spin up a Postgres container and return a connected, migrated handle. The
/// container is held alive by the returned [`TestDb`] for the test's duration.
async fn fresh_db() -> TestDb {
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
        _node: node,
        db,
        url,
    }
}

#[tokio::test]
async fn insert_then_get_returns_widget() {
    // GIVEN a fresh database
    let ctx = fresh_db().await;
    // WHEN a widget is inserted and re-fetched by its id
    let inserted = widgets::insert_widget(&ctx.db, "sprocket")
        .await
        .expect("insert");
    let found = widgets::get_widget(&ctx.db, inserted.id)
        .await
        .expect("get")
        .expect("row present");
    // THEN the persisted row matches what was inserted
    assert_eq!(found.id, inserted.id);
    assert_eq!(found.name, "sprocket");
}

#[tokio::test]
async fn get_missing_returns_none() {
    // GIVEN a fresh database with no rows
    let ctx = fresh_db().await;
    // WHEN we look up a random id that was never inserted
    let found = widgets::get_widget(&ctx.db, Uuid::new_v4())
        .await
        .expect("get");
    // THEN no row is returned
    assert!(found.is_none());
}

#[tokio::test]
async fn list_returns_newest_first() {
    // GIVEN three widgets inserted in sequence
    let ctx = fresh_db().await;
    let a = widgets::insert_widget(&ctx.db, "a")
        .await
        .expect("insert a");
    let b = widgets::insert_widget(&ctx.db, "b")
        .await
        .expect("insert b");
    let c = widgets::insert_widget(&ctx.db, "c")
        .await
        .expect("insert c");
    // WHEN all widgets are listed
    let listed = widgets::list_widgets(&ctx.db).await.expect("list");
    // THEN they come back most-recently-created first
    let names: Vec<&str> = listed.iter().map(|w: &Widget| w.name.as_str()).collect();
    assert_eq!(names, vec!["c", "b", "a"]);
    assert_eq!(listed[0].id, c.id);
    assert_eq!(listed[1].id, b.id);
    assert_eq!(listed[2].id, a.id);
}

#[tokio::test]
async fn count_reflects_inserts() {
    // GIVEN a fresh database
    let ctx = fresh_db().await;
    // WHEN two widgets are inserted
    assert_eq!(widgets::count_widgets(&ctx.db).await.expect("count 0"), 0);
    widgets::insert_widget(&ctx.db, "one")
        .await
        .expect("insert one");
    widgets::insert_widget(&ctx.db, "two")
        .await
        .expect("insert two");
    // THEN the count reflects both
    assert_eq!(widgets::count_widgets(&ctx.db).await.expect("count 2"), 2);
}

#[tokio::test]
async fn migrations_are_idempotent() {
    // GIVEN a database that has already been migrated once
    let ctx = fresh_db().await;
    let config = DbConfig {
        url: ctx.url.clone(),
        ..DbConfig::default()
    };
    // WHEN a second connection runs migrations against the same database
    let second = Db::connect(&config).await;
    // THEN it succeeds without re-applying or erroring on existing tables
    assert!(second.is_ok(), "second migrate should be a no-op");
    let second = second.expect("second connect");
    assert_eq!(widgets::count_widgets(&second).await.expect("count"), 0);
}

#[tokio::test]
async fn connect_rejects_empty_url() {
    // GIVEN a config whose url was never populated
    let config = DbConfig::default();
    // WHEN we try to connect
    let result = Db::connect(&config).await;
    // THEN it fails with a clear config error rather than a low-level connection error
    assert!(
        matches!(
            result,
            Err(db::DbError::Config(msg)) if msg.contains("empty")
        ),
        "expected an empty-url config error"
    );
}
