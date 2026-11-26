//! Integration tests against a real Postgres via the shared `db::testutil`
//! container helper. Run with `cargo test -p db --features testutil`.

use db::testutil::fresh_db;
use db::widgets::{self, Widget};
use db::{Db, DbConfig};
use uuid::Uuid;

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
