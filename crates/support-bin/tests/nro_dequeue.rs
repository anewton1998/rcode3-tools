//! Integration tests for the DB-backed dequeue pipeline, against a real
//! Postgres via `db::testutil`. Run with `cargo test -p support-bin` (Docker).
//!
//! The dry-run tests exercise the claim / classify / release path with no
//! network. The real-RDAP test is `#[ignore]`d (it hits the live internet).

use std::time::Duration;

use icann_rdap_client::prelude::{ClientConfig, MemoryBootstrapStore, create_client};
use support_bin::nro_dequeue::{DequeueConfig, dequeue_all};
use support_bin::nro_queue::NRO_TOPIC;

/// Build the RDAP + geofeed clients the dequeue needs (unused in dry-run).
fn build_clients() -> (
    icann_rdap_client::http::Client,
    MemoryBootstrapStore,
    reqwest::Client,
) {
    let client = create_client(&ClientConfig::default()).expect("rdap client");
    let store = MemoryBootstrapStore::new();
    let geofeed_client = reqwest::Client::new();
    (client, store, geofeed_client)
}

fn dry_config(max_items: Option<usize>) -> DequeueConfig {
    DequeueConfig {
        min_interval: Duration::from_millis(1),
        lease: Duration::from_secs(30),
        max_attempts: 3,
        retry_backoff: Duration::from_secs(1),
        claim_batch: 50,
        dry_run: true,
        max_items,
    }
}

#[tokio::test]
async fn dry_run_counts_and_restores_the_queue() {
    // GIVEN a queue with two IP records and one AS record (distinct registries)
    let ctx = db::testutil::fresh_db().await;
    db::queue::enqueue(
        &ctx.db,
        NRO_TOPIC,
        "apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A|e-stats",
        "apnic",
        None,
    )
    .await
    .expect("enqueue apnic");
    db::queue::enqueue(
        &ctx.db,
        NRO_TOPIC,
        "arin|US|asn|1|1|20010920|assigned|e5|e-stats",
        "arin",
        None,
    )
    .await
    .expect("enqueue arin");
    db::queue::enqueue(
        &ctx.db,
        NRO_TOPIC,
        "ripencc|DE|ipv6|2001:db8::|32|20100101|assigned|b|e-stats",
        "ripencc",
        None,
    )
    .await
    .expect("enqueue ripencc");

    let (client, store, geofeed) = build_clients();

    // WHEN drained in dry-run (no network, no stores)
    let stats = dequeue_all(&ctx.db, &client, &store, &geofeed, &dry_config(None))
        .await
        .expect("dequeue");

    // THEN the counts reflect the fixture
    assert_eq!(stats.processed, 2);
    assert_eq!(stats.discarded_asn, 1);
    assert_eq!(stats.queried, 0);
    assert_eq!(stats.saved, 0);
    // AND the queue is fully restored to pending (nothing consumed)
    let counts = db::queue::count_by_status(&ctx.db, NRO_TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&3));
    assert_eq!(counts.get("done"), None);
}

#[tokio::test]
async fn max_items_releases_the_remainder() {
    // GIVEN two IP records in two registries and a run capped at one
    let ctx = db::testutil::fresh_db().await;
    db::queue::enqueue(
        &ctx.db,
        NRO_TOPIC,
        "apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A|e-stats",
        "apnic",
        None,
    )
    .await
    .expect("enqueue apnic");
    db::queue::enqueue(
        &ctx.db,
        NRO_TOPIC,
        "ripencc|DE|ipv4|192.0.2.0|256|20110811|assigned|B|e-stats",
        "ripencc",
        None,
    )
    .await
    .expect("enqueue ripencc");

    let (client, store, geofeed) = build_clients();

    // WHEN drained in dry-run capped at one item
    let stats = dequeue_all(&ctx.db, &client, &store, &geofeed, &dry_config(Some(1)))
        .await
        .expect("dequeue");

    // THEN only one was processed and both remain pending
    assert_eq!(stats.processed, 1);
    let counts = db::queue::count_by_status(&ctx.db, NRO_TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&2));
}

#[tokio::test]
#[ignore = "hits the live RDAP internet; run explicitly with `-- --ignored`"]
async fn real_query_stores_a_result() {
    // GIVEN a queue with one real, RDAP-resolvable address (APNIC 1.0.0.0)
    let ctx = db::testutil::fresh_db().await;
    db::queue::enqueue(
        &ctx.db,
        NRO_TOPIC,
        "apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A|e-stats",
        "apnic",
        None,
    )
    .await
    .expect("enqueue");

    let (client, store, geofeed) = build_clients();
    let config = DequeueConfig {
        min_interval: Duration::from_millis(1),
        lease: Duration::from_secs(60),
        max_attempts: 2,
        retry_backoff: Duration::from_secs(1),
        claim_batch: 10,
        dry_run: false,
        max_items: Some(1),
    };

    // WHEN drained for real
    let stats = dequeue_all(&ctx.db, &client, &store, &geofeed, &config)
        .await
        .expect("dequeue");

    // THEN a result row was stored for the address
    assert_eq!(stats.saved, 1);
    let addr: std::net::IpAddr = "1.0.0.0".parse().unwrap();
    let stored = db::results::get_rdap_result(&ctx.db, addr)
        .await
        .expect("get result")
        .expect("result present");
    assert_eq!(stored.registry, "apnic");
}
