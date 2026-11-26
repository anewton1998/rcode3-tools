//! Integration tests for the DB-backed enqueue pipeline, against a real
//! Postgres via `db::testutil`. Run with `cargo test -p support-bin` (Docker).

use support_bin::nro_queue::{self, EnqueueStats};

/// A fixture with one of each skipped record kind plus two RIR entries.
const FIXTURE: &str = "2|nro|20261108|775178|19821213|20261108|+0000\n\
nro|*|asn|*|117676|summary\n\
nro|*|ipv4|*|271419|summary\n\
nro|*|ipv6|*|386083|summary\n\
iana|ZZ|asn|0|1|20140311|reserved|ietf|iana\n\
arin|US|asn|1|1|20010920|assigned|e5e3b9c13678dfc483fb1f819d70883c|e-stats\n\
ripencc|EU|asn|7|1|19930901|assigned|8c44e083-7a7a-4853-a906-c7ca5b1167d9|e-stats\n";

#[tokio::test]
async fn enqueue_counts_skips_and_inserts() {
    // GIVEN a fresh database
    let ctx = db::testutil::fresh_db().await;
    // WHEN the fixture is enqueued
    let stats = nro_queue::enqueue_stats(&ctx.db, FIXTURE.as_bytes(), "serial-1", 1)
        .await
        .expect("enqueue");
    // THEN the skips and the insert count are as expected (the two RIR lines)
    assert_eq!(
        stats,
        EnqueueStats {
            enqueued: 2,
            deduped: 0,
            skipped_serial: 1,
            skipped_summary: 3,
            skipped_iana: 1,
        }
    );
    let counts = db::queue::count_by_status(&ctx.db, nro_queue::NRO_TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&2));
}

#[tokio::test]
async fn re_enqueue_same_source_serial_is_deduped() {
    // GIVEN a fixture already enqueued under a source serial
    let ctx = db::testutil::fresh_db().await;
    nro_queue::enqueue_stats(&ctx.db, FIXTURE.as_bytes(), "serial-1", 4)
        .await
        .expect("first enqueue");
    // WHEN the same file (same source serial) is enqueued again
    let second = nro_queue::enqueue_stats(&ctx.db, FIXTURE.as_bytes(), "serial-1", 4)
        .await
        .expect("second enqueue");
    // THEN nothing new is inserted — everything deduped
    assert_eq!(second.enqueued, 0);
    assert_eq!(second.deduped, 2);
    let counts = db::queue::count_by_status(&ctx.db, nro_queue::NRO_TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&2));
}

#[tokio::test]
async fn different_source_serial_inserts_again() {
    // GIVEN a fixture enqueued under one source serial
    let ctx = db::testutil::fresh_db().await;
    nro_queue::enqueue_stats(&ctx.db, FIXTURE.as_bytes(), "serial-A", 4)
        .await
        .expect("enqueue A");
    // WHEN the same lines are enqueued under a different source serial (a new file)
    let second = nro_queue::enqueue_stats(&ctx.db, FIXTURE.as_bytes(), "serial-B", 4)
        .await
        .expect("enqueue B");
    // THEN they insert (dedup scope is per-file)
    assert_eq!(second.enqueued, 2);
    assert_eq!(second.deduped, 0);
    let counts = db::queue::count_by_status(&ctx.db, nro_queue::NRO_TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&4));
}

#[tokio::test]
async fn enqueue_of_only_skipped_lines_yields_no_rows() {
    // GIVEN a stream with nothing but skipped records
    let ctx = db::testutil::fresh_db().await;
    let skipped = "2|nro|20261108|775178|19821213|20261108|+0000\n\
nro|*|asn|*|117676|summary\n\
iana|ZZ|asn|0|1|20140311|reserved|ietf|iana\n";
    // WHEN enqueued
    let stats = nro_queue::enqueue_stats(&ctx.db, skipped.as_bytes(), "serial-x", 4)
        .await
        .expect("enqueue");
    // THEN nothing is inserted
    assert_eq!(stats.enqueued, 0);
    assert_eq!(stats.skipped_serial, 1);
    assert_eq!(stats.skipped_summary, 1);
    assert_eq!(stats.skipped_iana, 1);
}
