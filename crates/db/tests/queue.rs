//! Integration tests for the generic queue, against a real Postgres via
//! `db::testutil`. Run with `cargo test -p db --features testutil`.

use std::time::Duration;

use db::queue::{self, EnqueueSummary, JobOutcome};
use db::testutil::fresh_db;

const TOPIC: &str = "test-topic";

#[tokio::test]
async fn enqueue_then_claim_returns_the_job() {
    // GIVEN a freshly enqueued job
    let ctx = fresh_db().await;
    let id = queue::enqueue(&ctx.db, TOPIC, "payload-1", "p1", Some("dedup-1"))
        .await
        .expect("enqueue")
        .expect("inserted");
    // WHEN it is claimed
    let jobs = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim");
    // THEN the same job comes back, now running
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, id);
    assert_eq!(jobs[0].payload, "payload-1");
    assert_eq!(jobs[0].attempts, 1);
    assert!(jobs[0].locked_until.is_some());
}

#[tokio::test]
async fn enqueue_batch_reports_inserted_and_deduped() {
    // GIVEN a batch with a duplicate dedup key inside it
    let ctx = fresh_db().await;
    let items = [
        queue::QueueItem {
            payload: "a",
            partition_key: "p",
            dedup_key: Some("k1"),
        },
        queue::QueueItem {
            payload: "b",
            partition_key: "p",
            dedup_key: Some("k2"),
        },
        queue::QueueItem {
            payload: "a-dup",
            partition_key: "p",
            dedup_key: Some("k1"),
        },
    ];
    // WHEN the batch is inserted
    let summary = queue::enqueue_batch(&ctx.db, TOPIC, &items)
        .await
        .expect("batch");
    // THEN the duplicate is dropped and the unique key holds
    assert_eq!(
        summary,
        EnqueueSummary {
            inserted: 2,
            deduped: 1
        }
    );
}

#[tokio::test]
async fn re_enqueue_same_dedup_key_is_a_noop() {
    // GIVEN a job already enqueued under a dedup key
    let ctx = fresh_db().await;
    queue::enqueue(&ctx.db, TOPIC, "first", "p", Some("same"))
        .await
        .expect("first insert");
    // WHEN the same dedup key is enqueued again
    let second = queue::enqueue(&ctx.db, TOPIC, "second", "p", Some("same"))
        .await
        .expect("second attempt");
    // THEN nothing is inserted
    assert!(second.is_none());
    let counts = queue::count_by_status(&ctx.db, TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&1));
}

#[tokio::test]
async fn claim_interleaves_one_per_partition() {
    // GIVEN two partitions each with two jobs
    let ctx = fresh_db().await;
    for p in ["alpha", "beta"] {
        queue::enqueue(&ctx.db, TOPIC, &format!("{p}-1"), p, None)
            .await
            .expect("enqueue 1");
        queue::enqueue(&ctx.db, TOPIC, &format!("{p}-2"), p, None)
            .await
            .expect("enqueue 2");
    }
    // WHEN one round of claiming happens
    let round1 = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim round 1");
    // THEN it yields exactly one job per partition
    let parts: Vec<&str> = round1.iter().map(|j| j.partition_key.as_str()).collect();
    assert_eq!(parts, vec!["alpha", "beta"]);
    // AND a second round yields the remaining one per partition
    let round2 = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim round 2");
    assert_eq!(round2.len(), 2);
    // AND a third round finds nothing
    let round3 = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim round 3");
    assert!(round3.is_empty());
}

#[tokio::test]
async fn expired_lease_is_reclaimable() {
    // GIVEN a job claimed with a short lease
    let ctx = fresh_db().await;
    queue::enqueue(&ctx.db, TOPIC, "job", "p", None)
        .await
        .expect("enqueue");
    let first =
        queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_millis(200), None)
            .await
            .expect("first claim");
    assert_eq!(first.len(), 1);
    // WHEN we claim again while the lease is still held
    let during = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim during lease");
    // THEN nothing is available
    assert!(during.is_empty());
    // AND after the lease lapses (simulating a crashed worker)
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim after lease");
    // THEN the job is reclaimable with a bumped attempt count
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].attempts, 2);
}

#[tokio::test]
async fn mark_failed_requeues_until_max_then_fails() {
    // GIVEN a job claimed once
    let ctx = fresh_db().await;
    queue::enqueue(&ctx.db, TOPIC, "job", "p", None)
        .await
        .expect("enqueue");
    let claimed = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim");
    let id = claimed[0].id;
    // WHEN it fails with max_attempts = 2 (attempts now 1 < 2)
    let outcome = queue::mark_failed(&ctx.db, id, 2, Duration::from_millis(200), "boom 1")
        .await
        .expect("mark_failed 1");
    // THEN it is requeued, not terminal
    assert_eq!(outcome, JobOutcome::Requeued);
    // AND after the backoff it is re-claimed (attempts now 2)
    tokio::time::sleep(Duration::from_millis(300)).await;
    let again = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("re-claim");
    assert_eq!(again[0].attempts, 2);
    // AND failing again hits the max and goes terminal
    let outcome2 = queue::mark_failed(&ctx.db, id, 2, Duration::from_millis(200), "boom 2")
        .await
        .expect("mark_failed 2");
    assert_eq!(outcome2, JobOutcome::Failed);
    let counts = queue::count_by_status(&ctx.db, TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("failed"), Some(&1));
}

#[tokio::test]
async fn release_returns_running_jobs_to_pending() {
    // GIVEN two claimed jobs in two distinct partitions
    let ctx = fresh_db().await;
    for i in 0..2 {
        queue::enqueue(&ctx.db, TOPIC, &format!("job-{i}"), &format!("p{i}"), None)
            .await
            .expect("enqueue");
    }
    let claimed = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim");
    let ids: Vec<i64> = claimed.iter().map(|j| j.id).collect();
    // WHEN they are released
    let released = queue::release(&ctx.db, &ids).await.expect("release");
    // THEN both go back to pending and are claimable again
    assert_eq!(released, 2);
    let counts = queue::count_by_status(&ctx.db, TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&2));
}

#[tokio::test]
async fn peek_does_not_change_status() {
    // GIVEN a pending job
    let ctx = fresh_db().await;
    queue::enqueue(&ctx.db, TOPIC, "job", "p", None)
        .await
        .expect("enqueue");
    // WHEN it is peeked
    let peeked = queue::peek_one_per_partition(&ctx.db, TOPIC, 10)
        .await
        .expect("peek");
    // THEN the row is visible but still pending (not locked)
    assert_eq!(peeked.len(), 1);
    assert_eq!(peeked[0].attempts, 0);
    let counts = queue::count_by_status(&ctx.db, TOPIC)
        .await
        .expect("counts");
    assert_eq!(counts.get("pending"), Some(&1));
    assert_eq!(counts.get("running"), None);
}

#[tokio::test]
async fn release_restores_attempts() {
    // GIVEN a job that has been claimed once (attempts = 1)
    let ctx = fresh_db().await;
    let id = queue::enqueue(&ctx.db, TOPIC, "job", "p", None)
        .await
        .expect("enqueue")
        .expect("inserted");
    let claimed = queue::claim_one_per_partition(&ctx.db, TOPIC, 10, Duration::from_secs(30), None)
        .await
        .expect("claim");
    assert_eq!(claimed[0].attempts, 1);
    // WHEN it is released without being processed
    queue::release(&ctx.db, &[id]).await.expect("release");
    // THEN the attempt it never really used is given back
    let peeked = queue::peek_one_per_partition(&ctx.db, TOPIC, 10)
        .await
        .expect("peek");
    assert_eq!(peeked[0].attempts, 0);
}

#[tokio::test]
async fn rotating_cursor_prevents_starvation_with_small_limit() {
    // GIVEN three busy partitions and a claim limit of one
    let ctx = fresh_db().await;
    for p in ["a", "b", "c"] {
        for i in 0..2 {
            queue::enqueue(&ctx.db, TOPIC, &format!("{p}-{i}"), p, None)
                .await
                .expect("enqueue");
        }
    }
    // WHEN we claim one per round, advancing the rotating cursor each time
    let mut served = std::collections::HashSet::new();
    let mut start_after: Option<String> = None;
    for _ in 0..3 {
        let jobs = queue::claim_one_per_partition(
            &ctx.db,
            TOPIC,
            1,
            Duration::from_secs(30),
            start_after.as_deref(),
        )
        .await
        .expect("claim");
        assert_eq!(jobs.len(), 1, "each round claims exactly one");
        served.insert(jobs[0].partition_key.clone());
        start_after = jobs.last().map(|j| j.partition_key.clone());
    }
    // THEN every partition got served despite the limit being below the partition
    // count (without the rotating cursor, only "a" would ever be claimed).
    let expected: std::collections::HashSet<String> =
        ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
    assert_eq!(served, expected);
}
