//! A generic, durable job queue backed by the `queue_jobs` table.
//!
//! Delivery is **at-least-once**: [`claim_one_per_partition`] leases rows (sets
//! `locked_until` and bumps `attempts`), so a worker that crashes mid-job lets the
//! lease lapse and the row becomes claimable again. Concurrent workers are safe
//! because claiming uses `FOR UPDATE SKIP LOCKED`.
//!
//! The queue is **topic-partitioned**: `topic` is the logical queue, and
//! `partition_key` is a grouping used by the claim to interleave work (e.g. the
//! RIR registry) so a single consumer round-robins across groups instead of
//! stalling on one group's long run.
//!
//! Idempotent enqueue: supply a `dedup_key` and the partial unique index makes a
//! repeat insert a no-op (see [`enqueue`] / [`enqueue_batch`]).

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::error::Result;
use crate::pool::Db;

/// A claimed or peeked queue row.
#[derive(Debug, Clone, FromRow)]
pub struct Job {
    /// Primary key.
    pub id: i64,
    /// Logical queue name.
    pub topic: String,
    /// The opaque work payload.
    pub payload: String,
    /// Round-robin grouping key.
    pub partition_key: String,
    /// Number of times this row has been claimed (>= 1 once claimed).
    pub attempts: i32,
    /// Lease expiry while `running`; `None` when free.
    pub locked_until: Option<DateTime<Utc>>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
}

/// One item to insert via [`enqueue_batch`].
#[derive(Debug, Clone, Copy)]
pub struct QueueItem<'a> {
    /// The opaque work payload.
    pub payload: &'a str,
    /// Round-robin grouping key.
    pub partition_key: &'a str,
    /// Optional idempotency key (see the partial unique index).
    pub dedup_key: Option<&'a str>,
}

/// Outcome of a batch enqueue: how many rows landed vs were deduped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnqueueSummary {
    /// Rows actually inserted.
    pub inserted: usize,
    /// Items skipped because their `dedup_key` already existed.
    pub deduped: usize,
}

/// Outcome of [`mark_failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    /// Attempts remain: the row is back to `pending` with a retry lease.
    Requeued,
    /// Attempts exhausted: the row is terminal `failed`.
    Failed,
}

/// Insert a single job. Returns the new row id, or `None` if a matching
/// `dedup_key` already existed (no-op).
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn enqueue(
    db: &Db,
    topic: &str,
    payload: &str,
    partition_key: &str,
    dedup_key: Option<&str>,
) -> Result<Option<i64>> {
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO queue_jobs (topic, payload, partition_key, dedup_key)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (topic, dedup_key) WHERE dedup_key IS NOT NULL DO NOTHING
         RETURNING id",
    )
    .bind(topic)
    .bind(payload)
    .bind(partition_key)
    .bind(dedup_key)
    .fetch_optional(db.pool())
    .await?;
    Ok(id)
}

/// Insert many jobs in one statement, skipping any whose `dedup_key` collides.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn enqueue_batch(
    db: &Db,
    topic: &str,
    items: &[QueueItem<'_>],
) -> Result<EnqueueSummary> {
    if items.is_empty() {
        return Ok(EnqueueSummary::default());
    }
    let payloads: Vec<&str> = items.iter().map(|i| i.payload).collect();
    let partitions: Vec<&str> = items.iter().map(|i| i.partition_key).collect();
    let dedups: Vec<Option<&str>> = items.iter().map(|i| i.dedup_key).collect();

    let inserted = sqlx::query(
        "INSERT INTO queue_jobs (topic, payload, partition_key, dedup_key)
         SELECT $1, v.payload, v.partition_key, v.dedup_key
         FROM UNNEST($2::text[], $3::text[], $4::text[])
             AS v(payload, partition_key, dedup_key)
         ON CONFLICT (topic, dedup_key) WHERE dedup_key IS NOT NULL DO NOTHING",
    )
    .bind(topic)
    .bind(&payloads)
    .bind(&partitions)
    .bind(&dedups)
    .execute(db.pool())
    .await?;

    let inserted = inserted.rows_affected() as usize;
    Ok(EnqueueSummary {
        inserted,
        deduped: items.len() - inserted,
    })
}

/// Claim up to `limit` jobs, **one per `partition_key`** (round-robin), taking a
/// `lease`-long lock and incrementing `attempts`.
///
/// A row is claimable when it is `pending` (with no unexpired retry-backoff lease)
/// **or** `running` with an expired lease — so a crashed worker's in-flight jobs
/// become reclaimable once their lease lapses. `FOR UPDATE SKIP LOCKED` makes this
/// safe under concurrent consumers: rows a peer currently holds are skipped
/// rather than blocking.
///
/// `start_after` rotates the partition ordering: partitions strictly greater than
/// it are served first, so when `limit` is smaller than the number of busy
/// partitions the cut-off advances each round instead of always starving the
/// alphabetically-last ones. Pass `None` (or the last `partition_key` served in
/// the previous round) to rotate.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn claim_one_per_partition(
    db: &Db,
    topic: &str,
    limit: i64,
    lease: Duration,
    start_after: Option<&str>,
) -> Result<Vec<Job>> {
    let lease_secs = lease.as_secs_f64();
    let jobs = sqlx::query_as::<_, Job>(
        "WITH claimed AS (
             SELECT j.id
             FROM (
                 SELECT DISTINCT partition_key
                 FROM queue_jobs
                 WHERE topic = $1
                   AND status IN ('pending', 'running')
                   AND (locked_until IS NULL OR locked_until <= now())
             ) p
             CROSS JOIN LATERAL (
                 SELECT id
                 FROM queue_jobs q
                 WHERE q.topic = $1
                   AND q.partition_key = p.partition_key
                   AND q.status IN ('pending', 'running')
                   AND (q.locked_until IS NULL OR q.locked_until <= now())
                 ORDER BY q.id
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             ) j
             ORDER BY (p.partition_key > $4) DESC NULLS LAST, p.partition_key
             LIMIT $2
         )
         UPDATE queue_jobs
         SET status = 'running',
             attempts = attempts + 1,
             locked_until = now() + make_interval(secs => $3::double precision),
             updated_at = now()
         FROM claimed
         WHERE queue_jobs.id = claimed.id
         RETURNING queue_jobs.id, queue_jobs.topic, queue_jobs.payload,
                   queue_jobs.partition_key, queue_jobs.attempts,
                   queue_jobs.locked_until, queue_jobs.created_at",
    )
    .bind(topic)
    .bind(limit)
    .bind(lease_secs)
    .bind(start_after)
    .fetch_all(db.pool())
    .await?;
    Ok(jobs)
}

/// Non-mutating counterpart of [`claim_one_per_partition`]: peek one pending job
/// per partition without locking or changing status (for dry-run scheduling).
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn peek_one_per_partition(db: &Db, topic: &str, limit: i64) -> Result<Vec<Job>> {
    let jobs = sqlx::query_as::<_, Job>(
        "SELECT q.id, q.topic, q.payload, q.partition_key, q.attempts,
                q.locked_until, q.created_at
         FROM (
             SELECT DISTINCT partition_key
             FROM queue_jobs
             WHERE topic = $1
               AND status = 'pending'
               AND (locked_until IS NULL OR locked_until <= now())
         ) p
         CROSS JOIN LATERAL (
             SELECT * FROM queue_jobs q
             WHERE q.topic = $1
               AND q.partition_key = p.partition_key
               AND q.status = 'pending'
               AND (q.locked_until IS NULL OR q.locked_until <= now())
             ORDER BY q.id
             LIMIT 1
         ) q
         ORDER BY p.partition_key
         LIMIT $2",
    )
    .bind(topic)
    .bind(limit)
    .fetch_all(db.pool())
    .await?;
    Ok(jobs)
}

/// Mark a job successfully completed.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn mark_done(db: &Db, id: i64) -> Result<()> {
    sqlx::query(
        "UPDATE queue_jobs
         SET status = 'done', locked_until = NULL, updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Record a failure for a claimed job.
///
/// If the job has reached `max_attempts` it becomes terminal `failed`; otherwise
/// it returns to `pending` with a `retry_after` lease (backoff) so it is not
/// immediately re-claimed.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn mark_failed(
    db: &Db,
    id: i64,
    max_attempts: i32,
    retry_after: Duration,
    error: &str,
) -> Result<JobOutcome> {
    let retry_secs = retry_after.as_secs_f64();
    let status: String = sqlx::query_scalar(
        "UPDATE queue_jobs
         SET status = CASE WHEN attempts >= $2 THEN 'failed' ELSE 'pending' END,
             locked_until = CASE
                 WHEN attempts >= $2 THEN NULL
                 ELSE now() + make_interval(secs => $3::double precision)
             END,
             last_error = $4,
             updated_at = now()
         WHERE id = $1
         RETURNING status",
    )
    .bind(id)
    .bind(max_attempts)
    .bind(retry_secs)
    .bind(error)
    .fetch_one(db.pool())
    .await?;

    Ok(if status == "failed" {
        JobOutcome::Failed
    } else {
        JobOutcome::Requeued
    })
}

/// Extend the lease on a still-`running` job to `now + lease`.
///
/// Call this just before a long-running unit of work so the held time never
/// exceeds one item's work — otherwise a slow batch (e.g. rate-limit sleeps +
/// geofeed downloads) can outlive the lease taken at claim time and let a peer
/// re-claim a row that is still being processed.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn renew_lease(db: &Db, id: i64, lease: Duration) -> Result<()> {
    sqlx::query(
        "UPDATE queue_jobs
         SET locked_until = now() + make_interval(secs => $2::double precision), updated_at = now()
         WHERE id = $1 AND status = 'running'",
    )
    .bind(id)
    .bind(lease.as_secs_f64())
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Return claimed-but-unprocessed jobs to `pending`, clearing their lease and
/// undoing the `attempts` bump the claim applied (so a row that was never really
/// processed does not burn retry budget).
///
/// Only rows still in `running` are touched, so this never clobbers a job that was
/// already marked `done`/`failed`. Returns the number of rows released.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn release(db: &Db, ids: &[i64]) -> Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    let res = sqlx::query(
        "UPDATE queue_jobs
         SET status = 'pending', attempts = attempts - 1, locked_until = NULL, updated_at = now()
         WHERE id = ANY($1) AND status = 'running'",
    )
    .bind(ids)
    .execute(db.pool())
    .await?;
    Ok(res.rows_affected())
}

/// Count rows for `topic` grouped by status.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn count_by_status(db: &Db, topic: &str) -> Result<HashMap<String, i64>> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, COUNT(*) FROM queue_jobs WHERE topic = $1 GROUP BY status")
            .bind(topic)
            .fetch_all(db.pool())
            .await?;
    Ok(rows.into_iter().collect())
}
