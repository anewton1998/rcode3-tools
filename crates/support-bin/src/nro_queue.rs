//! Enqueue pipeline for the `nro-enqueue` support binary.
//!
//! Reads the pipe-delimited NRO extended-stats stream and pushes every
//! per-RIR delegation entry into the durable Postgres job queue (the `db`
//! crate's generic [`queue`]), buffering a fixed number of entries per
//! `enqueue_batch` call. The serial, aggregate-summary and IANA-reserved
//! records are skipped via the pure classifiers in [`crate::nro`].
//!
//! Design notes:
//! - **DB-backed, async.** Each batch is one `INSERT .. ON CONFLICT DO NOTHING`
//!   against `queue_jobs`, so the binary runs on a tokio runtime.
//! - **Idempotent per file.** Every row's `dedup_key` is `source_serial + line`,
//!   where `source_serial` identifies the stats snapshot (its NRO serial).
//!   Re-enqueueing the same file is a no-op; a new file (new serial) inserts.
//! - **Partitioned by registry.** `partition_key` is the record's registry field,
//!   so the dequeue round-robins across RIRs.
//! - Lines are read with [`BufRead::lines`], which strips the line terminator
//!   (LF or CRLF), so the field-based classifiers never see a stray `\r`.

use std::io::BufRead;

use db::{Db, queue};

use crate::nro::{NroError, is_iana_line, is_serial_line, is_summary_line};

/// The queue topic this pipeline produces to and the dequeue consumes from.
pub const NRO_TOPIC: &str = "nro-delegations";

/// Counts produced by a single enqueue pass over a stats stream.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EnqueueStats {
    /// Delegation rows inserted into the queue.
    pub enqueued: usize,
    /// Rows skipped because their dedup key already existed.
    pub deduped: usize,
    /// NRO serial records skipped.
    pub skipped_serial: usize,
    /// Aggregate summary records skipped.
    pub skipped_summary: usize,
    /// IANA reserved records skipped.
    pub skipped_iana: usize,
}

/// Read `reader` line by line and enqueue every delegation entry into the
/// database queue under [`NRO_TOPIC`].
///
/// Blank lines are ignored; the serial / summary / iana records are counted as
/// skipped; all other lines are buffered and flushed with `enqueue_batch` every
/// `batch_size` entries (plus a final flush for the remainder). `source_serial`
/// scopes the per-row dedup key to this stats snapshot.
///
/// # Errors
///
/// Returns [`NroError::Read`] if the stream cannot be read and
/// [`NroError::Queue`] if a batch insert fails.
pub async fn enqueue_stats<R: BufRead>(
    db: &Db,
    reader: R,
    source_serial: &str,
    batch_size: usize,
) -> Result<EnqueueStats, NroError> {
    // Guard against a zero batch size (the CLI already rejects it, but this
    // function is public): a zero would flush one entry at a time.
    let batch_size = batch_size.max(1);
    let mut stats = EnqueueStats::default();

    // Owned buffers for the current batch; the QueueItems reference these and are
    // rebuilt at each flush, so nothing outlives the loop iteration.
    let mut lines: Vec<String> = Vec::with_capacity(batch_size);
    let mut partitions: Vec<String> = Vec::with_capacity(batch_size);
    let mut dedups: Vec<String> = Vec::with_capacity(batch_size);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if is_serial_line(&line) {
            stats.skipped_serial += 1;
            continue;
        }
        if is_summary_line(&line) {
            stats.skipped_summary += 1;
            continue;
        }
        if is_iana_line(&line) {
            stats.skipped_iana += 1;
            continue;
        }
        // The registry (field 0) is the round-robin partition key.
        let partition = line.split('|').next().unwrap_or_default().to_string();
        let dedup = format!("{source_serial}\n{line}");
        lines.push(line);
        partitions.push(partition);
        dedups.push(dedup);

        if lines.len() >= batch_size {
            flush(db, &lines, &partitions, &dedups, &mut stats).await?;
            lines.clear();
            partitions.clear();
            dedups.clear();
        }
    }
    flush(db, &lines, &partitions, &dedups, &mut stats).await?;
    Ok(stats)
}

/// Insert the buffered batch idempotently and fold the counts into `stats`.
async fn flush(
    db: &Db,
    lines: &[String],
    partitions: &[String],
    dedups: &[String],
    stats: &mut EnqueueStats,
) -> Result<(), NroError> {
    if lines.is_empty() {
        return Ok(());
    }
    debug_assert!(
        lines.len() == partitions.len() && lines.len() == dedups.len(),
        "batch buffers must stay in lockstep"
    );
    let items: Vec<queue::QueueItem<'_>> = lines
        .iter()
        .zip(partitions)
        .zip(dedups)
        .map(|((line, partition), dedup)| queue::QueueItem {
            payload: line,
            partition_key: partition,
            dedup_key: Some(dedup.as_str()),
        })
        .collect();
    let summary = queue::enqueue_batch(db, NRO_TOPIC, &items).await?;
    stats.enqueued += summary.inserted;
    stats.deduped += summary.deduped;
    Ok(())
}
