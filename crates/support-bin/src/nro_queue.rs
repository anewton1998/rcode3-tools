//! Enqueue pipeline for the `nro-enqueue` support binary.
//!
//! Reads the pipe-delimited NRO extended-stats stream and pushes every
//! per-RIR delegation entry into a [`yaque`] disk-backed queue, buffering a
//! fixed number of entries per `try_send_batch` call — every entry is
//! persisted by the time the call returns. The serial, aggregate-summary and
//! IANA-reserved records are skipped via the pure classifiers in
//! [`crate::nro`].
//!
//! Design notes:
//! - The pipeline is **synchronous**: `yaque::Sender` is lock-free and its
//!   `try_send_batch` never blocks on an unbounded queue, so the CLI needs no
//!   async runtime. (The async `send_batch` only exists to await drain when a
//!   `max_queue_size` is configured, which we do not use.)
//! - `yaque::Sender::open` creates the queue directory (and its parents) if
//!   it does not already exist, satisfying "create the queue dir if missing".
//! - Each queued message is the raw pipe-delimited record bytes, with no
//!   trailing newline — lossless and cheap for downstream consumers to parse.
//! - Lines are read with [`BufRead::lines`], which strips the line terminator
//!   (LF or CRLF), so the field-based classifiers never see a stray `\r`.

use std::io::BufRead;

use yaque::{Sender, TrySendError};

use crate::nro::{NroError, is_iana_line, is_serial_line, is_summary_line};

/// Counts produced by a single enqueue pass over a stats stream.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EnqueueStats {
    /// Delegation entries pushed into the queue.
    pub enqueued: usize,
    /// NRO serial records skipped.
    pub skipped_serial: usize,
    /// Aggregate summary records skipped.
    pub skipped_summary: usize,
    /// IANA reserved records skipped.
    pub skipped_iana: usize,
}

/// Read `reader` line by line and enqueue every delegation entry into `sender`.
///
/// Blank lines are ignored; the serial / summary / iana records are counted as
/// skipped; all other lines are buffered and flushed with `try_send_batch`
/// every `batch_size` entries (plus a final flush for the remainder).
///
/// # Errors
///
/// Returns [`NroError::Read`] if the stream cannot be read and
/// [`NroError::Queue`] if a batch send fails.
pub fn enqueue_stats<R: BufRead>(
    reader: R,
    sender: &mut Sender,
    batch_size: usize,
) -> Result<EnqueueStats, NroError> {
    // Guard against a zero batch size (the CLI already rejects it, but this
    // function is public): a zero would flush one entry at a time.
    let batch_size = batch_size.max(1);
    let mut stats = EnqueueStats::default();
    let mut batch: Vec<String> = Vec::with_capacity(batch_size);

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
        batch.push(line);
        if batch.len() >= batch_size {
            stats.enqueued += flush(sender, &mut batch)?;
        }
    }
    stats.enqueued += flush(sender, &mut batch)?;
    Ok(stats)
}

/// Send the buffered batch atomically and clear it, returning the count sent.
fn flush(sender: &mut Sender, batch: &mut Vec<String>) -> Result<usize, NroError> {
    if batch.is_empty() {
        return Ok(0);
    }
    sender.try_send_batch(batch.iter()).map_err(|e| match e {
        TrySendError::Io(io) => NroError::Queue(format!("send error: {io}")),
        TrySendError::QueueFull { base, .. } => {
            NroError::Queue(format!("queue at {} is full", base.display()))
        }
    })?;
    let n = batch.len();
    batch.clear();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use yaque::Receiver;

    /// A fixture with one of each skipped record kind plus two RIR entries.
    const FIXTURE: &str = "2|nro|20261108|775178|19821213|20261108|+0000\n\
nro|*|asn|*|117676|summary\n\
nro|*|ipv4|*|271419|summary\n\
nro|*|ipv6|*|386083|summary\n\
iana|ZZ|asn|0|1|20140311|reserved|ietf|iana\n\
arin|US|asn|1|1|20010920|assigned|e5e3b9c13678dfc483fb1f819d70883c|e-stats\n\
ripencc|EU|asn|7|1|19930901|assigned|8c44e083-7a7a-4853-a906-c7ca5b1167d9|e-stats\n";

    const ARIN_LINE: &str =
        "arin|US|asn|1|1|20010920|assigned|e5e3b9c13678dfc483fb1f819d70883c|e-stats";
    const RIPENCC_LINE: &str =
        "ripencc|EU|asn|7|1|19930901|assigned|8c44e083-7a7a-4853-a906-c7ca5b1167d9|e-stats";

    /// A uniquely-named temp queue dir, removed on drop.
    struct TempQueue(PathBuf);
    impl TempQueue {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "support-bin-nro-queue-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempQueue {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn enqueue_counts_skips_and_entries() {
        // GIVEN the fixture and a fresh queue
        let queue = TempQueue::new("counts");
        let mut sender = Sender::open(queue.path()).expect("open sender");
        // WHEN enqueued with a small batch size
        let stats = enqueue_stats(FIXTURE.as_bytes(), &mut sender, 1).expect("enqueue");
        // THEN the skips and the enqueue count are as expected
        assert_eq!(
            stats,
            EnqueueStats {
                enqueued: 2,
                skipped_serial: 1,
                skipped_summary: 3,
                skipped_iana: 1,
            }
        );
    }

    #[test]
    fn enqueued_messages_are_the_rir_lines_in_order() {
        // GIVEN the fixture enqueued into a fresh queue
        let queue = TempQueue::new("drain");
        let mut sender = Sender::open(queue.path()).expect("open sender");
        enqueue_stats(FIXTURE.as_bytes(), &mut sender, 2).expect("enqueue");
        // WHEN the two queued messages are received
        let mut receiver = Receiver::open(queue.path()).expect("open receiver");
        let first = futures::executor::block_on(receiver.recv()).expect("recv first");
        assert_eq!(&*first, ARIN_LINE.as_bytes());
        first.commit().expect("commit first");
        let second = futures::executor::block_on(receiver.recv()).expect("recv second");
        assert_eq!(&*second, RIPENCC_LINE.as_bytes());
        second.commit().expect("commit second");
        // THEN the queue is exhausted — serial/summary/iana never reached it
        assert!(
            matches!(receiver.try_recv(), Err(yaque::TryRecvError::QueueEmpty)),
            "queue should hold exactly the two RIR lines"
        );
    }

    #[test]
    fn enqueue_flushes_a_nonempty_tail_batch() {
        // GIVEN two entries with a batch size larger than the entry count
        let queue = TempQueue::new("tail");
        let mut sender = Sender::open(queue.path()).expect("open sender");
        // WHEN enqueued (batch 3 > 2 entries → the final flush is non-empty)
        let stats = enqueue_stats(FIXTURE.as_bytes(), &mut sender, 3).expect("enqueue");
        // THEN both entries are carried by the tail flush and arrive in order
        assert_eq!(stats.enqueued, 2);
        let mut receiver = Receiver::open(queue.path()).expect("open receiver");
        let first = futures::executor::block_on(receiver.recv()).expect("recv first");
        assert_eq!(&*first, ARIN_LINE.as_bytes());
        first.commit().expect("commit first");
        let second = futures::executor::block_on(receiver.recv()).expect("recv second");
        assert_eq!(&*second, RIPENCC_LINE.as_bytes());
        second.commit().expect("commit second");
    }

    #[test]
    fn enqueue_of_only_skipped_lines_yields_no_messages() {
        // GIVEN a stream with nothing but skipped records
        let queue = TempQueue::new("empty");
        let mut sender = Sender::open(queue.path()).expect("open sender");
        let skipped = "2|nro|20261108|775178|19821213|20261108|+0000\n\
nro|*|asn|*|117676|summary\n\
iana|ZZ|asn|0|1|20140311|reserved|ietf|iana\n";
        // WHEN enqueued
        let stats = enqueue_stats(skipped.as_bytes(), &mut sender, 4).expect("enqueue");
        // THEN nothing is enqueued
        assert_eq!(stats.enqueued, 0);
        assert_eq!(stats.skipped_serial, 1);
        assert_eq!(stats.skipped_summary, 1);
        assert_eq!(stats.skipped_iana, 1);
    }
}
