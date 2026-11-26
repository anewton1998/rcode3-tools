//! Pure, offline-testable logic shared by the NRO support binaries
//! (`nro-extended-stats` and `nro-enqueue`).
//!
//! The Number Resource Organization (NRO) publishes a combined **extended
//! statistics** file — the five RIR registries' delegated-resource records
//! merged into one pipe-delimited stream. Unlike the plain delegated-stats
//! format, the *extended* variant carries per-record integrity hashes and an
//! `e-stats` marker, and opens with an NRO serial record of the form
//! `2|nro|<date>|<serial>|<start-asn>|<date>|+0000`.
//!
//! This module holds only the pure pieces the binaries need: the canonical
//! source URL, the timestamped-filename builder, the payload sanity guard,
//! the per-line record classifiers, and the latest-file picker. All network,
//! filesystem and queue work lives in [`crate::cli`] and [`crate::nro_queue`];
//! keeping the logic here means it is testable without touching the network,
//! disk or a queue.
//!
//! Design notes:
//! - The download timestamp is rendered in a **compact, filesystem-safe**
//!   RFC 3339 / ISO 8601 basic form (`%Y%m%dT%H%M%SZ`, e.g.
//!   `20261108T120500Z`). Full RFC 3339 with `:` colons is legal on Linux
//!   but breaks on Windows and trips a few tools, so the colon-free spelling is
//!   used for the on-disk name while still being unambiguously UTC (`Z`).
//! - The sanity guard checks only the *first* line (the NRO serial record)
//!   rather than parsing the whole ~57 MB stream, mirroring the PSL module's
//!   "refuse a malformed payload" philosophy at O(1) cost.
//! - The record classifiers key off the pipe-delimited fields: the serial
//!   record starts with `2|nro|`, aggregate summary records end with the
//!   `summary` marker, and IANA reserved records lead with the `iana`
//!   registry.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use thiserror::Error;

/// Canonical source of the NRO extended (combined) delegated-stats file.
pub const NRO_EXTENDED_STATS_URL: &str =
    "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats";

/// Base name of the upstream file, before the download timestamp is appended.
pub const NRO_BASE_NAME: &str = "nro-delegated-stats";

/// `strftime` pattern for the compact, filesystem-safe UTC timestamp used in
/// the output file name (no `:` colons).
pub const STAMP_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// Prefix of the NRO serial record that opens a valid extended-stats file.
const NRO_SERIAL_PREFIX: &str = "2|nro|";

/// Errors produced while validating the downloaded payload.
#[derive(Debug, Error)]
pub enum NroError {
    /// The downloaded file was empty, so there is nothing to validate.
    #[error("downloaded payload is empty")]
    EmptyPayload,
    /// The first line was present but is not the expected NRO serial record.
    #[error("payload does not look like NRO extended stats (first line: {0:?})")]
    UnexpectedFormat(String),
    /// No `<base>-<stamp>` stats file was found in the work directory, or an
    /// explicit `--stats-file` path does not exist.
    #[error("NRO stats file not found: {}", .0.display())]
    NoStatsFile(PathBuf),
    /// Reading the stats stream failed.
    #[error("read error: {0}")]
    Read(#[from] std::io::Error),
    /// A database queue operation failed.
    #[error("queue error: {0}")]
    Queue(#[from] db::DbError),
}

/// Build the timestamped file name: `<base>-<stamp>`.
///
/// The stamp is the compact UTC form from [`STAMP_FORMAT`], so
/// `("nro-delegated-stats", 2026-11-08T12:05:00Z)` yields
/// `nro-delegated-stats-20261108T120500Z`.
pub fn timestamped_filename(base: &str, when: DateTime<Utc>) -> String {
    format!("{base}-{}", when.format(STAMP_FORMAT))
}

/// Resolve the default output path: `work_dir/<base>-<stamp>`.
pub fn default_output_path(work_dir: &Path, base: &str, when: DateTime<Utc>) -> PathBuf {
    work_dir.join(timestamped_filename(base, when))
}

/// Whether `first_line` looks like the NRO serial record that opens a valid
/// extended-stats file (i.e. starts with `2|nro|`).
pub fn looks_like_nro_extended_stats(first_line: &str) -> bool {
    first_line.starts_with(NRO_SERIAL_PREFIX)
}

/// Validate the first line of a downloaded payload.
///
/// Returns [`NroError::EmptyPayload`] for an empty line and
/// [`NroError::UnexpectedFormat`] for a non-empty line that is not the NRO
/// serial record, so a truncated or wrong download never masquerades as a
/// valid artifact.
pub fn validate_first_line(first_line: &str) -> Result<(), NroError> {
    if first_line.is_empty() {
        return Err(NroError::EmptyPayload);
    }
    if !looks_like_nro_extended_stats(first_line) {
        // Truncate the captured sample so a pathological first line can never
        // balloon the error message printed to stderr.
        let sample: String = first_line.chars().take(120).collect();
        return Err(NroError::UnexpectedFormat(sample));
    }
    Ok(())
}

/// Whether `line` is the NRO serial record that opens the file.
pub fn is_serial_line(line: &str) -> bool {
    line.starts_with(NRO_SERIAL_PREFIX)
}

/// Whether `line` is an NRO aggregate summary record (last field `summary`).
pub fn is_summary_line(line: &str) -> bool {
    line.rsplit('|').next() == Some("summary")
}

/// Whether `line` is an IANA reserved-resource record (first field `iana`).
pub fn is_iana_line(line: &str) -> bool {
    line.split('|').next() == Some("iana")
}

/// Whether a line must be excluded from the queue: the serial record, the
/// aggregate summary records, or the IANA reserved records. Everything else
/// is a per-RIR delegation entry worth enqueuing.
pub fn should_skip_line(line: &str) -> bool {
    is_serial_line(line) || is_summary_line(line) || is_iana_line(line)
}

/// Pick the latest stats file name among `names` for the given `base`.
///
/// A candidate starts with `<base>-` and does not end in `.part` (the
/// download binary's staging files). Because the timestamp stamp is fixed
/// width and zero-padded, the lexicographic maximum is the most recent.
pub fn latest_stats_file<'a>(names: impl Iterator<Item = &'a str>, base: &str) -> Option<&'a str> {
    let prefix = format!("{base}-");
    names
        .filter(|name| name.starts_with(&prefix) && !name.ends_with(".part"))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    /// A fixed UTC instant (2026-11-08T12:05:00Z) for deterministic names.
    fn fixed_time() -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(2026, 11, 8)
            .expect("valid date")
            .and_hms_opt(12, 5, 0)
            .expect("valid time")
            .and_utc()
    }

    #[test]
    fn timestamped_filename_uses_compact_stamp() {
        // GIVEN a base name and a fixed UTC instant
        let when = fixed_time();
        // WHEN the timestamped file name is built
        let name = timestamped_filename(NRO_BASE_NAME, when);
        // THEN it is `<base>-<compact stamp>` with no colons
        assert_eq!(name, "nro-delegated-stats-20261108T120500Z");
        assert!(
            !name.contains(':'),
            "file name must be filesystem-safe (no colons)"
        );
    }

    #[test]
    fn default_output_path_joins_dir_and_name() {
        // GIVEN a work directory and a fixed instant
        let when = fixed_time();
        // WHEN the default output path is resolved
        let path = default_output_path(Path::new("work"), NRO_BASE_NAME, when);
        // THEN it is `work/<base>-<stamp>`
        assert_eq!(
            path,
            PathBuf::from("work").join("nro-delegated-stats-20261108T120500Z")
        );
    }

    #[test]
    fn guard_accepts_the_nro_serial_line() {
        // GIVEN the real NRO serial record
        let line = "2|nro|20261108|775178|19821213|20261108|+0000";
        // WHEN validated
        // THEN it passes
        assert!(looks_like_nro_extended_stats(line));
        assert!(validate_first_line(line).is_ok());
    }

    #[test]
    fn guard_rejects_a_data_record_as_first_line() {
        // GIVEN a non-serial data record (a real ARIN line)
        let line = "arin|US|asn|1|1|20010920|assigned|e5e3b9c13678dfc483fb1f819d70883c|e-stats";
        // WHEN validated
        // THEN it reports the unexpected format
        assert!(!looks_like_nro_extended_stats(line));
        assert!(matches!(
            validate_first_line(line),
            Err(NroError::UnexpectedFormat(_))
        ));
    }

    #[test]
    fn guard_rejects_empty_payload() {
        // GIVEN an empty first line
        // WHEN validated
        // THEN it reports the empty payload
        assert!(matches!(
            validate_first_line(""),
            Err(NroError::EmptyPayload)
        ));
    }

    #[test]
    fn classifies_each_record_type() {
        // GIVEN one line of each kind from the real file
        let serial = "2|nro|20261108|775178|19821213|20261108|+0000";
        let summary = "nro|*|asn|*|117676|summary";
        let iana = "iana|ZZ|asn|0|1|20140311|reserved|ietf|iana";
        let rir = "arin|US|asn|1|1|20010920|assigned|e5e3b9c13678dfc483fb1f819d70883c|e-stats";
        // WHEN each classifier runs
        // THEN each line is recognised by exactly its own category
        assert!(is_serial_line(serial));
        assert!(is_summary_line(summary));
        assert!(is_iana_line(iana));
        assert!(!is_serial_line(rir) && !is_summary_line(rir) && !is_iana_line(rir));
        // A pipe-less line's only field is the whole line, so a bare
        // `summary` / `iana` classifies by that field.
        assert!(is_summary_line("summary"));
        assert!(is_iana_line("iana"));
    }

    #[test]
    fn should_skip_covers_serial_summary_and_iana_only() {
        // GIVEN the four record kinds
        // WHEN deciding whether to skip
        // THEN only the RIR delegation entry is kept
        assert!(should_skip_line(
            "2|nro|20261108|775178|19821213|20261108|+0000"
        ));
        assert!(should_skip_line("nro|*|ipv6|*|386083|summary"));
        assert!(should_skip_line(
            "iana|ZZ|asn|112|1|20140311|reserved|ietf|iana"
        ));
        assert!(!should_skip_line(
            "ripencc|EU|asn|7|1|19930901|assigned|8c44e083-7a7a-4853-a906-c7ca5b1167d9|e-stats"
        ));
    }

    #[test]
    fn latest_stats_file_picks_max_and_ignores_staging() {
        // GIVEN a mix of stamped files, a staging `.part`, and unrelated names
        let names = [
            "nro-delegated-stats-20261108T120000Z",
            "nro-delegated-stats-20261108T145855Z",
            "nro-delegated-stats-20261107T090000Z",
            "nro-delegated-stats.4242.part",
            "icann_psl.txt",
        ];
        // WHEN the latest is picked for the NRO base name
        let latest = latest_stats_file(names.iter().copied(), NRO_BASE_NAME);
        // THEN the newest stamped file wins and the staging/unrelated names are
        // ignored
        assert_eq!(latest, Some("nro-delegated-stats-20261108T145855Z"));
    }

    #[test]
    fn latest_stats_file_returns_none_when_nothing_matches() {
        // GIVEN names with no matching prefix
        let names = ["icann_psl.txt", "rdap_tlds.txt"];
        // WHEN the latest is picked
        // THEN there is none
        assert_eq!(
            latest_stats_file(names.iter().copied(), NRO_BASE_NAME),
            None
        );
    }

    /// RAII guard that removes a temp directory on drop (including on panic),
    /// so `--ignored` network runs are self-cleaning.
    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[ignore = "hits the network; run explicitly with `cargo test -p support-bin -- --ignored`"]
    fn downloads_and_validates_the_real_extended_stats() {
        // GIVEN a uniquely-named temp output dir and the live NRO extended stats
        let dir = TempDir(std::env::temp_dir().join(format!(
            "support-bin-nro-stats-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        )));
        let path = default_output_path(&dir.0, NRO_BASE_NAME, Utc::now());
        let client =
            crate::cli::http_client(std::time::Duration::from_secs(300)).expect("build client");
        // WHEN the file is streamed to disk
        let bytes =
            crate::cli::download_to_file(&client, NRO_EXTENDED_STATS_URL, &path).expect("download");
        // THEN a plausibly large file exists and its serial line validates
        assert!(bytes > 1_000_000, "expected > 1 MB, got {bytes}");
        let first = crate::cli::read_first_line(&path).expect("read first line");
        validate_first_line(&first).expect("serial line validates");
    }
}
