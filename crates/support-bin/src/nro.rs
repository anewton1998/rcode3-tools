//! Pure, offline-testable logic behind the `nro-extended-stats` support binary.
//!
//! The Number Resource Organization (NRO) publishes a combined **extended
//! statistics** file — the five RIR registries' delegated-resource records
//! merged into one pipe-delimited stream. Unlike the plain delegated-stats
//! format, the *extended* variant carries per-record integrity hashes and an
//! `e-stats` marker, and opens with an NRO serial record of the form
//! `2|nro|<date>|<serial>|<start-asn>|<date>|+0000`.
//!
//! This module holds only the pure pieces the binary needs: the canonical
//! source URL, the timestamped-filename builder, and the payload sanity guard.
//! All network and filesystem work lives in [`crate::cli`]; keeping the logic
//! here means it is testable without touching the network or disk.
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
