//! Pure, offline-testable logic behind the `psl-extract` support binary.
//!
//! The Public Suffix List (PSL) is a flat text file of *public suffixes* — the
//! registry-controlled tail of a domain name (e.g. `com`, `co.uk`). This module
//! reads the raw `.dat` payload, isolates the **ICANN** section (private domains
//! are excluded by construction), and reduces it to a small, sorted, de-duplicated
//! list of suffixes that carry at least `min_labels` labels.
//!
//! Design notes:
//! - The ICANN section is delimited by the literal marker comments
//!   `// ===BEGIN ICANN DOMAINS===` / `// ===END ICANN DOMAINS===`; everything
//!   outside that window (including the private-domains section) is ignored.
//! - Wildcard (`*.ck`) and exception (`!www.ck`) entries are kept **verbatim** so
//!   the full suffix semantics survive; the consumer is responsible for
//!   interpreting the `*` / `!` markers.
//! - Entries are stored as UTF-8 exactly as they appear in the source (no punycode
//!   conversion), so IDN suffixes round-trip unchanged.
//! - Label counting is a plain `split('.')` on the literal string, so `*.ck` and
//!   `!www.ck` both count as two labels and are retained at `min_labels = 2`.

use std::fmt::Write as _;

use thiserror::Error;

/// Canonical source of the Public Suffix List.
pub const PSL_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";

/// Literal comment that opens the ICANN (non-private) section of the list.
const ICANN_BEGIN: &str = "// ===BEGIN ICANN DOMAINS===";
/// Literal comment that closes the ICANN section.
const ICANN_END: &str = "// ===END ICANN DOMAINS===";

/// Errors produced while extracting the ICANN section.
#[derive(Debug, Error)]
pub enum PslError {
    /// A required section marker was absent from the payload.
    #[error("missing required marker in payload: {0}")]
    MissingMarker(&'static str),
    /// The ICANN section was present but yielded no usable entries.
    #[error("ICANN section contained no entries")]
    Empty,
    /// The source header was missing its `VERSION` / `COMMIT` provenance, so the
    /// committed artifact would carry no traceable origin.
    #[error("source header missing VERSION / COMMIT provenance")]
    MissingProvenance,
}

/// The ICANN portion of the list plus its provenance header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// `VERSION` value from the source header (e.g. `2026-11-04_19-07-29_UTC`).
    pub version: String,
    /// `COMMIT` value from the source header (a git SHA).
    pub commit: String,
    /// Raw ICANN entry lines (comments and blanks already removed, unsorted).
    pub entries: Vec<String>,
}

/// Number of dot-separated labels in a single entry.
///
/// Counts the literal labels, so `*.ck` and `!www.ck` each yield `2`.
pub fn label_count(entry: &str) -> usize {
    entry.split('.').count()
}

/// Slice the ICANN section out of a raw PSL payload and capture its provenance.
///
/// Fails with [`PslError::MissingMarker`] if a marker is absent or the `END`
/// marker is never reached after `BEGIN` (a truncated payload would otherwise
/// silently swallow the private-domains section), [`PslError::Empty`] if the
/// section holds no entries, or [`PslError::MissingProvenance`] if the header
/// lacks `VERSION` / `COMMIT`.
pub fn extract_icann(dat: &str) -> Result<Extracted, PslError> {
    if !dat.contains(ICANN_BEGIN) {
        return Err(PslError::MissingMarker(ICANN_BEGIN));
    }
    if !dat.contains(ICANN_END) {
        return Err(PslError::MissingMarker(ICANN_END));
    }

    let mut version = String::new();
    let mut commit = String::new();
    let mut inside = false;
    let mut entries = Vec::new();

    for raw in dat.lines() {
        let line = raw.trim();

        if line == ICANN_BEGIN {
            inside = true;
            continue;
        }
        if line == ICANN_END {
            inside = false;
            continue;
        }

        // Provenance lives in the top-of-file header, so scan it regardless of
        // whether we are inside the ICANN window yet. First occurrence wins so a
        // stray duplicate later in the file cannot overwrite the real header.
        if let Some(v) = line.strip_prefix("// VERSION:")
            && version.is_empty()
        {
            version = v.trim().to_string();
        } else if let Some(c) = line.strip_prefix("// COMMIT:")
            && commit.is_empty()
        {
            commit = c.trim().to_string();
        }

        if !inside {
            continue;
        }
        // Strip blank lines and comment lines; everything else is an entry.
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        entries.push(line.to_string());
    }

    // `BEGIN` was seen but `END` never closed the window: the payload is
    // truncated or malformed, and continuing would have collected the private
    // section. Refuse rather than emit a wrong list.
    if inside {
        return Err(PslError::MissingMarker(ICANN_END));
    }
    if entries.is_empty() {
        return Err(PslError::Empty);
    }
    if version.is_empty() || commit.is_empty() {
        return Err(PslError::MissingProvenance);
    }
    Ok(Extracted {
        version,
        commit,
        entries,
    })
}

/// Keep entries with at least `min_labels` labels, de-duplicated and sorted.
pub fn filter_entries(entries: &[String], min_labels: usize) -> Vec<String> {
    let mut kept: Vec<String> = entries
        .iter()
        .filter(|entry| label_count(entry) >= min_labels)
        .cloned()
        .collect();
    kept.sort();
    kept.dedup();
    kept
}

/// Render the committed artifact: a `#` provenance header followed by one entry
/// per line.
pub fn render(extracted: &Extracted, min_labels: usize, entries: &[String]) -> String {
    let generated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // Writing to a `String` is infallible, so the `writeln!` results are ignored.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Public Suffix List - ICANN domains only, >= {min_labels} labels"
    );
    let _ = writeln!(out, "# Source: {PSL_URL}");
    let _ = writeln!(out, "# List version: {}", extracted.version);
    let _ = writeln!(out, "# List commit: {}", extracted.commit);
    let _ = writeln!(out, "# Generated: {generated}");
    let _ = writeln!(out, "# Entries: {}", entries.len());
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# Generated by `cargo run -p support-bin --bin psl-extract`. Do not edit by hand."
    );
    for entry in entries {
        let _ = writeln!(out, "{entry}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature PSL fixture mirroring the real file's structure: a provenance
    /// header, an ICANN section with comments/wildcards/exceptions, and a private
    /// section that must be ignored.
    const FIXTURE: &str = "\
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0.

// VERSION: 2026-11-04_TEST_UTC
// COMMIT: deadbeefcafe

// ===BEGIN ICANN DOMAINS===

// ac : http://nic.ac/rules.htm
ac
com.ac
edu.ac

// a single-label TLD
com
// wildcard and exception entries
*.ck
!www.ck
a.b.c

// ===END ICANN DOMAINS===

// ===BEGIN PRIVATE DOMAINS===
private.example
should.not.appear
// ===END PRIVATE DOMAINS===
";

    fn fixture_entries() -> Vec<String> {
        extract_icann(FIXTURE).expect("fixture parses").entries
    }

    #[test]
    fn captures_provenance_from_header() {
        // GIVEN a payload with VERSION and COMMIT header lines
        // WHEN the ICANN section is extracted
        let extracted = extract_icann(FIXTURE).expect("fixture parses");
        // THEN the provenance fields are captured
        assert_eq!(extracted.version, "2026-11-04_TEST_UTC");
        assert_eq!(extracted.commit, "deadbeefcafe");
    }

    #[test]
    fn keeps_icann_entries_and_ignores_private_section() {
        // GIVEN the fixture
        let entries = fixture_entries();
        // WHEN the ICANN entries are collected
        // THEN ICANN entries are present and private ones are absent
        assert!(entries.contains(&"ac".to_string()));
        assert!(entries.contains(&"com.ac".to_string()));
        assert!(entries.contains(&"*.ck".to_string()));
        assert!(entries.contains(&"!www.ck".to_string()));
        assert!(entries.contains(&"a.b.c".to_string()));
        assert!(!entries.iter().any(|e| e.contains("private")));
        assert!(!entries.iter().any(|e| e.contains("should.not.appear")));
    }

    #[test]
    fn strips_comments_and_blank_lines() {
        // GIVEN the fixture
        let entries = fixture_entries();
        // WHEN the entries are inspected
        // THEN no comment or blank line leaked through
        assert!(
            entries
                .iter()
                .all(|e| !e.starts_with("//") && !e.is_empty()),
            "entries: {entries:?}"
        );
    }

    #[test]
    fn min_labels_two_drops_single_label_tlds() {
        // GIVEN the raw ICANN entries
        let entries = fixture_entries();
        // WHEN filtered at min_labels = 2
        let kept = filter_entries(&entries, 2);
        // THEN single-label TLDs are gone, multi-label entries remain
        assert!(
            !kept.contains(&"com".to_string()),
            "single-label 'com' should drop"
        );
        assert!(
            !kept.contains(&"ac".to_string()),
            "single-label 'ac' should drop"
        );
        assert!(kept.contains(&"com.ac".to_string()));
        assert!(kept.contains(&"*.ck".to_string()));
        assert!(kept.contains(&"!www.ck".to_string()));
        assert!(kept.contains(&"a.b.c".to_string()));
    }

    #[test]
    fn min_labels_one_keeps_everything() {
        // GIVEN the raw ICANN entries
        let entries = fixture_entries();
        // WHEN filtered at min_labels = 1
        let kept = filter_entries(&entries, 1);
        // THEN every entry survives
        assert_eq!(kept.len(), entries.len());
    }

    #[test]
    fn filter_dedupes_and_sorts() {
        // GIVEN a list with duplicates and out-of-order entries
        let entries: Vec<String> = ["b.example", "a.example", "b.example", "c.example"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // WHEN filtered at min_labels = 2
        let kept = filter_entries(&entries, 2);
        // THEN duplicates collapse and the result is sorted
        assert_eq!(kept, vec!["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn label_count_counts_literal_labels() {
        // GIVEN representative entries
        // WHEN counted
        // THEN the literal dot-separated label count is returned
        assert_eq!(label_count("com"), 1);
        assert_eq!(label_count("co.uk"), 2);
        assert_eq!(label_count("*.ck"), 2);
        assert_eq!(label_count("!www.ck"), 2);
        assert_eq!(label_count("a.b.c"), 3);
    }

    #[test]
    fn render_includes_header_and_entries() {
        // GIVEN an extracted payload and a filtered list
        let extracted = extract_icann(FIXTURE).expect("fixture parses");
        let kept = filter_entries(&extracted.entries, 2);
        // WHEN rendered
        let text = render(&extracted, 2, &kept);
        // THEN the header carries provenance and the body carries the entries
        assert!(text.starts_with("# Public Suffix List"));
        assert!(text.contains("# List version: 2026-11-04_TEST_UTC"));
        assert!(text.contains("# List commit: deadbeefcafe"));
        assert!(text.contains(&format!("# Entries: {}\n", kept.len())));
        assert!(text.contains("\ncom.ac\n"));
        assert!(text.contains("\n*.ck\n"));
        // and the single-label TLD is absent from the body
        assert!(!text.contains("\ncom\n"));
    }

    #[test]
    fn missing_icann_begin_marker_is_an_error() {
        // GIVEN a payload with no ICANN begin marker
        let dat = "// VERSION: x\n// COMMIT: y\ncom\n";
        // WHEN extracted
        let result = extract_icann(dat);
        // THEN it reports the missing begin marker
        assert!(matches!(result, Err(PslError::MissingMarker(ICANN_BEGIN))));
    }

    #[test]
    fn empty_icann_section_is_an_error() {
        // GIVEN an ICANN section with only comments
        let dat = format!("{ICANN_BEGIN}\n// nothing here\n{ICANN_END}\n");
        // WHEN extracted
        let result = extract_icann(&dat);
        // THEN it reports the empty section
        assert!(matches!(result, Err(PslError::Empty)));
    }

    #[test]
    fn missing_icann_end_marker_is_an_error() {
        // GIVEN a payload with a BEGIN marker but no END marker at all
        let dat = format!("// VERSION: x\n// COMMIT: y\n{ICANN_BEGIN}\ncom.ac\n");
        // WHEN extracted
        let result = extract_icann(&dat);
        // THEN it reports the missing end marker
        assert!(matches!(result, Err(PslError::MissingMarker(ICANN_END))));
    }

    #[test]
    fn truncated_section_never_leaks_private_entries() {
        // GIVEN a payload where END appears *before* BEGIN, so the ICANN window
        // is opened but never closed before EOF (both markers `contains`-check ok)
        let dat = format!(
            "// VERSION: x\n// COMMIT: y\n{ICANN_END}\n{ICANN_BEGIN}\ncom.ac\n\
             // ===BEGIN PRIVATE DOMAINS===\nprivate.example\n"
        );
        // WHEN extracted
        let result = extract_icann(&dat);
        // THEN it refuses with the missing-END error rather than collecting the
        // private section into the ICANN entries
        assert!(matches!(result, Err(PslError::MissingMarker(ICANN_END))));
    }

    #[test]
    fn missing_provenance_is_an_error() {
        // GIVEN a well-formed ICANN section whose header has no VERSION/COMMIT
        let dat = format!("{ICANN_BEGIN}\ncom.ac\na.b.c\n{ICANN_END}\n");
        // WHEN extracted
        let result = extract_icann(&dat);
        // THEN it refuses to produce a provenance-less artifact
        assert!(matches!(result, Err(PslError::MissingProvenance)));
    }

    #[test]
    fn parses_crlf_payload_identically() {
        // GIVEN the fixture with Windows line endings
        let crlf = FIXTURE.replace('\n', "\r\n");
        // WHEN extracted
        let extracted = extract_icann(&crlf).expect("crlf fixture parses");
        // THEN the entries match the LF fixture exactly (no stray \r)
        assert_eq!(extracted.version, "2026-11-04_TEST_UTC");
        assert_eq!(extracted.entries, fixture_entries());
        assert!(extracted.entries.iter().all(|e| !e.contains('\r')));
    }

    #[test]
    #[ignore = "hits the network; run explicitly with `cargo test -p support-bin -- --ignored`"]
    fn downloads_and_filters_the_real_list() {
        // GIVEN the live Public Suffix List
        let dat = reqwest::blocking::get(PSL_URL)
            .expect("download")
            .text()
            .expect("read body");
        // WHEN extracted and filtered at the default threshold
        let extracted = extract_icann(&dat).expect("parses");
        let kept = filter_entries(&extracted.entries, 2);
        // THEN invariants hold for the real data
        assert!(!extracted.version.is_empty(), "version should be present");
        assert!(!kept.is_empty(), "expected a non-empty list");
        assert!(
            kept.iter().all(|e| label_count(e) >= 2),
            "every kept entry must have >= 2 labels"
        );
        assert!(
            kept.iter().all(|e| !e.starts_with("//") && !e.is_empty()),
            "no comments or blanks should survive"
        );
    }
}
