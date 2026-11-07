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
//! - The RDAP gate (`rdap_tlds` + `filter_by_rdap`) drops entries whose
//!   top-level label has no RDAP service in the IANA bootstrap file. TLDs are
//!   compared as punycode A-labels, so a Unicode entry like `a.рф` matches the
//!   bootstrap's `xn--p1ai` spelling.

use std::collections::HashSet;
use std::fmt::Write as _;

use thiserror::Error;

/// Canonical source of the Public Suffix List.
pub const PSL_URL: &str = "https://publicsuffix.org/list/public_suffix_list.dat";

/// Canonical source of the IANA RDAP bootstrap file for DNS registrations.
pub const RDAP_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";

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

/// Errors produced while parsing the IANA RDAP bootstrap file.
#[derive(Debug, Error)]
pub enum RdapError {
    /// The payload was not valid JSON.
    #[error("invalid RDAP bootstrap JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// The JSON was valid but did not match the documented bootstrap shape.
    #[error("unexpected RDAP bootstrap shape: {0}")]
    UnexpectedShape(&'static str),
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

/// Normalize a TLD to its punycode A-label for matching.
///
/// Every label goes through `domain_to_ascii`, which lowercases ASCII and
/// converts Unicode to its A-label. A label that fails IDNA validation falls
/// back to a lowercased raw copy — it simply never matches a valid bootstrap
/// entry, which is the safe outcome.
fn normalize_tld(tld: &str) -> String {
    idna::domain_to_ascii(tld).unwrap_or_else(|_| tld.to_ascii_lowercase())
}

/// The top-level label of an entry, ignoring wildcard/exception markers.
///
/// `*.ck` and `!www.ck` both yield `ck`; `com` yields `com`.
pub fn tld_of(entry: &str) -> &str {
    let entry = entry.strip_prefix('!').unwrap_or(entry);
    let entry = entry.strip_prefix("*.").unwrap_or(entry);
    entry.rsplit('.').next().unwrap_or(entry)
}

/// Collect the set of TLDs covered by the IANA RDAP bootstrap file.
///
/// The file maps RDAP base URLs to the TLDs they serve (`services[i][0]` is
/// the TLD list for `services[i][1]`); this returns the union of every TLD
/// list, normalized to punycode A-labels so Unicode and `xn--` spellings
/// collapse to one canonical form.
pub fn rdap_tlds(json: &str) -> Result<HashSet<String>, RdapError> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let services = value
        .get("services")
        .and_then(serde_json::Value::as_array)
        .ok_or(RdapError::UnexpectedShape("missing `services` array"))?;

    let mut tlds = HashSet::new();
    for service in services {
        let labels = service
            .get(0)
            .and_then(serde_json::Value::as_array)
            .ok_or(RdapError::UnexpectedShape("service entry has no TLD list"))?;
        for label in labels {
            let tld = label
                .as_str()
                .ok_or(RdapError::UnexpectedShape("TLD label is not a string"))?;
            tlds.insert(normalize_tld(tld));
        }
    }
    if tlds.is_empty() {
        return Err(RdapError::UnexpectedShape("`services` contains no TLDs"));
    }
    Ok(tlds)
}

/// Keep only entries whose TLD is covered by the RDAP bootstrap set.
///
/// An entry survives when its top-level label (wildcard/exception markers
/// stripped, punycode-normalized) is present in `tlds`; entries under TLDs
/// with no RDAP service are dropped. Input order is preserved.
pub fn filter_by_rdap(entries: &[String], tlds: &HashSet<String>) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| tlds.contains(&normalize_tld(tld_of(entry))))
        .cloned()
        .collect()
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

/// Render the **full** ICANN public suffix list artifact: a `#` provenance header
/// followed by every ICANN entry (all label counts, wildcards and exceptions
/// preserved) on its own line.
///
/// Unlike [`render`], this artifact is **not** RDAP-gated and **not** min-label
/// filtered, so it is the authoritative source for registrable-domain (eTLD+1)
/// computation: single-label TLDs (`com`), wildcards (`*.ck`) and exceptions
/// (`!www.ck`) are all present, and the result is independent of RDAP coverage.
pub fn render_icann_psl(extracted: &Extracted, entries: &[String]) -> String {
    let generated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    // Writing to a `String` is infallible, so the `writeln!` results are ignored.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Public Suffix List - ICANN domains (full, all labels)"
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

/// Read the `publication` timestamp from the IANA RDAP bootstrap JSON.
///
/// Returns [`RdapError::UnexpectedShape`] if the field is absent or not a string,
/// so a committed `rdap_tlds.txt` always carries real provenance.
pub fn rdap_publication(json: &str) -> Result<String, RdapError> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    value
        .get("publication")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or(RdapError::UnexpectedShape("missing `publication` field"))
}

/// Render the RDAP-covered TLD set artifact: a `#` provenance header followed by
/// one punycode A-label per line, sorted.
///
/// This is the positive signal for "is this TLD served by RDAP": a TLD absent
/// from this list (e.g. `de`) has no RDAP service in the IANA bootstrap.
pub fn render_rdap_tlds(tlds: &HashSet<String>, publication: &str) -> String {
    let generated = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut sorted: Vec<&String> = tlds.iter().collect();
    sorted.sort();
    // Writing to a `String` is infallible, so the `writeln!` results are ignored.
    let mut out = String::new();
    let _ = writeln!(out, "# RDAP-covered TLDs (IANA bootstrap)");
    let _ = writeln!(out, "# Source: {RDAP_BOOTSTRAP_URL}");
    let _ = writeln!(out, "# Bootstrap publication: {publication}");
    let _ = writeln!(out, "# Generated: {generated}");
    let _ = writeln!(out, "# TLDs: {}", sorted.len());
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# Generated by `cargo run -p support-bin --bin psl-extract`. Do not edit by hand."
    );
    for tld in sorted {
        let _ = writeln!(out, "{tld}");
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

    /// A miniature IANA RDAP bootstrap fixture: service rows covering
    /// single-label, multi-label, uppercase, and Unicode spellings.
    const RDAP_FIXTURE: &str = r#"{
  "description": "RDAP bootstrap file for Domain Name System registrations",
  "publication": "2026-10-28T22:00:04Z",
  "services": [
    [["com"], ["https://rdap.example/com/"]],
    [["рф", "xn--p1ai"], ["https://rdap.example/rf/"]],
    [["kg", "MG"], ["http://rdap.example/kg/"]]
  ]
}"#;

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

    #[test]
    fn rdap_tlds_collects_and_normalizes_all_labels() {
        // GIVEN a bootstrap fixture with multi-label, uppercase and Unicode rows
        // WHEN the TLD set is parsed
        let tlds = rdap_tlds(RDAP_FIXTURE).expect("fixture parses");
        // THEN every label is present, lowercased / punycoded (рф dedupes with
        // its own xn-- spelling, so four unique TLDs remain)
        assert!(tlds.contains("com"));
        assert!(tlds.contains("xn--p1ai"));
        assert!(tlds.contains("kg"));
        assert!(tlds.contains("mg"));
        assert_eq!(tlds.len(), 4);
    }

    #[test]
    fn rdap_tlds_rejects_invalid_json() {
        // GIVEN a payload that is not JSON at all
        // WHEN parsed
        let result = rdap_tlds("not json");
        // THEN it reports invalid JSON
        assert!(matches!(result, Err(RdapError::InvalidJson(_))));
    }

    #[test]
    fn rdap_tlds_rejects_missing_services() {
        // GIVEN valid JSON without the required `services` array
        // WHEN parsed
        let result = rdap_tlds(r#"{"publication": "x"}"#);
        // THEN it reports the unexpected shape
        assert!(matches!(result, Err(RdapError::UnexpectedShape(_))));
    }

    #[test]
    fn rdap_tlds_rejects_non_string_label() {
        // GIVEN a service row whose TLD list contains a non-string element
        // WHEN parsed
        let result = rdap_tlds(r#"{"services": [[["com", 42], ["https://x/"]]]}"#);
        // THEN it reports the unexpected shape
        assert!(matches!(result, Err(RdapError::UnexpectedShape(_))));
    }

    #[test]
    fn rdap_tlds_rejects_empty_services() {
        // GIVEN a bootstrap file with no service rows at all
        // WHEN parsed
        let result = rdap_tlds(r#"{"services": []}"#);
        // THEN it refuses rather than yielding an empty gate
        assert!(matches!(result, Err(RdapError::UnexpectedShape(_))));
    }

    #[test]
    fn rdap_tlds_rejects_service_row_that_is_not_an_array() {
        // GIVEN a `services` array whose row is a bare string, not a [tlds, urls] pair
        // WHEN parsed
        let result = rdap_tlds(r#"{"services": ["x"]}"#);
        // THEN it reports the unexpected shape
        assert!(matches!(result, Err(RdapError::UnexpectedShape(_))));
    }

    #[test]
    fn rdap_tlds_rejects_all_empty_tld_lists() {
        // GIVEN service rows whose TLD lists are all empty
        // WHEN parsed
        let result = rdap_tlds(r#"{"services": [[], []]}"#);
        // THEN the empty-set guard fires
        assert!(matches!(result, Err(RdapError::UnexpectedShape(_))));
    }

    #[test]
    fn tld_of_strips_wildcard_and_exception_markers() {
        // GIVEN representative entries
        // WHEN the top-level label is extracted
        // THEN markers are ignored and the last label is returned
        assert_eq!(tld_of("com"), "com");
        assert_eq!(tld_of("co.uk"), "uk");
        assert_eq!(tld_of("*.ck"), "ck");
        assert_eq!(tld_of("!www.ck"), "ck");
        assert_eq!(tld_of("a.b.c"), "c");
        // marker combo that isn't valid PSL, but must not panic
        assert_eq!(tld_of("!*.ck"), "ck");
    }

    #[test]
    fn filter_by_rdap_keeps_known_and_drops_unknown_tlds() {
        // GIVEN entries whose TLDs are only partly covered by the fixture
        let tlds = rdap_tlds(RDAP_FIXTURE).expect("fixture parses");
        let entries: Vec<String> = ["com", "a.com", "com.kg", "a.mg", "a.nope", "*.nope"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // WHEN filtered against the bootstrap set
        let kept = filter_by_rdap(&entries, &tlds);
        // THEN only entries under covered TLDs survive, in input order
        assert_eq!(kept, vec!["com", "a.com", "com.kg", "a.mg"]);
    }

    #[test]
    fn filter_by_rdap_matches_unicode_against_punycode_set() {
        // GIVEN a punycode-only set and a Unicode-TLD entry
        let tlds: HashSet<String> = ["xn--p1ai".to_string()].into_iter().collect();
        let entries: Vec<String> = ["a.рф", "xn--p1ai", "b.com"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // WHEN filtered
        let kept = filter_by_rdap(&entries, &tlds);
        // THEN the Unicode entry matches via punycode normalization and the
        // uncovered `com` entry drops
        assert_eq!(kept, vec!["a.рф", "xn--p1ai"]);
    }

    #[test]
    #[ignore = "hits the network; run explicitly with `cargo test -p support-bin -- --ignored`"]
    fn downloads_the_real_rdap_bootstrap() {
        // GIVEN the live IANA RDAP bootstrap file
        let json = reqwest::blocking::get(RDAP_BOOTSTRAP_URL)
            .expect("download")
            .text()
            .expect("read body");
        // WHEN the TLD set is parsed
        let tlds = rdap_tlds(&json).expect("parses");
        // THEN well-known gTLDs are covered and the set is plausibly complete.
        // (Do NOT assert Unicode-TLD A-labels here: coverage of IDN TLDs in the
        // bootstrap changes over time; the synthetic fixture covers that path.)
        assert!(tlds.contains("com"));
        assert!(tlds.contains("net"));
        assert!(tlds.contains("org"));
        assert!(
            tlds.len() > 1_000,
            "bootstrap should cover 1000+ TLDs, got {}",
            tlds.len()
        );
    }

    #[test]
    fn render_icann_psl_keeps_single_labels_wildcards_and_exceptions() {
        // GIVEN the full ICANN entries (no min-label / RDAP filtering)
        let extracted = extract_icann(FIXTURE).expect("fixture parses");
        let full = filter_entries(&extracted.entries, 1);
        // WHEN rendered as the full PSL artifact
        let text = render_icann_psl(&extracted, &full);
        // THEN single-label TLDs, wildcards and exceptions all survive
        assert!(text.starts_with("# Public Suffix List - ICANN domains (full"));
        assert!(
            text.contains("\ncom\n"),
            "single-label TLD 'com' must be kept"
        );
        assert!(text.contains("\n*.ck\n"), "wildcard entry must be kept");
        assert!(text.contains("\n!www.ck\n"), "exception entry must be kept");
        assert!(text.contains(&format!("# Entries: {}\n", full.len())));
    }

    #[test]
    fn rdap_publication_reads_the_bootstrap_field() {
        // GIVEN the bootstrap fixture with a publication timestamp
        // WHEN read
        let publication = rdap_publication(RDAP_FIXTURE).expect("has publication");
        // THEN the value is returned verbatim
        assert_eq!(publication, "2026-10-28T22:00:04Z");
    }

    #[test]
    fn rdap_publication_missing_is_an_error() {
        // GIVEN bootstrap JSON with no publication field
        // WHEN read
        let result = rdap_publication(r#"{"services": [["com"], ["https://x/"]]}"#);
        // THEN it reports the unexpected shape
        assert!(matches!(result, Err(RdapError::UnexpectedShape(_))));
    }

    #[test]
    fn render_rdap_tlds_is_sorted_with_provenance() {
        // GIVEN an unsorted TLD set and a publication string
        let tlds: HashSet<String> = ["org", "com", "xn--p1ai"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // WHEN rendered
        let text = render_rdap_tlds(&tlds, "2026-10-28T22:00:04Z");
        // THEN the header carries provenance and the body is sorted, one per line
        assert!(text.starts_with("# RDAP-covered TLDs"));
        assert!(text.contains("# Bootstrap publication: 2026-10-28T22:00:04Z"));
        assert!(text.contains("# TLDs: 3"));
        let body: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(body, vec!["com", "org", "xn--p1ai"]);
    }
}
