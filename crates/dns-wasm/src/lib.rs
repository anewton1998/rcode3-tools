//! Browser-side DNS-over-HTTPS client for the dns-explorer app.
//!
//! Mirrors the `rdap-wasm` pattern: the axum server never sees lookups —
//! the page calls into this module (compiled to wasm) and the query travels
//! directly from the browser to the configured DoH server. `hickory-proto`
//! provides the DNS wire format; the HTTPS transport is the browser's
//! `fetch` (via reqwest's wasm backend).
//!
//! Design note: `hickory-resolver`'s DoH transport is tokio-native and
//! cannot run under wasm32-unknown-unknown, so the explorer drives
//! `hickory-proto` messages over a plain HTTP fetch instead. The native
//! `rlib` build keeps the same code path testable with tokio.

mod lookup;
mod rdata;
mod record_names;
mod render;

use std::sync::Mutex;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use wasm_bindgen::prelude::*;

/// DoH endpoint used when none has been configured.
pub const DEFAULT_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

static DOH_URL: Mutex<Option<String>> = Mutex::new(None);

/// Trims whitespace and trailing slashes so endpoint URLs compare equal
/// regardless of a trailing slash.
fn normalize_doh_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn current_doh_url() -> String {
    DOH_URL
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        // A stored empty string (e.g. `set_doh_url("")`) falls back to the
        // baked default rather than producing a malformed request URL.
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| DEFAULT_DOH_URL.to_string())
}

/// Sets the DNS-over-HTTPS server URL used for all lookups.
#[wasm_bindgen]
pub fn set_doh_url(url: &str) {
    let mut guard = DOH_URL.lock().expect("doh url lock poisoned");
    *guard = Some(normalize_doh_url(url));
}

/// Returns the currently configured DoH server URL.
#[wasm_bindgen(js_name = getDohUrl)]
pub fn get_doh_url() -> String {
    current_doh_url()
}

/// One selectable record type in the dropdown.
///
/// `code` is the mnemonic (the `<option>` value sent to the lookup); `label`
/// is the display text, a formal name with the mnemonic in parentheses
/// (e.g. `Address (A)`).
#[derive(serde::Serialize)]
struct RecordTypeOption {
    code: &'static str,
    label: String,
}

/// A labelled group of record types for the dropdown UI.
#[derive(serde::Serialize)]
struct RecordTypeGroup {
    label: &'static str,
    options: Vec<RecordTypeOption>,
}

/// The record types offered in the explorer, grouped for display.
fn record_type_groups() -> Vec<RecordTypeGroup> {
    const GROUPS: &[(&str, &[&str])] = &[
        ("Addresses", &["A", "AAAA"]),
        ("Names", &["CNAME", "NS", "PTR", "SOA"]),
        ("Mail & Text", &["MX", "TXT"]),
        ("Services", &["SRV", "NAPTR", "CAA"]),
        ("Security", &["DNSKEY", "DS", "SSHFP", "TLSA"]),
    ];
    GROUPS
        .iter()
        .map(|(label, codes)| RecordTypeGroup {
            label,
            options: codes
                .iter()
                .map(|code| RecordTypeOption {
                    code,
                    label: record_names::record_type_label(code),
                })
                .collect(),
        })
        .collect()
}

/// Returns the grouped record-type options for the dropdown UI.
///
/// Resolves to an array of `{ label, options: [{ code, label }] }`.
#[wasm_bindgen(js_name = recordTypeGroups)]
pub fn record_type_groups_export() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&record_type_groups())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parses a record-type code (`"A"`, `"AAAA"`, `"MX"`, ...) as offered by
/// [`record_type_groups_export`].
fn parse_record_type(code: &str) -> Result<RecordType, String> {
    code.trim()
        .parse::<RecordType>()
        .map_err(|_| format!("unknown DNS record type: {code}"))
}

/// Converts an IP address typed into the explorer input into its reverse
/// DNS name (`"1.2.3.4"` → `"4.3.2.1.in-addr.arpa"`).
///
/// Returns `None` (JS `undefined`) when the input is not a parseable IP
/// address, so the caller can distinguish "not an IP" from an error
/// without exception handling. The lookup side pairs this with a forced
/// `PTR` record type.
///
/// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) convert to the full
/// 32-nibble `ip6.arpa` form per RFC 3596, not the `in-addr.arpa`
/// form; bracketed (`[::1]`) and zone-id (`fe80::1%eth0`) forms do not
/// parse and return `None`.
#[wasm_bindgen(js_name = ipToReverseDns)]
pub fn ip_to_reverse_dns_export(input: &str) -> Option<String> {
    input
        .trim()
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| icann_rdap_common::rdns::ip_to_reverse_dns(&ip))
}

/// The payload returned by [`dns_explorer`].
#[derive(serde::Serialize)]
struct DnsLookupResult {
    /// Result-panel HTML: status banner plus one table per message section.
    html: String,
    /// Pretty-printed JSON of the parsed DNS message (for downloads).
    json: String,
    /// Short human-readable status for non-NOERROR responses (empty on
    /// NOERROR); drives the red line and the history entry.
    error: String,
}

/// Runs a DNS-over-HTTPS lookup in the browser and resolves with
/// `{ html, json, error }`.
///
/// A non-NOERROR response (e.g. NXDOMAIN) renders into `html` with a short
/// summary in `error`; only a transport/parse failure throws.
#[wasm_bindgen(js_name = dnsExplorer)]
pub async fn dns_explorer(name: &str, record_type: &str) -> Result<JsValue, JsValue> {
    let record_type = parse_record_type(record_type).map_err(|e| JsValue::from_str(&e))?;
    let (message, received) = lookup::query_doh(&current_doh_url(), name, record_type)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let error = if message.metadata.response_code == ResponseCode::NoError {
        String::new()
    } else {
        format!("DNS status: {}", message.metadata.response_code)
    };
    // A serialization failure is surfaced in the JSON payload rather than
    // silently producing an empty download.
    let json = serde_json::to_string_pretty(&message)
        .unwrap_or_else(|e| format!("{{\"error\": \"json serialization failed: {e}\"}}"));
    let result = DnsLookupResult {
        html: render::render_message(&message, received),
        json,
        error,
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_doh_url_trims_slash_and_space() {
        assert_eq!(
            normalize_doh_url("  https://dns.example.com/dns-query//  "),
            "https://dns.example.com/dns-query"
        );
        assert_eq!(
            normalize_doh_url("https://dns.example"),
            "https://dns.example"
        );
    }

    #[test]
    fn default_doh_url_until_configured() {
        // The initial state (no set_doh_url) falls back to the baked default.
        // Note: other tests must not call set_doh_url before this one; the
        // global is only mutated through the wasm-facing setter.
        assert_eq!(current_doh_url(), DEFAULT_DOH_URL);
    }

    #[test]
    fn record_type_groups_cover_the_common_types() {
        // GIVEN the dropdown groups
        let groups = record_type_groups();
        // THEN every advertised code parses as a real record type, its label
        // is "Formal (MNEMONIC)", and the common lookup types are present.
        let mut codes: Vec<&str> = Vec::new();
        for group in &groups {
            assert!(!group.options.is_empty(), "{} group is empty", group.label);
            for option in &group.options {
                assert!(
                    parse_record_type(option.code).is_ok(),
                    "group {} advertises unparseable code {}",
                    group.label,
                    option.code
                );
                // Every dropdown code must be curated, otherwise it would
                // silently render as "Unknown (CODE)".
                assert!(
                    record_names::formal_record_name(option.code).is_some(),
                    "dropdown code {} has no curated formal name (would render as Unknown)",
                    option.code
                );
                assert!(
                    option.label.ends_with(&format!("({})", option.code)),
                    "label {:?} does not end with the mnemonic ({})",
                    option.label,
                    option.code
                );
                codes.push(option.code);
            }
        }
        for expected in ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"] {
            assert!(codes.contains(&expected), "missing {expected} in {codes:?}");
        }
    }

    #[test]
    fn record_type_group_labels_are_formal_names() {
        // GIVEN the dropdown groups
        // WHEN the offered codes are inspected
        let groups = record_type_groups();
        let label_for = |code: &str| -> String {
            groups
                .iter()
                .flat_map(|g| g.options.iter())
                .find(|o| o.code == code)
                .map(|o| o.label.clone())
                .unwrap_or_default()
        };
        // THEN each shows the formal name with the mnemonic in parentheses.
        assert_eq!(label_for("A"), "Address (A)");
        assert_eq!(label_for("MX"), "Mail Exchange (MX)");
        assert_eq!(label_for("SOA"), "Start of Authority (SOA)");
        assert_eq!(label_for("TLSA"), "TLSA Certificate Association (TLSA)");
    }

    #[test]
    fn parse_record_type_rejects_garbage() {
        assert!(parse_record_type("not-a-type").is_err());
        assert!(parse_record_type("").is_err());
    }

    #[test]
    fn ip_to_reverse_dns_converts_ipv4() {
        // GIVEN an IPv4 address in the input
        // WHEN it is converted for a reverse lookup
        let reverse = ip_to_reverse_dns_export("1.2.3.4");
        // THEN it is the reversed-octet in-addr.arpa name
        assert_eq!(reverse.as_deref(), Some("4.3.2.1.in-addr.arpa"));
    }

    #[test]
    fn ip_to_reverse_dns_converts_ipv6() {
        // GIVEN a compressed IPv6 address in the input
        // WHEN it is converted for a reverse lookup
        let reverse = ip_to_reverse_dns_export("2001:db8::567:89ab");
        // THEN it is the full nibble-reversed ip6.arpa name
        assert_eq!(
            reverse.as_deref(),
            Some("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
        );
    }

    #[test]
    fn ip_to_reverse_dns_trims_whitespace() {
        // GIVEN surrounding whitespace (the JS caller also trims; the
        // Rust-side trim is defensive redundancy)
        // WHEN it is converted
        let reverse = ip_to_reverse_dns_export("  10.0.0.1  ");
        // THEN the address still parses and converts
        assert_eq!(reverse.as_deref(), Some("1.0.0.10.in-addr.arpa"));
    }

    #[test]
    fn ip_to_reverse_dns_ipv4_mapped_ipv6_uses_ip6_arpa() {
        // GIVEN an IPv4-mapped IPv6 address
        // WHEN it is converted
        let reverse = ip_to_reverse_dns_export("::ffff:1.2.3.4");
        // THEN it is the full 32-nibble ip6.arpa form (RFC 3596), not
        // the in-addr.arpa name a user might expect
        assert_eq!(
            reverse.as_deref(),
            Some("4.0.3.0.2.0.1.0.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa")
        );
    }

    #[test]
    fn ip_to_reverse_dns_returns_none_for_domain_names() {
        // GIVEN plain domain names and partial IPs that are not addresses
        // WHEN they are offered for reverse conversion
        // THEN none of them convert (JS sees null, lookup keeps its type)
        for input in [
            "example.com",
            "1.2.3",
            "256.1.1.1",
            "1.2.3.4.5",
            "010.1.1.1",
            "[::1]",
            "fe80::1%eth0",
            "",
            "   ",
            "2001:db8::gg",
        ] {
            assert_eq!(
                ip_to_reverse_dns_export(input),
                None,
                "{input:?} should not convert to a reverse name"
            );
        }
    }
}
