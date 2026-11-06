//! HTML rendering of parsed DNS messages for the explorer's result panel.
//!
//! Reuses the shared `ui-components` design-system classes (`data_table`,
//! `data_key`, `data_title`, `mono_text`, `wrap_value`, `info_text`,
//! `warning_text`) so rendered fragments theme identically with the rest of
//! the site. All record text is HTML-escaped before interpolation: DNS data
//! (especially TXT records) is attacker-controlled.

use chrono::{DateTime, Utc};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::Record;

use crate::rdata::{RdataValue, rdata_fields};
use crate::record_names::record_type_label;

/// Renders a DNS response message as an HTML fragment: a status banner
/// followed by one table per non-empty section.
///
/// `received` is the UTC instant the response was received; it anchors each
/// record's TTL expiry ("... until <local> (<rfc3339 UTC>)").
pub fn render_message(message: &Message, received: DateTime<Utc>) -> String {
    let mut html = status_banner(message);
    if message.answers.is_empty() {
        // Surface the empty-answer condition right after the status, before
        // the authority/additional sections that accompany a negative
        // response, and flag it as a warning.
        html.push_str("<p class=\"warning_text\">No answer records returned.</p>");
    } else {
        html.push_str(&record_table("Answers", &message.answers, received));
    }
    if !message.authorities.is_empty() {
        html.push_str(&record_table("Authority", &message.authorities, received));
    }
    if !message.additionals.is_empty() {
        html.push_str(&record_table("Additional", &message.additionals, received));
    }
    html
}

fn status_banner(message: &Message) -> String {
    let code = message.metadata.response_code;
    let class = if code == ResponseCode::NoError {
        "info_text"
    } else {
        "warning_text"
    };
    // A truncated response is incomplete, so the Flags row is highlighted as
    // a warning regardless of the response code.
    let flags_class = if message.metadata.truncation {
        "warning_text"
    } else {
        "info_text"
    };
    // The JSON download link is picked up by the explorer's delegated click
    // handler (`a[data-download-format]`), which pairs it with the JSON
    // payload returned alongside this HTML.
    let flags = flags_label(message);
    let edns = edns_label(message);
    format!(
        "<table class=\"data_table\"><tbody>\
         <tr><td class=\"data_key\">Status</td><td class=\"{class}\">{code}</td></tr>\
         <tr><td class=\"data_key\">Flags</td><td class=\"{flags_class}\">{flags}</td></tr>\
         <tr><td class=\"data_key\">EDNS</td><td class=\"info_text\">{edns}</td></tr>\
         <tr><td class=\"data_key\">Other Formats</td><td class=\"format_links\"><a href=\"#\" class=\"format_link\" data-download-format=\"json\" title=\"Download JSON\">JSON <span class=\"format_arrow\">\u{21E3}</span></a></td></tr>\
         </tbody></table>"
    )
}

/// Human-readable label for the DNS header flags, as `Full Name (ABBR)`
/// entries joined by ` · `, or an em dash when no flags are set.
fn flags_label(message: &Message) -> String {
    let m = &message.metadata;
    let set = [
        (m.recursion_desired, "Recursion Desired (RD)"),
        (m.recursion_available, "Recursion Available (RA)"),
        (m.authoritative, "Authoritative Answer (AA)"),
        (m.truncation, "Truncated (TC)"),
        (m.authentic_data, "Authentic Data (AD)"),
        (m.checking_disabled, "Checking Disabled (CD)"),
    ];
    let labels: Vec<&str> = set
        .into_iter()
        .filter_map(|(on, label)| if on { Some(label) } else { None })
        .collect();
    if labels.is_empty() {
        "\u{2014}".to_string()
    } else {
        labels.join(" \u{00b7} ")
    }
}

/// Human-readable label for the EDNS0 OPT record: version, advertised
/// payload size and the DNSSEC OK flag, or `None` when the response
/// carries no EDNS0 record.
fn edns_label(message: &Message) -> String {
    match &message.edns {
        None => "None".to_string(),
        Some(edns) => {
            let mut label = format!("v{} \u{00b7} {} bytes", edns.version(), edns.max_payload());
            if edns.flags().dnssec_ok {
                label.push_str(" \u{00b7} DNSSEC OK (DO)");
            }
            label
        }
    }
}

fn record_table(title: &str, records: &[Record], received: DateTime<Utc>) -> String {
    // Each record renders as its own key/value block (one key per row);
    // consecutive records are separated by an accent divider.
    let blocks = records
        .iter()
        .map(|record| record_block(record, received))
        .collect::<Vec<_>>()
        .join("<hr class=\"data_divider\">");
    format!("<h2 class=\"data_title\">{title}</h2><div class=\"data_section\">{blocks}</div>")
}

/// Renders one record as a key/value `data_table`: each field on its own
/// row with the field name in a `.data_key` cell.
///
/// Common record types are expanded into typed, labeled rows by
/// [`rdata_fields`]. Unmapped types fall back to a single `Data` row with
/// the escaped string form.
fn record_block(record: &Record, received: DateTime<Utc>) -> String {
    // `RecordType` converts to its `&'static str` mnemonic without allocating,
    // so the formal-name lookup needs no intermediate `String`.
    let type_code: &'static str = record.record_type().into();
    let mut rows = vec![
        row_with_class("Name", "mono_text", escape(&record.name.to_string())),
        row("TTL", ttl_label(record.ttl, received)),
        row("Class", record.dns_class.to_string()),
        row("Type", record_type_label(type_code)),
    ];

    let fields = rdata_fields(&record.data);
    if fields.is_empty() {
        rows.push(row_with_class(
            "Data",
            "wrap_value",
            escape(&record.data.to_string()),
        ));
    } else {
        for field in fields {
            let value = match field.value {
                RdataValue::Text(value) => escape(&value),
                RdataValue::Address {
                    display,
                    reverse_dns,
                    rdap_query_type,
                } => address_value_html(&display, &reverse_dns, rdap_query_type),
                RdataValue::Nameserver { display } => ns_query_value_html(&display, "nameserver"),
                RdataValue::CanonicalName { display } => {
                    host_query_value_html(&display, "canonical name")
                }
                RdataValue::DomainName { display } => {
                    host_query_value_html(&display, "domain name")
                }
                RdataValue::MailExchange { display } => {
                    host_query_value_html(&display, "mail exchange")
                }
                RdataValue::PrimaryServer { display } => {
                    ns_query_value_html(&display, "primary server")
                }
                RdataValue::ServiceTarget { display } => host_query_value_html(&display, "target"),
                RdataValue::CaaIssuer { display } => host_query_value_html(&display, "CAA value"),
                RdataValue::CaaEmail { display } => copy_value_html(&display, "email address"),
                RdataValue::ResponsibleEmail { display } => {
                    copy_value_html(&display, "email address")
                }
                RdataValue::CopyableData {
                    display,
                    copy_label,
                } => copy_value_html(&display, copy_label),
            };
            rows.push(row_with_class(field.label, "wrap_value", value));
        }
    }

    format!(
        "<table class=\"data_table\"><tbody>{}</tbody></table>",
        rows.join("")
    )
}

/// Renders an IP address with its reverse-DNS link, RDAP query suffix,
/// and a copy-to-clipboard button.
///
/// The visible address remains the in-page PTR link. The trailing
/// `(⌕ RDAP)` opens the RDAP Explorer for the original address, using the
/// explicit address query type rather than a reverse-DNS query type.
/// The copy button carries `data-copy-value` so the explorer's delegated
/// click handler can copy the IP without Alpine processing `x-html`
/// directives.
fn address_value_html(display: &str, reverse_dns: &str, rdap_query_type: &str) -> String {
    format!(
        "{} {} {}",
        reverse_dns_link_html(display, reverse_dns),
        rdap_query_suffix_html(display, rdap_query_type),
        copy_button_html(display, "IP")
    )
}

/// Renders a nameserver-style host with its `(⌕ A AAAA RDAP)` query links
/// and a copy-to-clipboard button.
///
/// Used by NS records and the SOA primary server: the visible name is
/// plain text, the trailing `(⌕ A AAAA RDAP)` offers two in-page address
/// queries plus a cross-app RDAP query, and the copy button carries
/// `data-copy-value` so the explorer's delegated click handler can copy
/// the name without Alpine processing `x-html` directives. `copy_label`
/// names the kind of value (e.g. `"nameserver"`, `"primary server"`) so
/// the tooltip reads naturally.
fn ns_query_value_html(display: &str, copy_label: &str) -> String {
    format!(
        "{} {} {}",
        escape(display),
        nameserver_query_suffix_html(display),
        copy_button_html(display, copy_label)
    )
}

/// Renders the shared `A`/`AAAA` in-page DNS query links for a host name.
///
/// Both the nameserver and CNAME canonical-name suffixes reuse these links:
/// each runs an in-page lookup for the host's address records via the
/// explorer's delegated `runNsQuery` handler (the `ns` attribute naming is
/// historical; the handler is a generic "query this name for this record
/// type"). Modifier-clicks fall through to the browser's open-in-new-tab
/// behavior.
fn dns_query_links_html(display: &str) -> String {
    let a_href = escape(&format!("?name={display}&type=A"));
    let aaaa_href = escape(&format!("?name={display}&type=AAAA"));
    let a_label = escape(&format!("Query A records for {display}"));
    let aaaa_label = escape(&format!("Query AAAA records for {display}"));
    let escaped = escape(display);
    format!(
        "<a class=\"ns_query_link\" href=\"{a_href}\" title=\"{a_label}\" aria-label=\"{a_label}\" data-ns-query=\"{escaped}\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"{aaaa_href}\" title=\"{aaaa_label}\" aria-label=\"{aaaa_label}\" data-ns-query=\"{escaped}\" data-ns-query-type=\"AAAA\">AAAA</a>"
    )
}

/// Renders the `(⌕ A AAAA RDAP)` suffix for a nameserver value.
///
/// The magnifier is shared decorative chrome (`aria-hidden`); `A` and
/// `AAAA` are the shared in-page DNS query links, while `RDAP` is a
/// cross-app navigation link to the RDAP Explorer using the `nameserver`
/// query type. The RDAP link always navigates.
///
/// The href is HTML-escaped but not percent-encoded: nameserver names are
/// `[a-z0-9.-]`, so the query string is already URL-safe.
fn nameserver_query_suffix_html(display: &str) -> String {
    let rdap_href = escape(&format!("../rdap-explorer?query={display}&type=nameserver"));
    let rdap_label = escape(&format!("Query RDAP for {display}"));
    format!(
        "<span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> {} <a class=\"ns_query_link\" href=\"{rdap_href}\" title=\"{rdap_label}\" aria-label=\"{rdap_label}\">RDAP</a>)</span>",
        dns_query_links_html(display)
    )
}

/// Renders the `(⌕ A AAAA)` query suffix (shared magnifier plus the
/// shared `A`/`AAAA` links) for a host name that has no RDAP affordance.
///
/// Used by CNAME canonical targets and PTR domain names. The nameserver
/// suffix wraps the same links but appends its own RDAP link.
fn dns_query_suffix_html(display: &str) -> String {
    format!(
        "<span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> {})</span>",
        dns_query_links_html(display)
    )
}

/// Renders a host name with its `(⌕ A AAAA)` query links and a
/// copy-to-clipboard button.
///
/// Used by CNAME canonical targets and PTR domain names: the visible name
/// is plain text, the trailing `(⌕ A AAAA)` offers two in-page queries
/// for the host's address records, and the copy button carries
/// `data-copy-value` for the explorer's delegated handler. `copy_label`
/// names the kind of value (e.g. `"canonical name"`, `"domain name"`) so
/// the tooltip reads naturally.
fn host_query_value_html(display: &str, copy_label: &str) -> String {
    format!(
        "{} {} {}",
        escape(display),
        dns_query_suffix_html(display),
        copy_button_html(display, copy_label)
    )
}

/// Renders a value with a copy-to-clipboard button but no query links.
///
/// Used by the CAA `iodef` email value: the visible text is plain and the
/// trailing copy button carries `data-copy-value` for the explorer's
/// delegated handler. `copy_label` names the kind of value (e.g.
/// `"email address"`) so the tooltip reads naturally.
fn copy_value_html(display: &str, copy_label: &str) -> String {
    format!(
        "{} {}",
        escape(display),
        copy_button_html(display, copy_label)
    )
}

/// Renders an IP address as an in-page reverse-DNS query link.
///
/// The visible text is the address itself; the link target is the PTR name
/// produced by `icann_rdap_common::rdns::ip_to_reverse_dns`. The relative
/// `href` lets middle-click or modifier-click open the same query in a new
/// tab, while the explorer's delegated click handler runs the lookup in
/// place.
///
/// The href is HTML-escaped but not percent-encoded: `ip_to_reverse_dns`
/// only emits `[0-9a-f.]` labels, so the query string is already URL-safe.
fn reverse_dns_link_html(display: &str, target: &str) -> String {
    let href = escape(&format!("?name={target}&type=PTR"));
    let label = escape(&format!("Query PTR for {target}"));
    format!(
        "<a class=\"reverse_dns_link mono_text\" href=\"{href}\" title=\"{label}\" aria-label=\"{label}\" data-reverse-dns-query=\"{}\">{}</a>",
        escape(target),
        escape(display)
    )
}

/// Renders the `(⌕ RDAP)` suffix for an address value.
///
/// The whole magnifier-plus-label is clickable, but only the `RDAP` text is
/// underlined by the stylesheet. The link navigates to the sibling RDAP
/// Explorer in the same tab and queries the original IP address, not the
/// reverse DNS name.
///
/// The href is HTML-escaped but not percent-encoded: `display` comes from
/// `IpAddr::to_string`, whose charset is `[0-9a-f.:]`, so the query string
/// is already URL-safe.
fn rdap_query_suffix_html(display: &str, rdap_query_type: &str) -> String {
    let href = escape(&format!(
        "../rdap-explorer?query={display}&type={rdap_query_type}"
    ));
    let label = escape(&format!("Query RDAP for {display}"));
    format!(
        "<span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"{href}\" title=\"{label}\" aria-label=\"{label}\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span>"
    )
}

/// The copy-to-clipboard icon (shown while not just-copied).
const COPY_ICON_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="copy-icon"><rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>"#;

/// The checkmark icon (shown for two seconds after a successful copy).
/// Hidden by default via inline `style="display:none"` because the DNS
/// explorer's result panel uses `x-html`, where Alpine does not process
/// `x-show` directives. The delegated click handler toggles the inline
/// style directly.
const CHECK_ICON_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="check-icon" style="display:none"><path d="M20 6 9 17l-5-5"/></svg>"#;

/// Renders a copy-to-clipboard button for a value.
///
/// The button carries `data-copy-value` so the explorer's delegated
/// click handler (`onResultClick`) can copy the value via the
/// `copyToClipboard` helper defined in `layout.html`. The copy icon
/// swaps to a checkmark for two seconds on success, then swaps back.
///
/// `label` names the kind of value being copied (e.g. `"IP"`,
/// `"nameserver"`) so the tooltip reads naturally.
///
/// Unlike the `rdap-wasm` copy button (which uses inline Alpine
/// directives), this button uses `data-copy-value` because the DNS
/// explorer's result panel is rendered via `x-html`, where Alpine does
/// not process directives in the inserted content.
fn copy_button_html(value: &str, label: &str) -> String {
    format!(
        "<button type=\"button\" class=\"copy_btn\" title=\"Copy {label} to clipboard\" aria-label=\"Copy {escaped} to clipboard\" data-copy-value=\"{escaped}\">{COPY_ICON_SVG}{CHECK_ICON_SVG}</button>",
        escaped = escape(value),
        label = escape(label),
    )
}

fn row(label: &str, value: String) -> String {
    format!("<tr><td class=\"data_key\">{label}</td><td>{value}</td></tr>")
}

fn row_with_class(label: &str, class: &str, value: String) -> String {
    format!("<tr><td class=\"data_key\">{label}</td><td class=\"{class}\">{value}</td></tr>")
}

/// Renders a record's TTL (a `u32` count of seconds, per RFC 1035) as a
/// human-readable expiry relative to `received`: the raw seconds, then
/// "until" the local-time rendering and the RFC 3339 UTC instant.
///
/// The UTC timestamp is wrapped in a `.mono_text` span so it renders in the
/// monospace font (the local rendering stays in the surrounding font). The
/// returned value is HTML: the timestamp is chrono-generated, not
/// user-supplied, so it needs no escaping.
///
/// A TTL of `0` means "use for this transaction only, do not cache", so it
/// is labelled as non-cacheable rather than given a (meaningless) expiry.
fn ttl_label(ttl: u32, received: DateTime<Utc>) -> String {
    if ttl == 0 {
        return "0 seconds (not cacheable)".to_string();
    }
    let expires = received
        + chrono::TimeDelta::try_seconds(i64::from(ttl))
            .expect("u32 seconds always fits TimeDelta");
    let local = expires
        .with_timezone(&chrono::Local)
        .format("%d %b %Y at %l:%M %P");
    let utc = expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    format!("{ttl} seconds until {local} (<span class=\"mono_text\">{utc}</span>)")
}

/// Minimal HTML escaping for text interpolated into element content and
/// attributes. DNS rdata (TXT strings in particular) can contain anything.
/// Single quotes are escaped too so the output stays safe if a future edit
/// interpolates it into a single-quoted attribute.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::rdata::{DNSKEY, DS};
    use hickory_proto::dnssec::{Algorithm as DnsSecAlgorithm, DigestType, PublicKeyBuf};
    use hickory_proto::rr::rdata::TLSA;
    use hickory_proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, TXT};
    use hickory_proto::rr::{Name, RData, RecordData};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(name.parse().expect("name"), ttl, RData::A(A::from(ip)))
    }

    fn aaaa_record(name: &str, ip: Ipv6Addr, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::AAAA(AAAA::from(ip)),
        )
    }

    fn ns_record(name: &str, ns: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::NS(NS(ns.parse().expect("nameserver"))),
        )
    }

    fn cname_record(name: &str, target: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::CNAME(CNAME(target.parse().expect("canonical target"))),
        )
    }

    fn ptr_record(name: &str, domain: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::PTR(PTR(domain.parse().expect("domain name"))),
        )
    }

    fn soa_record(name: &str, mname: &str, rname: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::SOA(SOA::new(
                mname.parse().expect("mname"),
                rname.parse().expect("rname"),
                2026010101,
                7200,
                3600,
                1209600,
                3600,
            )),
        )
    }

    fn srv_record(name: &str, target: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::SRV(SRV::new(10, 20, 443, target.parse().expect("target"))),
        )
    }

    fn caa_issue_record(name: &str, issuer: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::CAA(CAA::new_issue(
                false,
                Some(issuer.parse().expect("issuer")),
                Vec::new(),
            )),
        )
    }

    fn caa_iodef_record(name: &str, url: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::CAA(CAA::new_iodef(
                false,
                url::Url::parse(url).expect("iodef url"),
            )),
        )
    }

    fn ds_record(name: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            DS::new(
                12345,
                DnsSecAlgorithm::ECDSAP256SHA256,
                DigestType::SHA256,
                vec![0xde, 0xad, 0xbe, 0xef],
            )
            .into_rdata(),
        )
    }

    fn dnskey_record(name: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            DNSKEY::new(
                true,
                true,
                false,
                PublicKeyBuf::new(vec![0x01, 0x02], DnsSecAlgorithm::ED25519),
            )
            .into_rdata(),
        )
    }

    fn tlsa_record(name: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            TLSA::new(
                hickory_proto::rr::rdata::tlsa::CertUsage::DaneEe,
                hickory_proto::rr::rdata::tlsa::Selector::Full,
                hickory_proto::rr::rdata::tlsa::Matching::Sha256,
                vec![0x0a, 0x1b, 0x2c],
            )
            .into_rdata(),
        )
    }

    fn txt_record(name: &str, text: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::TXT(TXT::new(vec![text.to_string()])),
        )
    }

    fn mx_record(name: &str, preference: u16, exchange: &str, ttl: u32) -> Record {
        Record::from_rdata(
            name.parse().expect("name"),
            ttl,
            RData::MX(MX::new(preference, exchange.parse().expect("exchange"))),
        )
    }

    /// Fixed receipt instant so TTL expiry assertions are deterministic.
    /// Chosen so `ttl: 300` expires exactly on the next whole minute.
    fn received() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixed received time")
            .with_timezone(&Utc)
    }

    #[test]
    fn renders_answer_section_as_table() {
        // GIVEN a message with one A record in the answer section
        let mut message = Message::new(
            1,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(a_record(
            "example.com.",
            Ipv4Addr::new(93, 184, 216, 34),
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN it carries the status banner and a record block with the data
        assert!(html.contains("Status"), "{html}");
        assert!(html.contains("No Error"), "{html}");
        assert!(html.contains("data_table"), "{html}");
        assert!(html.contains("93.184.216.34"), "{html}");
        // AND the TTL is labelled as seconds with its UTC expiry (the local
        // rendering is timezone-dependent, so only the UTC part is asserted).
        assert!(html.contains("300 seconds until"), "{html}");
        assert!(html.contains("2026-01-01T00:05:00Z"), "{html}");
        // AND the Type cell shows the formal name with the mnemonic.
        assert!(html.contains("Address (A)"), "{html}");
    }

    #[test]
    fn record_block_uses_one_key_per_row() {
        // GIVEN a message with one A record in the answer section
        let mut message = Message::new(
            11,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(a_record(
            "example.com.",
            Ipv4Addr::new(93, 184, 216, 34),
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the record renders as a key/value block: each field on its
        // own row with a .data_key cell, and the old column grid is gone
        for field in ["Name", "TTL", "Class", "Type", "Address"] {
            assert!(
                html.contains(&format!("<td class=\"data_key\">{field}</td>")),
                "missing {field} key row: {html}"
            );
        }
        assert!(
            !html.contains("<td class=\"data_key\">Data</td>"),
            "mapped A record should not render a fallback Data row: {html}"
        );
        assert!(!html.contains("stack_table"), "{html}");
        assert!(!html.contains("data-label"), "{html}");
        assert!(!html.contains("<thead>"), "{html}");
    }

    #[test]
    fn multiple_records_are_separated_by_dividers() {
        // GIVEN a message with two A records in the answer section
        let mut message = Message::new(
            12,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(a_record("a.example.", Ipv4Addr::new(93, 184, 216, 34), 300));
        message.add_answer(a_record("b.example.", Ipv4Addr::new(1, 2, 3, 4), 60));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the two record blocks are separated by exactly one divider
        assert_eq!(
            html.matches("class=\"data_divider\"").count(),
            1,
            "expected one divider between two records: {html}"
        );
        assert!(html.contains("a.example."), "{html}");
        assert!(html.contains("b.example."), "{html}");
    }

    #[test]
    fn escapes_hostile_txt_record_content() {
        // GIVEN a TXT record carrying an HTML injection attempt
        let mut message = Message::new(
            2,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(Record::from_rdata(
            "evil.example.".parse().expect("name"),
            60,
            RData::TXT(TXT::new(vec!["<script>alert(1)</script>".to_string()])),
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the payload is escaped and no live script tag survives
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }

    #[test]
    fn empty_answers_show_a_placeholder_note() {
        // GIVEN a NOERROR response with no answers but with authority and
        // additional records (a typical negative response)
        let mut message = Message::new(
            3,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_authority(a_record(
            "example.com.",
            Ipv4Addr::new(93, 184, 216, 34),
            300,
        ));
        message.add_additional(a_record("ns.example.", Ipv4Addr::new(1, 2, 3, 4), 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the "no answer" note is a warning and appears before the
        // authority and additional sections
        assert!(
            html.contains("<p class=\"warning_text\">No answer records returned.</p>"),
            "{html}"
        );
        let note_at = html
            .find("No answer records returned")
            .expect("no-answer note");
        let authority_at = html.find(">Authority<").expect("authority section");
        let additional_at = html.find(">Additional<").expect("additional section");
        assert!(
            note_at < authority_at,
            "note must precede authority: {html}"
        );
        assert!(
            note_at < additional_at,
            "note must precede additional: {html}"
        );
    }

    #[test]
    fn nxdomain_is_flagged_with_warning_style() {
        // GIVEN an NXDOMAIN response
        let mut message = Message::new(
            4,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NXDomain;

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the status cell uses the warning style and names the code
        assert!(html.contains("warning_text"), "{html}");
        assert!(html.contains("Non-Existent Domain"), "{html}");
    }

    #[test]
    fn header_flags_render_with_meaningful_names() {
        // GIVEN a response with RD and RA set
        let mut message = Message::new(
            5,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.recursion_desired = true;
        message.metadata.recursion_available = true;

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the flags row shows the full names with abbreviations, not
        // bare dig codes
        assert!(html.contains("Recursion Desired (RD)"), "{html}");
        assert!(html.contains("Recursion Available (RA)"), "{html}");
        assert!(!html.contains(">RD<"), "{html}");
        assert!(!html.contains(">RA<"), "{html}");
    }

    #[test]
    fn no_header_flags_renders_placeholder() {
        // GIVEN a response with no header flags set
        let message = Message::new(
            6,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the flags row shows the em-dash placeholder
        assert!(
            html.contains("Flags</td><td class=\"info_text\">\u{2014}"),
            "{html}"
        );
    }

    #[test]
    fn truncation_flag_highlights_the_flags_row() {
        // GIVEN a truncated response
        let mut message = Message::new(
            7,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.truncation = true;

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the flags row carries the warning style and names the flag
        assert!(html.contains("Truncated (TC)"), "{html}");
        let flags_row = html
            .split("<tr>")
            .find(|row| row.contains("Flags</td>"))
            .expect("flags row");
        assert!(flags_row.contains("warning_text"), "{flags_row}");
    }

    #[test]
    fn edns_absent_renders_none() {
        // GIVEN a response with no EDNS0 record
        let message = Message::new(
            8,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the EDNS row reads "None"
        assert!(
            html.contains("EDNS</td><td class=\"info_text\">None"),
            "{html}"
        );
    }

    #[test]
    fn edns_present_shows_version_payload_and_dnssec_ok() {
        // GIVEN a response carrying EDNS0 with the DO bit set
        let mut message = Message::new(
            9,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        message.set_edns(edns);

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the EDNS row shows version, payload and the DO flag
        assert!(html.contains("v0"), "{html}");
        assert!(html.contains("4096 bytes"), "{html}");
        assert!(html.contains("DNSSEC OK (DO)"), "{html}");
    }

    #[test]
    fn edns_without_dnssec_ok_omits_the_do_flag() {
        // GIVEN a response carrying EDNS0 without the DO bit
        let mut message = Message::new(
            10,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        message.set_edns(edns);

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the payload is shown but the DO flag is absent
        assert!(html.contains("1232 bytes"), "{html}");
        assert!(!html.contains("DNSSEC OK"), "{html}");
    }

    #[test]
    fn ttl_label_shows_seconds_and_utc_expiry() {
        // GIVEN a 300s TTL received at a fixed instant
        // WHEN labelled
        let label = ttl_label(300, received());
        // THEN it reads as seconds with the "until" phrasing and the exact
        // RFC 3339 UTC expiry (received + 300s), wrapped in the monospace
        // span. The local segment is timezone-dependent, so only the UTC
        // instant is asserted exactly.
        assert!(label.starts_with("300 seconds until "), "{label}");
        assert!(
            label.ends_with(" (<span class=\"mono_text\">2026-01-01T00:05:00Z</span>)"),
            "{label}"
        );
    }

    #[test]
    fn ttl_label_zero_is_not_cacheable_with_no_expiry() {
        // GIVEN a TTL of 0 (transaction-only, must not be cached)
        // WHEN labelled
        let label = ttl_label(0, received());
        // THEN it is flagged non-cacheable and carries no "until" time.
        assert_eq!(label, "0 seconds (not cacheable)");
        assert!(!label.contains("until"), "{label}");
    }

    #[test]
    fn ttl_label_one_second_boundary() {
        // GIVEN the smallest non-zero TTL
        // WHEN labelled
        let label = ttl_label(1, received());
        // THEN it renders as one second until one second after receipt.
        assert!(label.starts_with("1 seconds until "), "{label}");
        assert!(
            label.ends_with(" (<span class=\"mono_text\">2026-01-01T00:00:01Z</span>)"),
            "{label}"
        );
    }

    #[test]
    fn ttl_label_handles_max_u32_ttl() {
        // GIVEN the largest representable TTL (~136 years)
        // WHEN labelled
        let label = ttl_label(u32::MAX, received());
        // THEN the seconds and the UTC expiry are correct with no overflow.
        assert!(label.starts_with("4294967295 seconds until "), "{label}");
        assert!(
            label.ends_with(" (<span class=\"mono_text\">2162-02-07T06:28:15Z</span>)"),
            "{label}"
        );
    }

    #[test]
    fn ttl_label_includes_local_time_segment() {
        // GIVEN a non-zero TTL
        // WHEN labelled
        let label = ttl_label(3600, received());
        // THEN the label has a local-time segment between "until" and the
        // monospace UTC instant (structure is timezone-independent even
        // though the exact local string is not).
        let after_until = label.split(" until ").nth(1).unwrap_or_default();
        let local_part = after_until.split(" (<span").next().unwrap_or_default();
        assert!(
            local_part.contains(" at "),
            "local segment missing 'at': {label}"
        );
        assert!(
            after_until.ends_with("(<span class=\"mono_text\">2026-01-01T01:00:00Z</span>)"),
            "{label}"
        );
    }

    #[test]
    fn a_record_data_renders_reverse_dns_and_rdap_links() {
        // GIVEN an A record whose data is an IPv4 address
        let mut message = Message::new(
            20,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(a_record(
            "example.com.",
            Ipv4Addr::new(93, 184, 216, 34),
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Address cell renders the IP as a reverse-DNS query link
        // and adds an RDAP query link for the original address.
        assert!(
            html.contains(
                "Address</td><td class=\"wrap_value\"><a class=\"reverse_dns_link mono_text\" href=\"?name=34.216.184.93.in-addr.arpa&amp;type=PTR\" title=\"Query PTR for 34.216.184.93.in-addr.arpa\" aria-label=\"Query PTR for 34.216.184.93.in-addr.arpa\" data-reverse-dns-query=\"34.216.184.93.in-addr.arpa\">93.184.216.34</a> <span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"../rdap-explorer?query=93.184.216.34&amp;type=ip_v4_addr\" title=\"Query RDAP for 93.184.216.34\" aria-label=\"Query RDAP for 93.184.216.34\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy IP to clipboard\" aria-label=\"Copy 93.184.216.34 to clipboard\" data-copy-value=\"93.184.216.34\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
    }

    #[test]
    fn aaaa_record_data_renders_reverse_dns_and_rdap_links() {
        // GIVEN an AAAA record whose data is an IPv6 address
        let mut message = Message::new(
            21,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(aaaa_record(
            "example.com.",
            Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c6, 0x1970),
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Address cell renders the IPv6 address as a reverse-DNS
        // query link and adds an RDAP query link for the original address.
        assert!(
            html.contains(
                "Address</td><td class=\"wrap_value\"><a class=\"reverse_dns_link mono_text\" href=\"?name=0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa&amp;type=PTR\" title=\"Query PTR for 0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa\" aria-label=\"Query PTR for 0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa\" data-reverse-dns-query=\"0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa\">2606:2800:220:1:248:1893:25c6:1970</a> <span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"../rdap-explorer?query=2606:2800:220:1:248:1893:25c6:1970&amp;type=ip_v6_addr\" title=\"Query RDAP for 2606:2800:220:1:248:1893:25c6:1970\" aria-label=\"Query RDAP for 2606:2800:220:1:248:1893:25c6:1970\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy IP to clipboard\" aria-label=\"Copy 2606:2800:220:1:248:1893:25c6:1970 to clipboard\" data-copy-value=\"2606:2800:220:1:248:1893:25c6:1970\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
    }

    #[test]
    fn compressed_ipv6_record_renders_full_reverse_dns_target_and_rdap_address() {
        // GIVEN a compressed IPv6 address
        let mut message = Message::new(
            25,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(aaaa_record("example.com.", Ipv6Addr::LOCALHOST, 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the reverse-DNS link uses the full reverse target while the
        // RDAP link queries the compressed address itself.
        assert!(
            html.contains(
                "Address</td><td class=\"wrap_value\"><a class=\"reverse_dns_link mono_text\" href=\"?name=1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa&amp;type=PTR\" title=\"Query PTR for 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\" aria-label=\"Query PTR for 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\" data-reverse-dns-query=\"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\">::1</a> <span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"../rdap-explorer?query=::1&amp;type=ip_v6_addr\" title=\"Query RDAP for ::1\" aria-label=\"Query RDAP for ::1\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy IP to clipboard\" aria-label=\"Copy ::1 to clipboard\" data-copy-value=\"::1\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
    }

    #[test]
    fn ns_record_renders_nameserver_query_links_and_copy_button() {
        // GIVEN an NS record whose rdata is a nameserver host name
        let mut message = Message::new(
            26,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(ns_record("example.com.", "a.iana-servers.net.", 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Nameserver cell renders the name (trailing dot stripped)
        // followed by the (⌕ A AAAA RDAP) query suffix and a copy button.
        assert!(
            html.contains(
                "Nameserver</td><td class=\"wrap_value\">a.iana-servers.net <span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> <a class=\"ns_query_link\" href=\"?name=a.iana-servers.net&amp;type=A\" title=\"Query A records for a.iana-servers.net\" aria-label=\"Query A records for a.iana-servers.net\" data-ns-query=\"a.iana-servers.net\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"?name=a.iana-servers.net&amp;type=AAAA\" title=\"Query AAAA records for a.iana-servers.net\" aria-label=\"Query AAAA records for a.iana-servers.net\" data-ns-query=\"a.iana-servers.net\" data-ns-query-type=\"AAAA\">AAAA</a> <a class=\"ns_query_link\" href=\"../rdap-explorer?query=a.iana-servers.net&amp;type=nameserver\" title=\"Query RDAP for a.iana-servers.net\" aria-label=\"Query RDAP for a.iana-servers.net\">RDAP</a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy nameserver to clipboard\" aria-label=\"Copy a.iana-servers.net to clipboard\" data-copy-value=\"a.iana-servers.net\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
    }

    #[test]
    fn cname_record_renders_canonical_name_query_links_and_copy_button() {
        // GIVEN a CNAME record whose rdata is a canonical target name
        let mut message = Message::new(
            27,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(cname_record(
            "alias.example.com.",
            "target.example.com.",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Canonical Name cell renders the target (trailing dot
        // stripped) followed by the (⌕ A AAAA) query suffix and a copy
        // button — and no RDAP link.
        assert!(
            html.contains(
                "Canonical Name</td><td class=\"wrap_value\">target.example.com <span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> <a class=\"ns_query_link\" href=\"?name=target.example.com&amp;type=A\" title=\"Query A records for target.example.com\" aria-label=\"Query A records for target.example.com\" data-ns-query=\"target.example.com\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"?name=target.example.com&amp;type=AAAA\" title=\"Query AAAA records for target.example.com\" aria-label=\"Query AAAA records for target.example.com\" data-ns-query=\"target.example.com\" data-ns-query-type=\"AAAA\">AAAA</a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy canonical name to clipboard\" aria-label=\"Copy target.example.com to clipboard\" data-copy-value=\"target.example.com\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
        assert!(
            !html.contains("type=nameserver"),
            "CNAME suffix must not carry an RDAP nameserver link: {html}"
        );
    }

    #[test]
    fn ptr_record_renders_domain_name_query_links_and_copy_button() {
        // GIVEN a PTR record whose rdata is a domain name
        let mut message = Message::new(
            28,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(ptr_record(
            "34.216.184.93.in-addr.arpa.",
            "host.example.com.",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Domain Name cell renders the name (trailing dot stripped)
        // followed by the (⌕ A AAAA) query suffix and a copy button — and
        // no RDAP link.
        assert!(
            html.contains(
                "Domain Name</td><td class=\"wrap_value\">host.example.com <span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> <a class=\"ns_query_link\" href=\"?name=host.example.com&amp;type=A\" title=\"Query A records for host.example.com\" aria-label=\"Query A records for host.example.com\" data-ns-query=\"host.example.com\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"?name=host.example.com&amp;type=AAAA\" title=\"Query AAAA records for host.example.com\" aria-label=\"Query AAAA records for host.example.com\" data-ns-query=\"host.example.com\" data-ns-query-type=\"AAAA\">AAAA</a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy domain name to clipboard\" aria-label=\"Copy host.example.com to clipboard\" data-copy-value=\"host.example.com\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
        assert!(
            !html.contains("type=nameserver"),
            "PTR suffix must not carry an RDAP nameserver link: {html}"
        );
    }

    #[test]
    fn soa_record_renders_primary_server_query_links_and_copy_button() {
        // GIVEN an SOA record whose primary server is a nameserver host
        let mut message = Message::new(
            29,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(soa_record(
            "example.com.",
            "ns1.example.com.",
            "admin.example.com.",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Primary Server cell renders the host (trailing dot
        // stripped) followed by the (⌕ A AAAA RDAP) query suffix and a
        // copy button.
        assert!(
            html.contains(
                "Primary Server</td><td class=\"wrap_value\">ns1.example.com <span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> <a class=\"ns_query_link\" href=\"?name=ns1.example.com&amp;type=A\" title=\"Query A records for ns1.example.com\" aria-label=\"Query A records for ns1.example.com\" data-ns-query=\"ns1.example.com\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"?name=ns1.example.com&amp;type=AAAA\" title=\"Query AAAA records for ns1.example.com\" aria-label=\"Query AAAA records for ns1.example.com\" data-ns-query=\"ns1.example.com\" data-ns-query-type=\"AAAA\">AAAA</a> <a class=\"ns_query_link\" href=\"../rdap-explorer?query=ns1.example.com&amp;type=nameserver\" title=\"Query RDAP for ns1.example.com\" aria-label=\"Query RDAP for ns1.example.com\">RDAP</a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy primary server to clipboard\" aria-label=\"Copy ns1.example.com to clipboard\" data-copy-value=\"ns1.example.com\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
    }

    #[test]
    fn soa_record_renders_responsible_person_email_copy_button_only() {
        // GIVEN an SOA record whose responsible person is a mailbox name
        let mut message = Message::new(
            33,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(soa_record(
            "example.com.",
            "ns1.example.com.",
            "admin.example.com.",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Responsible Person cell renders the email address with a
        // copy button only — no A/AAAA query links and no RDAP link. (The
        // negative checks are scoped to this row: the SOA Primary Server
        // row in the same record legitimately carries query links.)
        assert!(
            html.contains(
                "Responsible Person</td><td class=\"wrap_value\">admin@example.com <button type=\"button\" class=\"copy_btn\" title=\"Copy email address to clipboard\" aria-label=\"Copy admin@example.com to clipboard\" data-copy-value=\"admin@example.com\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
        let responsible_row = html
            .split("<tr>")
            .find(|row| row.starts_with("<td class=\"data_key\">Responsible Person</td>"))
            .expect("responsible person row");
        assert!(
            !responsible_row.contains("data-ns-query"),
            "responsible person email must not carry A/AAAA query links: {responsible_row}"
        );
        assert!(
            !responsible_row.contains("type=nameserver"),
            "responsible person email must not carry an RDAP nameserver link: {responsible_row}"
        );
    }

    #[test]
    fn soa_record_escapes_hostile_responsible_person_email() {
        // GIVEN an SOA whose responsible-person local part carries markup
        let rname = Name::from_labels(vec![
            b"<script>".as_slice(),
            b"example".as_slice(),
            b"com".as_slice(),
        ])
        .expect("rname");
        let mut message = Message::new(
            34,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(Record::from_rdata(
            "example.com.".parse().expect("name"),
            300,
            RData::SOA(SOA::new(
                "ns1.example.com.".parse().expect("mname"),
                rname,
                2026010101,
                7200,
                3600,
                1209600,
                3600,
            )),
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the markup is escaped in both the visible text and the copy
        // value, and no live script tag survives.
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;@example.com"), "{html}");
        assert!(
            html.contains("data-copy-value=\"&lt;script&gt;@example.com\""),
            "{html}"
        );
    }

    #[test]
    fn soa_record_renders_single_label_responsible_person_as_plain_text() {
        // GIVEN an SOA whose responsible person has no domain (one label)
        let mut message = Message::new(
            35,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(soa_record(
            "example.com.",
            "ns1.example.com.",
            "admin.",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Responsible Person row is plain text with no copy button.
        let responsible_row = html
            .split("<tr>")
            .find(|row| row.starts_with("<td class=\"data_key\">Responsible Person</td>"))
            .expect("responsible person row");
        assert!(responsible_row.contains("admin."), "{responsible_row}");
        assert!(
            !responsible_row.contains("copy_btn"),
            "single-label responsible person must not render a copy button: {responsible_row}"
        );
    }

    #[test]
    fn ds_record_renders_digest_copy_button() {
        // GIVEN a DS record
        let mut message = Message::new(
            36,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(ds_record("example.com.", 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Digest cell renders the hex value with a copy button.
        assert!(
            html.contains(
                "Digest</td><td class=\"wrap_value\">deadbeef <button type=\"button\" class=\"copy_btn\" title=\"Copy digest to clipboard\" aria-label=\"Copy deadbeef to clipboard\" data-copy-value=\"deadbeef\">"
            ),
            "{html}"
        );
    }

    #[test]
    fn dnskey_record_renders_public_key_copy_button() {
        // GIVEN a DNSKEY record
        let mut message = Message::new(
            37,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(dnskey_record("example.com.", 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Public Key cell renders the base64 value with a copy button.
        assert!(
            html.contains(
                "Public Key</td><td class=\"wrap_value\">AQI= <button type=\"button\" class=\"copy_btn\" title=\"Copy public key to clipboard\" aria-label=\"Copy AQI= to clipboard\" data-copy-value=\"AQI=\""
            ),
            "{html}"
        );
    }

    #[test]
    fn tlsa_record_renders_certificate_data_copy_button() {
        // GIVEN a TLSA record
        let mut message = Message::new(
            38,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(tlsa_record("example.com.", 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Certificate Data cell renders the hex value with a copy button.
        assert!(
            html.contains(
                "Certificate Data</td><td class=\"wrap_value\">0a1b2c <button type=\"button\" class=\"copy_btn\" title=\"Copy certificate data to clipboard\" aria-label=\"Copy 0a1b2c to clipboard\" data-copy-value=\"0a1b2c\">"
            ),
            "{html}"
        );
    }

    #[test]
    fn srv_record_renders_target_query_links_and_copy_button() {
        // GIVEN an SRV record whose target is a host name
        let mut message = Message::new(
            30,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(srv_record(
            "_https._tcp.example.com.",
            "svc.example.com.",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Target cell renders the host (trailing dot stripped)
        // followed by the (⌕ A AAAA) query suffix and a copy button — and
        // no RDAP link.
        assert!(
            html.contains(
                "Target</td><td class=\"wrap_value\">svc.example.com <span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> <a class=\"ns_query_link\" href=\"?name=svc.example.com&amp;type=A\" title=\"Query A records for svc.example.com\" aria-label=\"Query A records for svc.example.com\" data-ns-query=\"svc.example.com\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"?name=svc.example.com&amp;type=AAAA\" title=\"Query AAAA records for svc.example.com\" aria-label=\"Query AAAA records for svc.example.com\" data-ns-query=\"svc.example.com\" data-ns-query-type=\"AAAA\">AAAA</a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy target to clipboard\" aria-label=\"Copy svc.example.com to clipboard\" data-copy-value=\"svc.example.com\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
        assert!(
            !html.contains("type=nameserver"),
            "SRV suffix must not carry an RDAP nameserver link: {html}"
        );
    }

    #[test]
    fn caa_record_renders_issuer_query_links_and_copy_button() {
        // GIVEN a CAA issue record whose value is an LDH issuer host
        let mut message = Message::new(
            31,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(caa_issue_record("example.com.", "ca.example.net.", 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Value cell renders the issuer (trailing dot stripped)
        // followed by the (⌕ A AAAA) query suffix and a copy button — and
        // no RDAP link.
        assert!(
            html.contains(
                "Value</td><td class=\"wrap_value\">ca.example.net <span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> <a class=\"ns_query_link\" href=\"?name=ca.example.net&amp;type=A\" title=\"Query A records for ca.example.net\" aria-label=\"Query A records for ca.example.net\" data-ns-query=\"ca.example.net\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"?name=ca.example.net&amp;type=AAAA\" title=\"Query AAAA records for ca.example.net\" aria-label=\"Query AAAA records for ca.example.net\" data-ns-query=\"ca.example.net\" data-ns-query-type=\"AAAA\">AAAA</a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy CAA value to clipboard\" aria-label=\"Copy ca.example.net to clipboard\" data-copy-value=\"ca.example.net\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
        assert!(
            !html.contains("type=nameserver"),
            "CAA issuer suffix must not carry an RDAP nameserver link: {html}"
        );
    }

    #[test]
    fn caa_iodef_mailto_renders_copy_button_only() {
        // GIVEN a CAA iodef record whose value is a mailto URI
        let mut message = Message::new(
            32,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(caa_iodef_record(
            "example.com.",
            "mailto:security@example.com",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the Value cell renders the bare email address with a copy
        // button only — no A/AAAA query links and no RDAP link.
        assert!(
            html.contains(
                "Value</td><td class=\"wrap_value\">security@example.com <button type=\"button\" class=\"copy_btn\" title=\"Copy email address to clipboard\" aria-label=\"Copy security@example.com to clipboard\" data-copy-value=\"security@example.com\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
        assert!(
            !html.contains("data-ns-query"),
            "CAA email value must not carry A/AAAA query links: {html}"
        );
        assert!(
            !html.contains("type=nameserver"),
            "CAA email value must not carry an RDAP nameserver link: {html}"
        );
    }

    #[test]
    fn txt_record_falls_back_to_plain_data_row() {
        // GIVEN a TXT record whose text contains a standalone IPv4
        let mut message = Message::new(
            22,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(txt_record(
            "example.com.",
            "backup nameserver 198.51.100.3 available",
            300,
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the TXT record uses the fallback Data row and does not scan
        // the string for IP-like tokens.
        assert!(
            html.contains(
                "Data</td><td class=\"wrap_value\">backup nameserver 198.51.100.3 available</td>"
            ),
            "{html}"
        );
        assert!(
            !html.contains("<span class=\"mono_text\">198.51.100.3</span>"),
            "{html}"
        );
    }

    #[test]
    fn mx_record_renders_labeled_rows() {
        // GIVEN an MX record
        let mut message = Message::new(
            23,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(mx_record("example.com.", 10, "mail.example.", 300));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the MX fields are rendered as separate labeled rows: the
        // preference is plain text and the exchange carries the
        // (⌕ A AAAA) query suffix and a copy button.
        assert!(
            html.contains("Preference</td><td class=\"wrap_value\">10</td>"),
            "{html}"
        );
        assert!(
            html.contains(
                "Exchange</td><td class=\"wrap_value\">mail.example <span class=\"ns_query_suffix\">(<span class=\"ns_query_glyph\" aria-hidden=\"true\">\u{2315}</span> <a class=\"ns_query_link\" href=\"?name=mail.example&amp;type=A\" title=\"Query A records for mail.example\" aria-label=\"Query A records for mail.example\" data-ns-query=\"mail.example\" data-ns-query-type=\"A\">A</a> <a class=\"ns_query_link\" href=\"?name=mail.example&amp;type=AAAA\" title=\"Query AAAA records for mail.example\" aria-label=\"Query AAAA records for mail.example\" data-ns-query=\"mail.example\" data-ns-query-type=\"AAAA\">AAAA</a>)</span> <button type=\"button\" class=\"copy_btn\" title=\"Copy mail exchange to clipboard\" aria-label=\"Copy mail.example to clipboard\" data-copy-value=\"mail.example\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"copy-icon\"><rect width=\"8\" height=\"4\" x=\"8\" y=\"2\" rx=\"1\" ry=\"1\"/><path d=\"M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2\"/></svg><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"check-icon\" style=\"display:none\"><path d=\"M20 6 9 17l-5-5\"/></svg></button></td>"
            ),
            "{html}"
        );
        assert!(
            !html.contains("<td class=\"data_key\">Data</td>"),
            "mapped MX record should not render a fallback Data row: {html}"
        );
    }

    #[test]
    fn mapped_naptr_regexp_is_escaped() {
        // GIVEN a mapped NAPTR record whose regexp carries HTML markup
        let mut message = Message::new(
            24,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;
        message.add_answer(Record::from_rdata(
            "example.com.".parse().expect("name"),
            300,
            RData::NAPTR(NAPTR::new(
                1,
                2,
                b"U".to_vec().into_boxed_slice(),
                b"".to_vec().into_boxed_slice(),
                b"<script>alert(1)</script>".to_vec().into_boxed_slice(),
                "replacement.example.".parse().expect("replacement"),
            )),
        ));

        // WHEN rendered
        let html = render_message(&message, received());

        // THEN the mapped row escapes the hostile regexp value.
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(
            html.contains(
                "Regexp</td><td class=\"wrap_value\">&lt;script&gt;alert(1)&lt;/script&gt;</td>"
            ),
            "{html}"
        );
    }
}
