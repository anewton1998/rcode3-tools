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
            };
            rows.push(row_with_class(field.label, "wrap_value", value));
        }
    }

    format!(
        "<table class=\"data_table\"><tbody>{}</tbody></table>",
        rows.join("")
    )
}

/// Renders an IP address with its reverse-DNS link and RDAP query suffix.
///
/// The visible address remains the in-page PTR link. The trailing
/// `(⌕ RDAP)` opens the RDAP Explorer for the original address, using the
/// explicit address query type rather than a reverse-DNS query type.
fn address_value_html(display: &str, reverse_dns: &str, rdap_query_type: &str) -> String {
    format!(
        "{}{}",
        reverse_dns_link_html(display, reverse_dns),
        rdap_query_suffix_html(display, rdap_query_type)
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
/// underlined by the stylesheet. The link points at the sibling RDAP
/// Explorer and queries the original IP address, not the reverse DNS name.
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
        "<span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"{href}\" title=\"{label}\" aria-label=\"{label}\" target=\"_blank\" rel=\"noopener noreferrer\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span>"
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
    use hickory_proto::rr::RData;
    use hickory_proto::rr::rdata::{A, AAAA, MX, NAPTR, TXT};
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
                "Address</td><td class=\"wrap_value\"><a class=\"reverse_dns_link mono_text\" href=\"?name=34.216.184.93.in-addr.arpa&amp;type=PTR\" title=\"Query PTR for 34.216.184.93.in-addr.arpa\" aria-label=\"Query PTR for 34.216.184.93.in-addr.arpa\" data-reverse-dns-query=\"34.216.184.93.in-addr.arpa\">93.184.216.34</a><span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"../rdap-explorer?query=93.184.216.34&amp;type=ip_v4_addr\" title=\"Query RDAP for 93.184.216.34\" aria-label=\"Query RDAP for 93.184.216.34\" target=\"_blank\" rel=\"noopener noreferrer\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span></td>"
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
                "Address</td><td class=\"wrap_value\"><a class=\"reverse_dns_link mono_text\" href=\"?name=0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa&amp;type=PTR\" title=\"Query PTR for 0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa\" aria-label=\"Query PTR for 0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa\" data-reverse-dns-query=\"0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa\">2606:2800:220:1:248:1893:25c6:1970</a><span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"../rdap-explorer?query=2606:2800:220:1:248:1893:25c6:1970&amp;type=ip_v6_addr\" title=\"Query RDAP for 2606:2800:220:1:248:1893:25c6:1970\" aria-label=\"Query RDAP for 2606:2800:220:1:248:1893:25c6:1970\" target=\"_blank\" rel=\"noopener noreferrer\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span></td>"
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
                "Address</td><td class=\"wrap_value\"><a class=\"reverse_dns_link mono_text\" href=\"?name=1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa&amp;type=PTR\" title=\"Query PTR for 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\" aria-label=\"Query PTR for 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\" data-reverse-dns-query=\"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa\">::1</a><span class=\"rdap_query_suffix\">(<a class=\"rdap_query_link\" href=\"../rdap-explorer?query=::1&amp;type=ip_v6_addr\" title=\"Query RDAP for ::1\" aria-label=\"Query RDAP for ::1\" target=\"_blank\" rel=\"noopener noreferrer\"><span class=\"rdap_query_glyph\" aria-hidden=\"true\">\u{2315}</span><span class=\"rdap_query_text\">RDAP</span></a>)</span></td>"
            ),
            "{html}"
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

        // THEN the MX fields are rendered as separate labeled rows.
        assert!(
            html.contains("Preference</td><td class=\"wrap_value\">10</td>"),
            "{html}"
        );
        assert!(
            html.contains("Exchange</td><td class=\"wrap_value\">mail.example.</td>"),
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
