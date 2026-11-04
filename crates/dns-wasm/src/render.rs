//! HTML rendering of parsed DNS messages for the explorer's result panel.
//!
//! Reuses the shared `ui-components` design-system classes (`data_table`,
//! `data_key`, `data_title`, `mono_text`, `wrap_value`, `info_text`,
//! `warning_text`) so rendered fragments theme identically with the rest of
//! the site. All record text is HTML-escaped before interpolation: DNS data
//! (especially TXT records) is attacker-controlled.

use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::Record;

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
fn record_block(record: &Record, received: DateTime<Utc>) -> String {
    // `RecordType` converts to its `&'static str` mnemonic without allocating,
    // so the formal-name lookup needs no intermediate `String`.
    let type_code: &'static str = record.record_type().into();
    format!(
        "<table class=\"data_table\"><tbody>\
         <tr><td class=\"data_key\">Name</td><td class=\"mono_text\">{}</td></tr>\
         <tr><td class=\"data_key\">TTL</td><td>{}</td></tr>\
         <tr><td class=\"data_key\">Class</td><td>{}</td></tr>\
         <tr><td class=\"data_key\">Type</td><td>{}</td></tr>\
         <tr><td class=\"data_key\">Data</td><td class=\"wrap_value\">{}</td></tr>\
         </tbody></table>",
        escape(&record.name.to_string()),
        ttl_label(record.ttl, received),
        record.dns_class,
        record_type_label(type_code),
        mono_ip_data(&record.data.to_string()),
    )
}

/// True if `token` parses as an IPv4 or IPv6 address.
fn is_ip_address(token: &str) -> bool {
    token.parse::<Ipv4Addr>().is_ok() || token.parse::<Ipv6Addr>().is_ok()
}

/// Renders record data as HTML with every whitespace-delimited token that
/// parses as an IP address wrapped in a `.mono_text` span.
///
/// Whitespace runs are preserved verbatim and every segment (IP or not) is
/// HTML-escaped, since record data — TXT strings in particular — is
/// attacker-controlled. This makes A/AAAA values (a single IP token) render
/// fully monospace and also highlights standalone IPs embedded in other
/// record data. Tokens with an IP glued to punctuation (e.g. `1.2.3.4:80`)
/// are intentionally left as-is: only whole whitespace-delimited tokens are
/// tested against the address parsers.
fn mono_ip_data(data: &str) -> String {
    let mut out = String::with_capacity(data.len());
    let mut rest = data;
    while !rest.is_empty() {
        // Emit any leading whitespace run verbatim.
        let ws_end = rest
            .char_indices()
            .find(|(_, c)| !c.is_whitespace())
            .map_or(rest.len(), |(i, _)| i);
        if ws_end > 0 {
            out.push_str(&rest[..ws_end]);
            rest = &rest[ws_end..];
            continue;
        }
        // Take the next non-whitespace token and wrap it if it is an IP.
        let tok_end = rest
            .char_indices()
            .find(|(_, c)| c.is_whitespace())
            .map_or(rest.len(), |(i, _)| i);
        let token = &rest[..tok_end];
        if is_ip_address(token) {
            out.push_str("<span class=\"mono_text\">");
            out.push_str(&escape(token));
            out.push_str("</span>");
        } else {
            out.push_str(&escape(token));
        }
        rest = &rest[tok_end..];
    }
    out
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
    use hickory_proto::rr::rdata::{A, AAAA, TXT};
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
        for field in ["Name", "TTL", "Class", "Type", "Data"] {
            assert!(
                html.contains(&format!("<td class=\"data_key\">{field}</td>")),
                "missing {field} key row: {html}"
            );
        }
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
    fn a_record_data_renders_monospace() {
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

        // THEN the Data cell wraps the IP in a monospace span inside the
        // wrap_value cell.
        assert!(
            html.contains(
                "Data</td><td class=\"wrap_value\"><span class=\"mono_text\">93.184.216.34</span></td>"
            ),
            "{html}"
        );
    }

    #[test]
    fn aaaa_record_data_renders_monospace() {
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

        // THEN the IPv6 address is wrapped in a monospace span.
        assert!(
            html.contains("<span class=\"mono_text\">2606:2800:220:1:248:1893:25c6:1970</span>"),
            "{html}"
        );
    }

    #[test]
    fn txt_record_with_standalone_ip_renders_ip_monospace() {
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

        // THEN the embedded IP is wrapped in mono within the Data cell,
        // while the surrounding TXT text stays in the normal font.
        assert!(
            html.contains("<span class=\"mono_text\">198.51.100.3</span>"),
            "{html}"
        );
        assert!(html.contains("backup nameserver "), "{html}");
        assert!(html.contains(" available"), "{html}");
    }

    #[test]
    fn mono_ip_data_wraps_standalone_ip_in_text() {
        // GIVEN TXT-like data with a standalone IPv4 among words
        // WHEN rendered
        let html = mono_ip_data("edge router 203.0.113.7 up");
        // THEN only the IP token is wrapped; the words and spacing are kept.
        assert_eq!(
            html,
            "edge router <span class=\"mono_text\">203.0.113.7</span> up"
        );
    }

    #[test]
    fn mono_ip_data_leaves_non_ip_text_untouched() {
        // GIVEN data with no IP address
        // WHEN rendered
        let html = mono_ip_data("v=spf1 -all");
        // THEN no monospace span is added.
        assert_eq!(html, "v=spf1 -all");
        assert!(!html.contains("mono_text"), "{html}");
    }

    #[test]
    fn mono_ip_data_ignores_invalid_ip_like_tokens() {
        // GIVEN tokens that look IP-ish but do not parse as an address
        // WHEN rendered
        let html = mono_ip_data("1.2.3.4.5 999.1.1.1 1.2.3");
        // THEN none are wrapped.
        assert!(!html.contains("mono_text"), "{html}");
        assert_eq!(html, "1.2.3.4.5 999.1.1.1 1.2.3");
    }

    #[test]
    fn mono_ip_data_escapes_around_wrapped_ip() {
        // GIVEN hostile markup plus a standalone IP token
        // WHEN rendered
        let html = mono_ip_data("<b>host</b> 10.0.0.1");
        // THEN the markup is escaped while the IP is still wrapped in mono.
        assert!(html.contains("&lt;b&gt;"), "{html}");
        assert!(html.contains("&lt;/b&gt;"), "{html}");
        assert!(
            html.contains("<span class=\"mono_text\">10.0.0.1</span>"),
            "{html}"
        );
        assert!(!html.contains("<b>"), "{html}");
    }

    #[test]
    fn mono_ip_data_preserves_whitespace_runs() {
        // GIVEN data with multiple consecutive spaces around an IP
        // WHEN rendered
        let html = mono_ip_data("a  1.1.1.1   b");
        // THEN the whitespace runs are preserved verbatim around the wrapped IP.
        assert_eq!(html, "a  <span class=\"mono_text\">1.1.1.1</span>   b");
    }
}
