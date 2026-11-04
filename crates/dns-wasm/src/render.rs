//! HTML rendering of parsed DNS messages for the explorer's result panel.
//!
//! Reuses the shared `ui-components` design-system classes (`data_table`,
//! `data_key`, `data_title`, `mono_text`, `wrap_value`, `info_text`,
//! `warning_text`) so rendered fragments theme identically with the rest of
//! the site. All record text is HTML-escaped before interpolation: DNS data
//! (especially TXT records) is attacker-controlled.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::Record;

/// Renders a DNS response message as an HTML fragment: a status banner
/// followed by one table per non-empty section.
pub fn render_message(message: &Message) -> String {
    let mut html = status_banner(message);
    if message.answers.is_empty() {
        // Surface the empty-answer condition right after the status, before
        // the authority/additional sections that accompany a negative
        // response, and flag it as a warning.
        html.push_str("<p class=\"warning_text\">No answer records returned.</p>");
    } else {
        html.push_str(&record_table("Answers", &message.answers));
    }
    if !message.authorities.is_empty() {
        html.push_str(&record_table("Authority", &message.authorities));
    }
    if !message.additionals.is_empty() {
        html.push_str(&record_table("Additional", &message.additionals));
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

fn record_table(title: &str, records: &[Record]) -> String {
    // Each record renders as its own key/value block (one key per row);
    // consecutive records are separated by an accent divider.
    let blocks = records
        .iter()
        .map(record_block)
        .collect::<Vec<_>>()
        .join("<hr class=\"data_divider\">");
    format!("<h2 class=\"data_title\">{title}</h2><div class=\"data_section\">{blocks}</div>")
}

/// Renders one record as a key/value `data_table`: each field on its own
/// row with the field name in a `.data_key` cell.
fn record_block(record: &Record) -> String {
    format!(
        "<table class=\"data_table\"><tbody>\
         <tr><td class=\"data_key\">Name</td><td class=\"mono_text\">{}</td></tr>\
         <tr><td class=\"data_key\">TTL</td><td>{}</td></tr>\
         <tr><td class=\"data_key\">Class</td><td>{}</td></tr>\
         <tr><td class=\"data_key\">Type</td><td>{}</td></tr>\
         <tr><td class=\"data_key\">Data</td><td class=\"wrap_value\">{}</td></tr>\
         </tbody></table>",
        escape(&record.name.to_string()),
        record.ttl,
        record.dns_class,
        record.record_type(),
        escape(&record.data.to_string()),
    )
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
    use hickory_proto::rr::rdata::{A, TXT};
    use std::net::Ipv4Addr;

    fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(name.parse().expect("name"), ttl, RData::A(A::from(ip)))
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
        let html = render_message(&message);

        // THEN it carries the status banner and a record block with the data
        assert!(html.contains("Status"), "{html}");
        assert!(html.contains("No Error"), "{html}");
        assert!(html.contains("data_table"), "{html}");
        assert!(html.contains("93.184.216.34"), "{html}");
        assert!(html.contains(">300<"), "{html}");
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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

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
        let html = render_message(&message);

        // THEN the payload is shown but the DO flag is absent
        assert!(html.contains("1232 bytes"), "{html}");
        assert!(!html.contains("DNSSEC OK"), "{html}");
    }
}
