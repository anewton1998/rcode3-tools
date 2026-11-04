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
    if !message.answers.is_empty() {
        html.push_str(&record_table("Answers", &message.answers));
    }
    if !message.authorities.is_empty() {
        html.push_str(&record_table("Authority", &message.authorities));
    }
    if !message.additionals.is_empty() {
        html.push_str(&record_table("Additional", &message.additionals));
    }
    if message.answers.is_empty() {
        html.push_str("<p class=\"info_text\">No answer records returned.</p>");
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
    // The JSON download link is picked up by the explorer's delegated click
    // handler (`a[data-download-format]`), which pairs it with the JSON
    // payload returned alongside this HTML.
    format!(
        "<table class=\"data_table\"><tbody><tr><td class=\"data_key\">Status</td><td class=\"{class}\">{code}</td></tr><tr><td class=\"data_key\">Other Formats</td><td class=\"format_links\"><a href=\"#\" class=\"format_link\" data-download-format=\"json\" title=\"Download JSON\">JSON <span class=\"format_arrow\">\u{21E3}</span></a></td></tr></tbody></table>"
    )
}

fn record_table(title: &str, records: &[Record]) -> String {
    let rows: String = records.iter().map(record_row).collect();
    format!(
        "<h2 class=\"data_title\">{title}</h2>\
         <table class=\"data_table\"><thead><tr><th>Name</th><th>TTL</th><th>Class</th><th>Type</th><th>Data</th></tr></thead>\
         <tbody>{rows}</tbody></table>"
    )
}

fn record_row(record: &Record) -> String {
    format!(
        "<tr><td class=\"mono_text\">{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"wrap_value\">{}</td></tr>",
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

        // THEN it carries the status banner and a record table with the data
        assert!(html.contains("Status"), "{html}");
        assert!(html.contains("No Error"), "{html}");
        assert!(html.contains("data_table"), "{html}");
        assert!(html.contains("93.184.216.34"), "{html}");
        assert!(html.contains(">300<"), "{html}");
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
        // GIVEN a NOERROR response with no answers
        let mut message = Message::new(
            3,
            hickory_proto::op::MessageType::Response,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.response_code = ResponseCode::NoError;

        // WHEN rendered
        let html = render_message(&message);

        // THEN the "no answer" note is present
        assert!(html.contains("No answer records returned"), "{html}");
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
}
