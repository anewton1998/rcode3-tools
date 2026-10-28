use icann_rdap_common::prelude::Help;

use super::common::{append_level0_common, notices_list};
use super::html::{render, title};

/// Renders the results-panel body for an RFC 9083 server help response.
///
/// Per RFC 9083, the help content *is* the response's notices (plus the
/// `rdapConformance` claims), so this renders the level-0 common sections
/// (Service Notices + Conformance Claims) under a "Server Help" heading.
/// When nothing renderable came back (no notices, or only notices with no
/// content at all) an explicit note is shown so the panel is never blank.
pub(crate) fn help_html(help: &Help, authority: &str, anchor: &str) -> String {
    let mut parts = vec![title("Server Help", None)];
    // Key the note off the *rendered* notices, not the raw vec: a notice
    // with no title, type, or description renders nothing, so an empty
    // render is the real "nothing to show" signal.
    let rendered_notices = help
        .common
        .notices
        .as_ref()
        .map(|notices| notices_list(notices))
        .unwrap_or_default();
    if rendered_notices.is_empty() {
        parts.push("<p class=\"info_text\">The server returned no help notices.</p>".to_string());
    }
    append_level0_common(&mut parts, authority, &help.common);
    render(parts, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use icann_rdap_common::prelude::RdapResponse;

    fn parse(json: &str) -> Help {
        match serde_json::from_str::<RdapResponse>(json).unwrap() {
            RdapResponse::Help(h) => *h,
            other => panic!("expected a Help response, got {other:?}"),
        }
    }

    #[test]
    fn help_renders_notices_and_conformance() {
        // GIVEN an RFC 9083 help response with notices and conformance claims
        let help = parse(
            r#"{
                "rdapConformance": ["rdap_level_0", "help"],
                "notices": [
                    {
                        "title": "Terms of Use",
                        "description": ["Data is provided as-is.", "See the full terms."]
                    }
                ]
            }"#,
        );

        // WHEN the help body is rendered
        let html = help_html(&help, "rdap.example", "");

        // THEN the heading, notice title, every description line, and the
        // conformance claims are all present.
        assert!(html.contains("Server Help"), "{html}");
        assert!(html.contains("Service Notices"), "{html}");
        assert!(html.contains("Terms of Use"), "{html}");
        assert!(html.contains("Data is provided as-is."), "{html}");
        assert!(html.contains("See the full terms."), "{html}");
        assert!(html.contains("rdap_level_0"), "{html}");
        assert!(html.contains("Conformance Claims"), "{html}");
    }

    #[test]
    fn help_with_no_notices_shows_note() {
        // GIVEN a help response with no notices (the parser only detects
        // help via a `notices` array, so build the struct directly)
        let help = Help::response().build();

        // WHEN rendered
        let html = help_html(&help, "rdap.example", "");

        // THEN an explicit "no notices" note is shown alongside conformance.
        assert!(html.contains("no help notices"), "{html}");
        assert!(html.contains("rdap_level_0"), "{html}");
    }

    #[test]
    fn help_with_empty_notices_array_shows_note() {
        // GIVEN a wire help response whose notices array is empty (the
        // parser detects help from the array's presence, not its contents)
        let help = parse(r#"{ "notices": [], "rdapConformance": ["rdap_level_0"] }"#);

        // WHEN rendered
        let html = help_html(&help, "rdap.example", "");

        // THEN the "no notices" note still shows — the panel is not blank.
        assert!(html.contains("no help notices"), "{html}");
        assert!(html.contains("rdap_level_0"), "{html}");
    }

    #[test]
    fn help_with_contentless_notices_shows_note() {
        // GIVEN a help response whose only notice has no title, type, or
        // description (renders to nothing)
        let help = parse(r#"{ "notices": [{}], "rdapConformance": ["rdap_level_0"] }"#);

        // WHEN rendered
        let html = help_html(&help, "rdap.example", "");

        // THEN the note still shows, keyed off the rendered output.
        assert!(html.contains("no help notices"), "{html}");
    }

    #[test]
    fn help_escapes_notice_content() {
        // GIVEN a notice with HTML-significant characters
        let help = parse(
            r#"{
                "rdapConformance": ["rdap_level_0"],
                "notices": [{ "title": "A & B <script>", "description": ["<b>x</b>"] }]
            }"#,
        );

        // WHEN rendered
        let html = help_html(&help, "rdap.example", "");

        // THEN the content is escaped, not injected.
        assert!(html.contains("A &amp; B &lt;script&gt;"), "{html}");
        assert!(!html.contains("<script>"), "{html}");
    }
}
