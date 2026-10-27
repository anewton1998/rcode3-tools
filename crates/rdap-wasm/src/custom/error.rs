use icann_rdap_client::RdapClientError;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::prelude::{RdapResponse, Rfc9083Error};

use super::common::append_level0_common;
use super::html::{escape, kv_table, render, row, section, title};

/// Human-readable message for an HTTP-level RDAP error response.
pub fn http_error_message(data: &ResponseData) -> String {
    let code = data.http_data.status_code;
    if let RdapResponse::ErrorResponse(err) = &data.rdap {
        rdap_error_text(code, err.title.as_ref().map(|t| t.to_string()))
    } else {
        format!("HTTP {code}")
    }
}

/// Renders the results-panel body for an RFC 9083 error response.
///
/// The error code is shown in the heading; any `title`, `description`,
/// notices, and conformance claims the server provided are rendered below it.
/// The error code is always present (it is required by RFC 9083), so the
/// panel always has something to show.
pub(crate) fn error_response_html(err: &Rfc9083Error, authority: &str) -> String {
    let code = err.error_code();
    let mut summary = Vec::new();
    if let Some(t) = err.title() {
        summary.push(row(
            "Title",
            &format!("<span class=\"error_text\">{}</span>", escape(t)),
        ));
    }

    let mut parts = vec![
        title("RDAP Error", Some(&code.to_string())),
        kv_table(&summary),
    ];

    let description = err.description();
    if !description.is_empty() {
        let items = description
            .iter()
            .map(|d| format!("<li class=\"warning_text\">{}</li>", escape(d)))
            .collect::<Vec<_>>()
            .join("");
        parts.push(section(
            "Description",
            format!("<ul class=\"data_list\">{items}</ul>"),
        ));
    }

    append_level0_common(&mut parts, authority, &err.common);
    render(parts)
}

/// Renders the results-panel message shown when a non-200 response carried no
/// parseable RDAP error body (the "no information was returned" case).
pub(crate) fn no_information_html(status_code: u16) -> String {
    format!("<p class=\"info_text\">No information was returned (HTTP {status_code}).</p>")
}

/// Human-readable message for a client lookup error.
pub fn describe_error(e: &RdapClientError) -> String {
    if let RdapClientError::ParsingError(info) = e {
        format!(
            "HTTP {} - no valid RDAP response",
            info.http_data.status_code
        )
    } else {
        e.to_string()
    }
}

fn rdap_error_text(status_code: u16, title: Option<String>) -> String {
    match title {
        Some(t) => format!("RDAP error {}: {}", status_code, t),
        None => format!("RDAP error {}", status_code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdap_error_text_includes_status_code() {
        assert_eq!(rdap_error_text(404, None), "RDAP error 404");
        assert_eq!(
            rdap_error_text(404, Some("Not Found".to_string())),
            "RDAP error 404: Not Found"
        );
    }

    #[test]
    fn error_response_html_renders_code_title_and_description() {
        // GIVEN an RFC 9083 error with a title and a multi-line description
        let json = r#"{
            "errorCode": 404,
            "title": "Not Found",
            "description": ["Domain not found", "Try a different query"]
        }"#;
        let err: Rfc9083Error = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = error_response_html(&err, "rdap.example");
        // THEN the heading carries the code, and the title/description render
        assert!(html.contains("RDAP Error"), "{html}");
        assert!(html.contains("404"), "{html}");
        assert!(
            html.contains("<span class=\"error_text\">Not Found</span>"),
            "title should use the error_text class: {html}"
        );
        assert!(html.contains("Description"), "{html}");
        assert!(
            html.contains("<li class=\"warning_text\">Domain not found</li>"),
            "{html}"
        );
        assert!(
            html.contains("<li class=\"warning_text\">Try a different query</li>"),
            "{html}"
        );
    }

    #[test]
    fn error_response_html_renders_notices_and_conformance() {
        // GIVEN an error carrying level-0 notices and conformance claims
        let json = r#"{
            "errorCode": 429,
            "rdapConformance": ["rdap_level_0"],
            "notices": [{"title": "Rate Limited", "description": ["Slow down"]}]
        }"#;
        let err: Rfc9083Error = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = error_response_html(&err, "rdap.example");
        // THEN the notices and conformance sections appear
        assert!(html.contains("Service Notices"), "{html}");
        assert!(html.contains("Rate Limited"), "{html}");
        assert!(html.contains("rdap_level_0"), "{html}");
    }

    #[test]
    fn error_response_html_escapes_hostile_fields() {
        // GIVEN an error whose title and description carry markup
        let json = r#"{
            "errorCode": 400,
            "title": "<script>alert(1)</script>",
            "description": ["<img src=x>"]
        }"#;
        let err: Rfc9083Error = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = error_response_html(&err, "rdap.example");
        // THEN the markup is escaped
        assert!(!html.contains("<script>"), "{html}");
        assert!(!html.contains("<img"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }

    #[test]
    fn error_response_html_without_optional_fields_still_shows_code() {
        // GIVEN a bare error with only the required code
        let json = r#"{ "errorCode": 500 }"#;
        let err: Rfc9083Error = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = error_response_html(&err, "rdap.example");
        // THEN the heading still shows the code and no empty sections appear
        assert!(html.contains("RDAP Error"), "{html}");
        assert!(html.contains("500"), "{html}");
        assert!(!html.contains("Description"), "{html}");
    }

    #[test]
    fn no_information_html_includes_status() {
        // WHEN rendered for a 404
        let html = no_information_html(404);
        // THEN it states no information was returned with the status
        assert!(
            html.contains("No information was returned (HTTP 404)."),
            "{html}"
        );
        assert!(html.contains("info_text"), "{html}");
    }
}
