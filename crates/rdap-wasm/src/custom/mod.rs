mod anchor;
mod autnum;
mod common;
mod domain;
mod entity;
mod error;
mod help;
mod html;
mod nameserver;
mod network;
mod rpki;
mod search;
mod tree;

use icann_rdap_client::RdapClientError;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::httpdata::HttpData;
use icann_rdap_common::prelude::RdapResponse;

pub(crate) use anchor::response_anchor;
pub(crate) use error::no_information_html;
pub use error::{describe_error, http_error_message};
pub(crate) use tree::{ReferralOutcome, build_tree, render_tree, tree_block};

/// Renders the host/received banner from raw HTTP data.
///
/// Split out from [`render_response_banner`] so the "no information" path
/// (which has only `HttpData` from a parsing error, not a full
/// `ResponseData`) can render the same banner.
pub(crate) fn banner_from_http(http: &HttpData) -> String {
    let host = http.host();
    let time_str = http.received().to_rfc3339();
    format!(
        "<table class=\"data_table\"><tbody><tr><td class=\"data_key\">Host</td><td class=\"mono_text\">{}</td></tr><tr><td class=\"data_key\">Received</td><td class=\"mono_text\">{}</td></tr></tbody></table>",
        html::escape(host),
        html::escape(&time_str)
    )
}

/// Renders the "Response" data table section.
pub fn render_response_banner(data: &ResponseData) -> String {
    banner_from_http(&data.http_data)
}

/// Renders the host/received banner with an extra "Other Formats" row of
/// download links beneath the received date.
///
/// The links are inert markup (`href="#"`) tagged with a
/// `data-download-format` marker. The actual download is wired in the
/// explorer template via event delegation, because the rpsl/json payloads
/// live in the page's Alpine state rather than in this rendered fragment
/// (Alpine does not process directives inside `x-html` content). Only the
/// *main* response banner uses this; followed referrals keep the plain
/// [`render_response_banner`] so the download row appears once.
pub(crate) fn banner_with_formats(http: &HttpData) -> String {
    let host = http.host();
    let time_str = http.received().to_rfc3339();
    format!(
        "<table class=\"data_table\"><tbody><tr><td class=\"data_key\">Host</td><td class=\"mono_text\">{}</td></tr><tr><td class=\"data_key\">Received</td><td class=\"mono_text\">{}</td></tr><tr><td class=\"data_key\">Other Formats</td><td class=\"format_links\"><a href=\"#\" class=\"format_link\" data-download-format=\"rpsl\" title=\"Download RPSL\">RPSL <span class=\"format_arrow\">\u{21E3}</span></a><span class=\"format_sep\"> &middot; </span><a href=\"#\" class=\"format_link\" data-download-format=\"json\" title=\"Download JSON\">JSON <span class=\"format_arrow\">\u{21E3}</span></a></td></tr></tbody></table>",
        html::escape(host),
        html::escape(&time_str)
    )
}

/// Renders the results-panel HTML for any supported RDAP response.
///
/// `anchor` is the in-page anchor id for this response's body (see
/// [`anchor`]); pass `""` to render without anchor ids (the non-tree path).
pub fn render_response_html(data: &ResponseData, anchor: &str) -> String {
    let mut parts = vec![render_response_banner(data)];
    parts.push(render_response_body(data, anchor));
    parts.join("")
}

/// Renders the object-class body *without* the leading host/received banner,
/// so callers can slot other content (e.g. the result tree) between the
/// banner and the body. `anchor` threads the in-page anchor id through the
/// object renderers so the result tree's links resolve.
pub(crate) fn render_response_body(data: &ResponseData, anchor: &str) -> String {
    let authority = data.http_data.host();
    let mut parts = Vec::new();
    match &data.rdap {
        RdapResponse::Domain(domain) => parts.push(domain::domain_html(domain, authority, anchor)),
        RdapResponse::Nameserver(nameserver) => {
            parts.push(nameserver::nameserver_html(nameserver, authority, anchor))
        }
        RdapResponse::Network(network) => {
            parts.push(network::network_html(network, authority, anchor))
        }
        RdapResponse::Autnum(autnum) => parts.push(autnum::autnum_html(autnum, authority, anchor)),
        RdapResponse::Entity(entity) => parts.push(entity::entity_html(entity, authority, anchor)),
        RdapResponse::Rpki1Roa(roa) => parts.push(rpki::roa_html(roa, authority, anchor)),
        RdapResponse::Rpki1Aspa(aspa) => parts.push(rpki::aspa_html(aspa, authority, anchor)),
        RdapResponse::Rpki1X509ResourceCert(cert) => {
            parts.push(rpki::x509_html(cert, authority, anchor))
        }
        RdapResponse::ErrorResponse(err) => {
            parts.push(error::error_response_html(err, authority, anchor))
        }
        RdapResponse::Help(help) => parts.push(help::help_html(help, authority, anchor)),
        RdapResponse::DomainSearchResults(s) => parts.push(search::search_results_html(
            "Domain Search Results",
            s.results(),
            authority,
            &s.common,
            anchor,
            domain::domain_html,
        )),
        RdapResponse::EntitySearchResults(s) => parts.push(search::search_results_html(
            "Entity Search Results",
            s.results(),
            authority,
            &s.common,
            anchor,
            entity::entity_html,
        )),
        RdapResponse::NameserverSearchResults(s) => parts.push(search::search_results_html(
            "Nameserver Search Results",
            s.results(),
            authority,
            &s.common,
            anchor,
            nameserver::nameserver_html,
        )),
        RdapResponse::IpSearchResults(s) => parts.push(search::search_results_html(
            "IP Network Search Results",
            s.results(),
            authority,
            &s.common,
            anchor,
            network::network_html,
        )),
        RdapResponse::AutnumSearchResults(s) => parts.push(search::search_results_html(
            "Autnum Search Results",
            s.results(),
            authority,
            &s.common,
            anchor,
            autnum::autnum_html,
        )),
        RdapResponse::Rpki1RoaSearchResults(s) => parts.push(search::search_results_html(
            "RPKI ROA Search Results",
            s.results(),
            authority,
            &s.common,
            anchor,
            rpki::roa_html,
        )),
        RdapResponse::Rpki1AspaSearchResults(s) => parts.push(search::search_results_html(
            "RPKI ASPA Search Results",
            s.results(),
            authority,
            &s.common,
            anchor,
            rpki::aspa_html,
        )),
        RdapResponse::Rpki1X509ResourceCertSearchResults(s) => {
            parts.push(search::search_results_html(
                "X.509 Resource Certificate Search Results",
                s.results(),
                authority,
                &s.common,
                anchor,
                rpki::x509_html,
            ))
        }
    }
    parts.join("")
}

/// Returns one level of "related" referral URLs for a domain response
/// (empty for any other object class).
pub fn referral_urls(data: &ResponseData) -> Vec<String> {
    match &data.rdap {
        RdapResponse::Domain(domain) => domain::related_link_urls(domain),
        _ => Vec::new(),
    }
}

/// A horizontal-rule divider inserted before each appended referral result.
pub fn referral_divider() -> String {
    "<hr class=\"data_divider\">".to_string()
}

/// A short inline note shown when a "related" referral fails to load.
pub fn referral_error_note(url: &str, e: &RdapClientError) -> String {
    format!(
        "<p class=\"error_text\">Related lookup failed for <span class=\"mono_text\">{}</span>: {}</p>",
        html::escape(url),
        html::escape(&describe_error(e))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use icann_rdap_common::httpdata::HttpData;

    fn error_response_data() -> ResponseData {
        let rdap: RdapResponse = serde_json::from_str(
            r#"{ "errorCode": 404, "title": "Not Found", "description": ["missing"] }"#,
        )
        .unwrap();
        let http_data = HttpData::builder()
            .host("rdap.example".to_string())
            .status_code(404)
            .received(chrono::Utc::now())
            .build();
        ResponseData {
            rdap,
            rdap_type: "ErrorResponse".to_string(),
            http_data,
        }
    }

    #[test]
    fn render_response_body_routes_error_to_error_renderer() {
        // GIVEN an RFC 9083 error response
        let data = error_response_data();
        // WHEN the object-class body is rendered
        let body = render_response_body(&data, "");
        // THEN it uses the dedicated error renderer, not the generic
        // `info_text` fallback that prints the rdap_type.
        assert!(body.contains("RDAP Error"), "{body}");
        assert!(body.contains("Not Found"), "{body}");
        assert!(
            !body.contains("ErrorResponse"),
            "should not fall back to the rdap_type text: {body}"
        );
    }

    #[test]
    fn banner_with_formats_adds_download_row() {
        // GIVEN raw http data for a received response
        let http = HttpData::builder()
            .host("rdap.example".to_string())
            .status_code(200)
            .received(chrono::Utc::now())
            .build();
        // WHEN the formats banner is rendered
        let html = banner_with_formats(&http);
        // THEN it keeps the Host/Received rows and adds an "Other Formats"
        // row carrying both download markers, uppercase labels, and the
        // ⤓ download symbol placed after each label.
        assert!(html.contains(">Host<"), "{html}");
        assert!(html.contains(">Received<"), "{html}");
        assert!(html.contains("Other Formats"), "{html}");
        assert!(html.contains("data-download-format=\"rpsl\""), "{html}");
        assert!(html.contains("data-download-format=\"json\""), "{html}");
        assert!(
            html.contains("RPSL <span class=\"format_arrow\">\u{21E3}</span>"),
            "{html}"
        );
        assert!(
            html.contains("JSON <span class=\"format_arrow\">\u{21E3}</span>"),
            "{html}"
        );
    }
}
