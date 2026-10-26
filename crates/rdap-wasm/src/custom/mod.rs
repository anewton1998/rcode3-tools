mod autnum;
mod common;
mod domain;
mod entity;
mod error;
mod html;
mod nameserver;
mod network;
mod rpki;
mod search;
mod tree;

use icann_rdap_client::RdapClientError;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::prelude::RdapResponse;

pub use error::{describe_error, http_error_message};
pub(crate) use tree::{ReferralOutcome, build_tree, render_tree, tree_block};

/// Renders the "Response" data table section.
pub fn render_response_banner(data: &ResponseData) -> String {
    let host = data.http_data.host();
    let time = data.http_data.received();
    let time_str = time.to_rfc3339();
    format!(
        "<table class=\"data_table\"><tbody><tr><td class=\"data_key\">Host</td><td class=\"mono_text\">{}</td></tr><tr><td class=\"data_key\">Received</td><td class=\"mono_text\">{}</td></tr></tbody></table>",
        html::escape(host),
        html::escape(&time_str)
    )
}

/// Renders the results-panel HTML for any supported RDAP response.
pub fn render_response_html(data: &ResponseData) -> String {
    let mut parts = vec![render_response_banner(data)];
    parts.push(render_response_body(data));
    parts.join("")
}

/// Renders the object-class body *without* the leading host/received banner,
/// so callers can slot other content (e.g. the result tree) between the
/// banner and the body.
pub(crate) fn render_response_body(data: &ResponseData) -> String {
    let authority = data.http_data.host();
    let mut parts = Vec::new();
    match &data.rdap {
        RdapResponse::Domain(domain) => parts.push(domain::domain_html(domain, authority)),
        RdapResponse::Nameserver(nameserver) => {
            parts.push(nameserver::nameserver_html(nameserver, authority))
        }
        RdapResponse::Network(network) => parts.push(network::network_html(network, authority)),
        RdapResponse::Autnum(autnum) => parts.push(autnum::autnum_html(autnum, authority)),
        RdapResponse::Entity(entity) => parts.push(entity::entity_html(entity, authority)),
        RdapResponse::Rpki1Roa(roa) => parts.push(rpki::roa_html(roa, authority)),
        RdapResponse::Rpki1Aspa(aspa) => parts.push(rpki::aspa_html(aspa, authority)),
        RdapResponse::Rpki1X509ResourceCert(cert) => parts.push(rpki::x509_html(cert, authority)),
        RdapResponse::DomainSearchResults(s) => parts.push(search::search_results_html(
            "Domain Search Results",
            s.results(),
            authority,
            &s.common,
            domain::domain_html,
        )),
        RdapResponse::EntitySearchResults(s) => parts.push(search::search_results_html(
            "Entity Search Results",
            s.results(),
            authority,
            &s.common,
            entity::entity_html,
        )),
        RdapResponse::NameserverSearchResults(s) => parts.push(search::search_results_html(
            "Nameserver Search Results",
            s.results(),
            authority,
            &s.common,
            nameserver::nameserver_html,
        )),
        RdapResponse::IpSearchResults(s) => parts.push(search::search_results_html(
            "IP Network Search Results",
            s.results(),
            authority,
            &s.common,
            network::network_html,
        )),
        RdapResponse::AutnumSearchResults(s) => parts.push(search::search_results_html(
            "Autnum Search Results",
            s.results(),
            authority,
            &s.common,
            autnum::autnum_html,
        )),
        RdapResponse::Rpki1RoaSearchResults(s) => parts.push(search::search_results_html(
            "RPKI ROA Search Results",
            s.results(),
            authority,
            &s.common,
            rpki::roa_html,
        )),
        RdapResponse::Rpki1AspaSearchResults(s) => parts.push(search::search_results_html(
            "RPKI ASPA Search Results",
            s.results(),
            authority,
            &s.common,
            rpki::aspa_html,
        )),
        RdapResponse::Rpki1X509ResourceCertSearchResults(s) => {
            parts.push(search::search_results_html(
                "X.509 Resource Certificate Search Results",
                s.results(),
                authority,
                &s.common,
                rpki::x509_html,
            ))
        }
        other => parts.push(format!(
            "<span class=\"info_text\">{}</span>",
            html::escape(&other.to_string())
        )),
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
