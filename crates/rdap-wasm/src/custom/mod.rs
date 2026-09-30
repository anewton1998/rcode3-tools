mod autnum;
mod common;
mod domain;
mod entity;
mod error;
mod html;
mod nameserver;
mod network;

use icann_rdap_client::rdap::ResponseData;
use icann_rdap_client::RdapClientError;
use icann_rdap_common::prelude::RdapResponse;

pub use error::{describe_error, http_error_message};

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
    let authority = data.http_data.host();
    let mut parts = vec![render_response_banner(data)];
    match &data.rdap {
        RdapResponse::Domain(domain) => parts.push(domain::domain_html(domain, authority)),
        RdapResponse::Nameserver(nameserver) => {
            parts.push(nameserver::nameserver_html(nameserver, authority))
        }
        RdapResponse::Network(network) => parts.push(network::network_html(network, authority)),
        RdapResponse::Autnum(autnum) => parts.push(autnum::autnum_html(autnum, authority)),
        RdapResponse::Entity(entity) => parts.push(entity::entity_html(entity, authority)),
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
