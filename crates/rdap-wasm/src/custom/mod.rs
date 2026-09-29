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

/// Renders the results-panel HTML for any supported RDAP response.
pub fn render_response_html(data: &ResponseData) -> String {
    match &data.rdap {
        RdapResponse::Domain(domain) => domain::domain_html(domain),
        RdapResponse::Nameserver(nameserver) => nameserver::nameserver_html(nameserver),
        RdapResponse::Network(network) => network::network_html(network),
        RdapResponse::Autnum(autnum) => autnum::autnum_html(autnum),
        RdapResponse::Entity(entity) => entity::entity_html(entity),
        other => format!(
            "<span class=\"info_text\">{}</span>",
            html::escape(&other.to_string())
        ),
    }
}

/// Returns one level of "related" referral URLs for a domain response
/// (empty for any other object class).
pub fn referral_urls(data: &ResponseData) -> Vec<String> {
    match &data.rdap {
        RdapResponse::Domain(domain) => domain::related_link_urls(domain),
        _ => Vec::new(),
    }
}

/// A short inline note shown when a "related" referral fails to load.
pub fn referral_error_note(url: &str, e: &RdapClientError) -> String {
    format!(
        "<p class=\"error_text\">Related lookup failed for <span class=\"mono_text\">{}</span>: {}</p>",
        html::escape(url),
        html::escape(&describe_error(e))
    )
}
