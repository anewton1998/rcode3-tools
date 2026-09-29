mod autnum;
mod common;
mod domain;
mod entity;
mod error;
mod html;
mod nameserver;
mod network;

use icann_rdap_client::rdap::ResponseData;
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
