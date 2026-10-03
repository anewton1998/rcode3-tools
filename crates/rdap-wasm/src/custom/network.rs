use icann_rdap_common::prelude::Network;

use super::common::append_common;
use super::html::{escape, kv_table, lookup_action, mono, render, row, title};

/// Picks the address lookup query type from the address string.
fn addr_query_type(s: &str) -> &'static str {
    if s.contains(':') {
        "ip_v6_addr"
    } else {
        "ip_v4_addr"
    }
}

pub(crate) fn network_html(net: &Network, authority: &str) -> String {
    let oc = &net.object_common;
    let label = net.name.as_deref().or(net.start_address.as_deref());
    let mut summary = Vec::new();
    if let Some(s) = net.start_address.as_deref() {
        summary.push(row(
            "Start Address",
            &lookup_action(s, addr_query_type(s), &mono(s)),
        ));
    }
    if let Some(e) = net.end_address.as_deref() {
        summary.push(row(
            "End Address",
            &lookup_action(e, addr_query_type(e), &mono(e)),
        ));
    }
    if let Some(cidrs) = &net.cidr0_cidrs {
        for cidr in cidrs {
            if let Some(prefix) = &cidr.prefix {
                let (prefix_str, query_type) = match prefix {
                    icann_rdap_common::prelude::Cidr0CidrPrefix::V4Prefix(v) => {
                        (v.to_string(), "ip_v4_cidr")
                    }
                    icann_rdap_common::prelude::Cidr0CidrPrefix::V6Prefix(v) => {
                        (v.to_string(), "ip_v6_cidr")
                    }
                };
                if let Some(length) = &cidr.length {
                    let cidr_str = format!("{prefix_str}/{length}");
                    summary.push(row(
                        "CIDR",
                        &lookup_action(&cidr_str, query_type, &mono(&cidr_str)),
                    ));
                } else {
                    summary.push(row(
                        "CIDR",
                        &lookup_action(&prefix_str, query_type, &mono(&prefix_str)),
                    ));
                }
            }
        }
    }
    if let Some(v) = net.ip_version.as_deref() {
        summary.push(row("IP Version", &escape(v)));
    }
    if let Some(t) = net.network_type.as_deref() {
        summary.push(row("Type", &escape(t)));
    }
    if let Some(p) = net.parent_handle.as_deref() {
        summary.push(row("Parent Handle", &mono(p)));
    }
    if let Some(h) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(h)));
    }

    let mut parts = vec![title("Network", label), kv_table(&summary)];
    append_common(&mut parts, authority, oc, &net.common);
    render(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_renders_addresses() {
        let json = r#"{
            "objectClassName": "network",
            "handle": "NET-1",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "4",
            "name": "TEST-NET-1",
            "type": "allocation"
        }"#;
        let net: Network = serde_json::from_str(json).unwrap();
        let html = network_html(&net, "rdap.example");
        assert!(html.contains("Start Address"), "{html}");
        assert!(html.contains("192.0.2.0"), "{html}");
        assert!(html.contains("TEST-NET-1"), "{html}");
    }

    #[test]
    fn network_addresses_and_cidrs_are_lookup_links() {
        let json = r#"{
            "objectClassName": "network",
            "handle": "NET-1",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "4",
            "cidr0_cidrs": [
                {"v4prefix": "192.0.2.0", "length": 24},
                {"v6prefix": "2001:db8::", "length": 32}
            ]
        }"#;
        let net: Network = serde_json::from_str(json).unwrap();
        let html = network_html(&net, "rdap.example");
        assert!(
            html.contains("query = '192.0.2.0'; queryType = 'ip_v4_addr'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '192.0.2.255'; queryType = 'ip_v4_addr'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '192.0.2.0/24'; queryType = 'ip_v4_cidr'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '2001:db8::/32'; queryType = 'ip_v6_cidr'; lookup()"),
            "{html}"
        );
    }
}
