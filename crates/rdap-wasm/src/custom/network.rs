use icann_rdap_common::prelude::Network;

use super::common::append_common;
use super::html::{addr_with_scopes, escape, kv_table, mono, render, row, title};

/// Picks the address lookup query-type base code from the address string.
/// Appending `_top`/`_up`/`_down`/`_bottom` yields the scoped variants.
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
            &addr_with_scopes(s, addr_query_type(s)),
        ));
    }
    if let Some(e) = net.end_address.as_deref() {
        summary.push(row("End Address", &addr_with_scopes(e, addr_query_type(e))));
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
                let cidr_value = match &cidr.length {
                    Some(length) => format!("{prefix_str}/{length}"),
                    None => prefix_str,
                };
                summary.push(row("CIDR", &addr_with_scopes(&cidr_value, query_type)));
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

    #[test]
    fn addresses_are_followed_by_ip_label_and_scope_icons() {
        // GIVEN a network with a v4 start and a v6 end address
        let json = r#"{
            "objectClassName": "network",
            "handle": "NET-1",
            "startAddress": "192.0.2.0",
            "endAddress": "2001:db8::1"
        }"#;
        let net: Network = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = network_html(&net, "rdap.example");

        // THEN each address is followed by " SRCH " and the four scope icon links
        for scope in ["top", "up", "down", "bottom"] {
            assert!(
                html.contains(&format!(
                    "query = '192.0.2.0'; queryType = 'ip_v4_addr_{scope}'; lookup()"
                )),
                "missing v4 {scope} scope link: {html}"
            );
            assert!(
                html.contains(&format!(
                    "query = '2001:db8::1'; queryType = 'ip_v6_addr_{scope}'; lookup()"
                )),
                "missing v6 {scope} scope link: {html}"
            );
            assert!(
                html.contains(&format!("class=\"rdap-icon rdap-{scope}\"")),
                "missing {scope} icon: {html}"
            );
        }
        assert!(html.contains(" SRCH "), "missing SRCH label: {html}");
        // the " SRCH " separator must sit between the address link and the icons
        let link = html
            .find("query = '192.0.2.0'; queryType = 'ip_v4_addr';")
            .expect("address link: {html}");
        let sep = html.find(" SRCH ").expect("SRCH separator: {html}");
        let icon = html.find("rdap-icon rdap-top").expect("top icon: {html}");
        assert!(link < sep && sep < icon, "SRCH label misplaced: {html}");
    }

    #[test]
    fn cidr_without_length_still_gets_scope_icons() {
        // GIVEN a CIDR entry with no length
        let json = r#"{
            "objectClassName": "network",
            "handle": "NET-1",
            "cidr0_cidrs": [{"v4prefix": "192.0.2.0"}]
        }"#;
        let net: Network = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = network_html(&net, "rdap.example");

        // THEN the bare prefix gets the lookup link and cidr-scoped icons
        assert!(
            html.contains("query = '192.0.2.0'; queryType = 'ip_v4_cidr'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '192.0.2.0'; queryType = 'ip_v4_cidr_top'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '192.0.2.0'; queryType = 'ip_v4_cidr_bottom'; lookup()"),
            "{html}"
        );
    }

    #[test]
    fn cidrs_are_followed_by_ip_label_and_cidr_scoped_icons() {
        // GIVEN a network with v4 and v6 CIDR entries
        let json = r#"{
            "objectClassName": "network",
            "handle": "NET-1",
            "cidr0_cidrs": [
                {"v4prefix": "192.0.2.0", "length": 24},
                {"v6prefix": "2001:db8::", "length": 32}
            ]
        }"#;
        let net: Network = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = network_html(&net, "rdap.example");

        // THEN each CIDR is followed by " SRCH " and cidr-scoped icon links
        for scope in ["top", "up", "down", "bottom"] {
            assert!(
                html.contains(&format!(
                    "query = '192.0.2.0/24'; queryType = 'ip_v4_cidr_{scope}'; lookup()"
                )),
                "missing v4 cidr {scope} scope link: {html}"
            );
            assert!(
                html.contains(&format!(
                    "query = '2001:db8::/32'; queryType = 'ip_v6_cidr_{scope}'; lookup()"
                )),
                "missing v6 cidr {scope} scope link: {html}"
            );
        }
        assert!(html.contains(" SRCH "), "missing SRCH label: {html}");
    }
}
