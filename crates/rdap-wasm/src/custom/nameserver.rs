use icann_rdap_common::prelude::Nameserver;

use super::common::append_common;
use super::html::{kv_table, lookup_action, mono, push_unicode, render, row, title};

pub(crate) fn nameserver_html(ns: &Nameserver, authority: &str) -> String {
    let oc = &ns.object_common;
    let mut summary = Vec::new();
    if let Some(name) = ns.ldh_name.as_deref() {
        summary.push(row("Name", &mono(name)));
    }
    push_unicode(
        &mut summary,
        ns.unicode_name.as_deref(),
        ns.ldh_name.as_deref(),
    );
    if let Some(ip) = &ns.ip_addresses {
        if let Some(v4) = &ip.v4 {
            for s in v4.vec() {
                let addr = s.to_string();
                summary.push(row(
                    "IPv4",
                    &lookup_action(&addr, "ip_v4_addr", &mono(&addr)),
                ));
            }
        }
        if let Some(v6) = &ip.v6 {
            for s in v6.vec() {
                let addr = s.to_string();
                summary.push(row(
                    "IPv6",
                    &lookup_action(&addr, "ip_v6_addr", &mono(&addr)),
                ));
            }
        }
    }
    if let Some(handle) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(handle)));
    }

    let mut parts = vec![
        title("Nameserver", ns.ldh_name.as_deref()),
        kv_table(&summary),
    ];
    append_common(&mut parts, authority, oc, &ns.common);
    render(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameserver_renders_ip_addresses() {
        let json = r#"{
            "objectClassName": "nameserver",
            "handle": "NS1-X",
            "ldhName": "ns1.example.com",
            "status": ["active"],
            "ipAddresses": {"v4": ["192.0.2.1"], "v6": ["2001:db8::1"]}
        }"#;
        let ns: Nameserver = serde_json::from_str(json).unwrap();
        let html = nameserver_html(&ns, "rdap.example");
        assert!(html.contains("IPv4"), "{html}");
        assert!(html.contains("192.0.2.1"), "{html}");
        assert!(html.contains("IPv6"), "{html}");
    }

    #[test]
    fn nameserver_ip_addresses_are_lookup_links() {
        let json = r#"{
            "objectClassName": "nameserver",
            "handle": "NS1-X",
            "ldhName": "ns1.example.com",
            "status": ["active"],
            "ipAddresses": {"v4": ["192.0.2.1"], "v6": ["2001:db8::1"]}
        }"#;
        let ns: Nameserver = serde_json::from_str(json).unwrap();
        let html = nameserver_html(&ns, "rdap.example");
        assert!(
            html.contains("query = '192.0.2.1'; queryType = 'ip_v4_addr'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '2001:db8::1'; queryType = 'ip_v6_addr'; lookup()"),
            "{html}"
        );
    }

    #[test]
    fn multiple_nameserver_ips_each_get_their_own_row() {
        let json = r#"{
            "objectClassName": "nameserver",
            "handle": "NS1-X",
            "ldhName": "ns1.example.com",
            "status": ["active"],
            "ipAddresses": {"v4": ["192.0.2.1", "192.0.2.2"], "v6": ["2001:db8::1", "2001:db8::2"]}
        }"#;
        let ns: Nameserver = serde_json::from_str(json).unwrap();
        let html = nameserver_html(&ns, "rdap.example");
        let v4_rows = html.matches("<td class=\"data_key\">IPv4</td>").count();
        let v6_rows = html.matches("<td class=\"data_key\">IPv6</td>").count();
        assert_eq!(v4_rows, 2, "expected one IPv4 row per address: {html}");
        assert_eq!(v6_rows, 2, "expected one IPv6 row per address: {html}");
        assert!(
            html.contains("query = '192.0.2.2'; queryType = 'ip_v4_addr'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '2001:db8::2'; queryType = 'ip_v6_addr'; lookup()"),
            "{html}"
        );
        // addresses must not be comma-joined into a single cell
        assert!(!html.contains("192.0.2.1, 192.0.2.2"), "{html}");
    }
}
