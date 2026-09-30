use icann_rdap_common::prelude::Nameserver;

use super::common::append_common;
use super::html::{escape, kv_table, mono, push_unicode, render, row, title};

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
            let items = v4
                .vec()
                .iter()
                .map(|s| escape(&s.to_string()))
                .collect::<Vec<_>>();
            if !items.is_empty() {
                summary.push(row("IPv4", &mono(&items.join(", "))));
            }
        }
        if let Some(v6) = &ip.v6 {
            let items = v6
                .vec()
                .iter()
                .map(|s| escape(&s.to_string()))
                .collect::<Vec<_>>();
            if !items.is_empty() {
                summary.push(row("IPv6", &mono(&items.join(", "))));
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
}
