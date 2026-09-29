use icann_rdap_common::prelude::Network;

use super::common::append_common;
use super::html::{escape, kv_table, mono, render, row, title};

pub(crate) fn network_html(net: &Network) -> String {
    let oc = &net.object_common;
    let label = net.name.as_deref().or(net.start_address.as_deref());
    let mut summary = Vec::new();
    if let Some(s) = net.start_address.as_deref() {
        summary.push(row("Start Address", &mono(s)));
    }
    if let Some(e) = net.end_address.as_deref() {
        summary.push(row("End Address", &mono(e)));
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
    append_common(&mut parts, oc);
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
        let html = network_html(&net);
        assert!(html.contains("Start Address"), "{html}");
        assert!(html.contains("192.0.2.0"), "{html}");
        assert!(html.contains("TEST-NET-1"), "{html}");
    }
}
