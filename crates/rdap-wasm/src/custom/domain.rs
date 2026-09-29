use icann_rdap_common::prelude::Domain;

use super::common::{append_common, nameserver_list};
use super::html::{kv_table, mono, push_unicode, render, row, section, title};

pub(crate) fn domain_html(domain: &Domain) -> String {
    let oc = &domain.object_common;
    let mut summary = Vec::new();
    if let Some(name) = domain.ldh_name.as_deref() {
        summary.push(row("Name", &mono(name)));
    }
    push_unicode(
        &mut summary,
        domain.unicode_name.as_deref(),
        domain.ldh_name.as_deref(),
    );
    if let Some(handle) = oc.handle.as_deref() {
        summary.push(row("Handle", &mono(handle)));
    }

    let mut parts = vec![
        title("Domain", domain.ldh_name.as_deref()),
        kv_table(&summary),
    ];
    if let Some(nameservers) = &domain.nameservers {
        parts.push(section("Nameservers", nameserver_list(nameservers)));
    }
    append_common(&mut parts, oc);
    render(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_renders_summary_and_sections() {
        let json = r#"{
            "objectClassName": "domain",
            "handle": "EXAMPLE-COM",
            "ldhName": "example.com",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
            "nameservers": [{"objectClassName": "nameserver", "ldhName": "ns1.example.com"}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain);
        assert!(html.contains("rdap_type_title"), "{html}");
        assert!(html.contains("<th scope=\"row\">Name</th>"), "{html}");
        assert!(html.contains("example.com"), "{html}");
        assert!(html.contains(">Status<"), "{html}");
        assert!(html.contains("Nameservers"), "{html}");
    }
}
