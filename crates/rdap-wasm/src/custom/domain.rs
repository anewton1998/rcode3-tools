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

/// Extracts de-duplicated "related" referral URLs from a domain's links,
/// preferring each link's href and falling back to its value.
pub(crate) fn related_link_urls(domain: &Domain) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    if let Some(links) = &domain.object_common.links {
        for link in links.iter() {
            if !link.is_relation("related") {
                continue;
            }
            let url = match (link.href.as_deref(), link.value.as_deref()) {
                (Some(href), _) if !href.is_empty() => href.to_string(),
                (_, Some(value)) if !value.is_empty() => value.to_string(),
                _ => continue,
            };
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }
    urls
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
            "status": ["clientHold", "active"],
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
            "nameservers": [{"objectClassName": "nameserver", "ldhName": "ns1.example.com"}]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let html = domain_html(&domain);
        assert!(html.contains("data_title"), "{html}");
        assert!(html.contains("<td class=\"data_key\">Name</td>"), "{html}");
        assert!(html.contains("example.com"), "{html}");
        assert!(html.contains(">Status<"), "{html}");
        assert!(html.contains("Nameservers"), "{html}");
        // Status values are rendered as a sorted bullet list.
        let active_pos = html
            .find("<li>active</li>")
            .expect("active status bullet: {html}");
        let hold_pos = html
            .find("<li>clientHold</li>")
            .expect("clientHold status bullet: {html}");
        assert!(active_pos < hold_pos, "status should be sorted: {html}");
    }

    #[test]
    fn domain_related_link_urls_are_extracted_and_deduped() {
        let json = r#"{
            "objectClassName": "domain",
            "handle": "EXAMPLE-COM",
            "ldhName": "example.com",
            "links": [
                {"rel": "self", "href": "https://rdap.example/domain/example.com"},
                {"rel": "related", "href": "https://rdap.example/entity/299"},
                {"rel": "related", "value": "https://rdap.example/entity/300"},
                {"rel": "related", "href": "https://rdap.example/entity/299"}
            ]
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();
        let urls = related_link_urls(&domain);
        assert_eq!(
            urls,
            vec![
                "https://rdap.example/entity/299".to_string(),
                "https://rdap.example/entity/300".to_string()
            ]
        );
    }
}
