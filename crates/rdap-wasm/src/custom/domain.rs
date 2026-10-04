use icann_rdap_common::prelude::Domain;

use super::common::{append_common, nameserver_list};
use super::html::{kv_table, lookup_with_scopes, mono, push_unicode, render, row, section, title};

/// The reverse-DNS base query code for a domain name, if it is one:
/// `rdns_ipv4` for `*.in-addr.arpa`, `rdns_ipv6` for `*.ip6.arpa`
/// (case-insensitive, tolerating a trailing root `.`). Appending
/// `_top`/`_up`/`_down`/`_bottom` yields the scoped reverse-delegation
/// variants.
fn rdns_base(name: &str) -> Option<&'static str> {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    if lower.ends_with("in-addr.arpa") {
        Some("rdns_ipv4")
    } else if lower.ends_with("ip6.arpa") {
        Some("rdns_ipv6")
    } else {
        None
    }
}

pub(crate) fn domain_html(domain: &Domain, authority: &str) -> String {
    let oc = &domain.object_common;
    let mut summary = Vec::new();
    if let Some(name) = domain.ldh_name.as_deref() {
        // Reverse-DNS domains get the ⌕ scope links so the reverse
        // delegation hierarchy can be walked up/down from the name.
        let value = match rdns_base(name) {
            Some(base) => {
                // A trailing root dot is display-only; the query value
                // uses the canonical untrailing-dot form.
                let query = name.trim_end_matches('.');
                lookup_with_scopes(query, base, &mono(name))
            }
            None => mono(name),
        };
        summary.push(row("Name", &value));
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
    append_common(&mut parts, authority, oc, &domain.common);
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
        let html = domain_html(&domain, "rdap.example");
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
    fn in_addr_arpa_domain_gets_rdns_ipv4_scope_links() {
        // GIVEN a reverse-DNS (IPv4) domain
        let json = r#"{
            "objectClassName": "domain",
            "handle": "2.0.192.in-addr.arpa",
            "ldhName": "2.0.192.in-addr.arpa"
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN the name carries the ⌕ group with rdns_ipv4 scope links
        assert!(html.contains("(\u{2315}"), "missing search glyph: {html}");
        for scope in ["top", "up", "down", "bottom"] {
            assert!(
                html.contains(&format!(
                    "query = '2.0.192.in-addr.arpa'; queryType = 'rdns_ipv4_{scope}'; lookup()"
                )),
                "missing {scope} scope link: {html}"
            );
        }
    }

    #[test]
    fn ip6_arpa_domain_gets_rdns_ipv6_scope_links() {
        // GIVEN a reverse-DNS (IPv6) domain
        let json = r#"{
            "objectClassName": "domain",
            "handle": "8.b.d.0.1.0.0.2.ip6.arpa",
            "ldhName": "8.b.d.0.1.0.0.2.ip6.arpa"
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN the name carries rdns_ipv6 scope links
        for scope in ["top", "up", "down", "bottom"] {
            assert!(
                html.contains(&format!(
                    "query = '8.b.d.0.1.0.0.2.ip6.arpa'; queryType = 'rdns_ipv6_{scope}'; lookup()"
                )),
                "missing {scope} scope link: {html}"
            );
        }
    }

    #[test]
    fn rdns_detection_is_case_insensitive() {
        // GIVEN an upper-case reverse-DNS name
        let json = r#"{
            "objectClassName": "domain",
            "handle": "X",
            "ldhName": "2.0.192.IN-ADDR.ARPA"
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN the scope links still use the rdns_ipv4 base
        assert!(html.contains("queryType = 'rdns_ipv4_top'"), "{html}");
    }

    #[test]
    fn trailing_dot_in_addr_arpa_is_detected_and_query_trimmed() {
        // GIVEN a reverse-DNS name with a trailing root period
        let json = r#"{
            "objectClassName": "domain",
            "handle": "1.192.in-addr.arpa",
            "ldhName": "1.192.in-addr.arpa."
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN scope links use the trimmed canonical query value
        for scope in ["top", "up", "down", "bottom"] {
            assert!(
                html.contains(&format!(
                    "query = '1.192.in-addr.arpa'; queryType = 'rdns_ipv4_{scope}'; lookup()"
                )),
                "missing {scope} scope link: {html}"
            );
        }
        // the trailing dot must not leak into any query value
        assert!(
            !html.contains("in-addr.arpa.'"),
            "trailing dot leaked into query: {html}"
        );
        // the display keeps the original name with the dot
        assert!(html.contains("1.192.in-addr.arpa."), "{html}");
    }

    #[test]
    fn trailing_dot_ip6_arpa_is_detected() {
        // GIVEN an IPv6 reverse name with a trailing root period
        let json = r#"{
            "objectClassName": "domain",
            "handle": "8.b.d.0.1.0.0.2.ip6.arpa",
            "ldhName": "8.b.d.0.1.0.0.2.ip6.arpa."
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN rdns_ipv6 scope links are present with the trimmed value
        assert!(
            html.contains(
                "query = '8.b.d.0.1.0.0.2.ip6.arpa'; queryType = 'rdns_ipv6_bottom'; lookup()"
            ),
            "{html}"
        );
        assert!(!html.contains("ip6.arpa.'"), "trailing dot leaked: {html}");
    }

    #[test]
    fn forward_domain_gets_no_rdns_scope_links() {
        // GIVEN an ordinary forward domain
        let json = r#"{
            "objectClassName": "domain",
            "handle": "EXAMPLE-COM",
            "ldhName": "example.com"
        }"#;
        let domain: Domain = serde_json::from_str(json).unwrap();

        // WHEN rendered
        let html = domain_html(&domain, "rdap.example");

        // THEN no reverse-DNS scope links are added
        assert!(!html.contains("rdns_"), "{html}");
        assert!(!html.contains("\u{2315}"), "{html}");
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
