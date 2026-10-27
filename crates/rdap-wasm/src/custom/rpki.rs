//! Renderers for the RDAP RPKI extension object classes
//! (draft-ietf-regext-rdap-rpki): ROA, ASPA, and X.509 Resource Cert.
//!
//! Design notes:
//! - Each renderer mirrors the existing per-object pattern: a `data_title`
//!   heading, a `kv_table` summary of scalar fields, dedicated sections for
//!   the repeated structures (IP prefixes, provider ASes, digests), then the
//!   shared `append_common` tail (status, events, links, redacted, entities,
//!   notices, conformance).
//! - ASNs are rendered as `AS{n}` with an `as_number` lookup link and a copy
//!   button carrying the bare number (same policy as `autnum.rs`).
//! - IP prefixes/CIDRs pick their query-type base by address family so the
//!   scope links resolve (v6 when the value contains a colon).
//! - Every dynamic string is escaped; URIs go through the http-guarded
//!   `off_site_link`.

use icann_rdap_common::prelude::{
    Numberish, Rpk1Aspa, Rpk1Digest, Rpk1Roa, Rpk1RoaIp, Rpk1X509ResourceCert,
};

use super::common::append_common;
use super::html::{
    escape, kv_table, lookup_action, lookup_with_scopes, mono, off_site_link, render, row, section,
    str_opt, with_copy,
};

/// Renders an AS number as an `AS{n}` scoped-lookup link with a copy button
/// carrying the bare number. Falls back to plain mono text when the value is
/// not representable as a `u32`.
fn as_lookup_link(n: &Numberish<u32>) -> String {
    match n.as_u32() {
        Some(v) => {
            let bare = v.to_string();
            with_copy(
                lookup_with_scopes(&bare, "as_number", &mono(&format!("AS{v}"))),
                &bare,
            )
        }
        None => mono(&n.to_string()),
    }
}

/// Renders an IP address or CIDR prefix as a scoped-lookup link with a copy
/// button. The query-type base is chosen by address family (v6 when the value
/// contains a colon) and by whether it carries a `/` prefix length.
fn ip_lookup(s: &str) -> String {
    let base = match (s.contains(':'), s.contains('/')) {
        (true, true) => "ip_v6_cidr",
        (true, false) => "ip_v6_addr",
        (false, true) => "ip_v4_cidr",
        (false, false) => "ip_v4_addr",
    };
    with_copy(lookup_with_scopes(s, base, &mono(s)), s)
}

/// A two-column table of RPKI digests (algorithm / digest).
fn digests_table(digests: &[Rpk1Digest]) -> String {
    let rows: Vec<String> = digests
        .iter()
        .map(|d| {
            let algo = str_opt(d.digest_algorithm.as_ref());
            let val = d.digest.as_deref().map(mono).unwrap_or_default();
            format!("<tr><td>{algo}</td><td>{val}</td></tr>")
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<table class=\"data_table\"><thead><tr><th>Algorithm</th><th>Digest</th></tr></thead><tbody>{}</tbody></table>",
        rows.join("")
    )
}

/// A two-column table of ROA IP prefixes (prefix / max length).
fn roa_ips_table(ips: &[Rpk1RoaIp]) -> String {
    let rows: Vec<String> = ips
        .iter()
        .map(|rip| {
            let prefix = rip.ip.as_deref().map(ip_lookup).unwrap_or_default();
            let max = rip
                .max_length
                .as_ref()
                .map(|m| mono(&m.to_string()))
                .unwrap_or_default();
            format!("<tr><td>{prefix}</td><td>{max}</td></tr>")
        })
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "<table class=\"data_table\"><thead><tr><th>Prefix</th><th>Max Length</th></tr></thead><tbody>{}</tbody></table>",
        rows.join("")
    )
}

/// Pushes the validity window rows (only when the values are present).
fn push_validity(rows: &mut Vec<String>, before: Option<&str>, after: Option<&str>) {
    if let Some(b) = before {
        rows.push(row("Valid From", &mono(b)));
    }
    if let Some(a) = after {
        rows.push(row("Valid Until", &mono(a)));
    }
}

/// Pushes a URI row as an off-site link when it is http(s), else as mono
/// text. Either way the row carries a copy button for the raw URI.
fn push_uri(rows: &mut Vec<String>, label: &str, uri: Option<&str>) {
    let Some(u) = uri else { return };
    let link = off_site_link(u);
    if link.is_empty() {
        rows.push(row(label, &with_copy(mono(u), u)));
    } else {
        rows.push(row(label, &with_copy(link, u)));
    }
}

/// Renders a Route Origin Authorization (ROA) object.
pub(crate) fn roa_html(roa: &Rpk1Roa, authority: &str, anchor: &str) -> String {
    let oc = &roa.object_common;
    let label = roa.name.as_deref().or(oc.handle.as_deref());

    let mut summary = Vec::new();
    if let Some(n) = roa.name.as_deref() {
        summary.push(row("Name", &with_copy(escape(n), n)));
    }
    if let Some(h) = oc.handle.as_deref() {
        summary.push(row(
            "Handle",
            &with_copy(lookup_action(h, "rpki1_roa_handle", &mono(h)), h),
        ));
    }
    if let Some(t) = roa.rpki_type.as_ref() {
        summary.push(row("RPKI Type", &escape(t.as_ref())));
    }
    if let Some(asn) = roa.origin_autnum.as_ref() {
        summary.push(row("Origin AS", &as_lookup_link(asn)));
    }
    push_validity(
        &mut summary,
        roa.not_valid_before.as_deref(),
        roa.not_valid_after.as_deref(),
    );
    push_uri(
        &mut summary,
        "Publication URI",
        roa.publication_uri.as_deref(),
    );
    push_uri(
        &mut summary,
        "Notification URI",
        roa.notification_uri.as_deref(),
    );

    let mut parts = vec![title_class("RPKI ROA", label), kv_table(&summary)];
    if let Some(ips) = roa.roa_ips.as_ref() {
        parts.push(section("IP Prefixes", roa_ips_table(ips)));
    }
    if let Some(digests) = roa.digests.as_ref() {
        parts.push(section("Digests", digests_table(digests)));
    }
    append_common(&mut parts, authority, oc, &roa.common, anchor);
    render(parts, anchor)
}

/// Renders an Autonomous System Provider Authorization (ASPA) object.
pub(crate) fn aspa_html(aspa: &Rpk1Aspa, authority: &str, anchor: &str) -> String {
    let oc = &aspa.object_common;
    let label = aspa.name.as_deref().or(oc.handle.as_deref());

    let mut summary = Vec::new();
    if let Some(n) = aspa.name.as_deref() {
        summary.push(row("Name", &with_copy(escape(n), n)));
    }
    if let Some(h) = oc.handle.as_deref() {
        summary.push(row(
            "Handle",
            &with_copy(lookup_action(h, "rpki1_aspa_handle", &mono(h)), h),
        ));
    }
    if let Some(t) = aspa.rpki_type.as_ref() {
        summary.push(row("RPKI Type", &escape(t.as_ref())));
    }
    if let Some(c) = aspa.customer_autnum.as_ref() {
        summary.push(row("Customer AS", &as_lookup_link(c)));
    }
    push_validity(
        &mut summary,
        aspa.not_valid_before.as_deref(),
        aspa.not_valid_after.as_deref(),
    );
    push_uri(
        &mut summary,
        "Publication URI",
        aspa.publication_uri.as_deref(),
    );
    push_uri(
        &mut summary,
        "Notification URI",
        aspa.notification_uri.as_deref(),
    );

    let mut parts = vec![title_class("RPKI ASPA", label), kv_table(&summary)];
    if let Some(providers) = aspa.provider_autnums.as_ref() {
        let rows: Vec<String> = providers
            .iter()
            .map(|p| row("Provider AS", &as_lookup_link(p)))
            .collect();
        parts.push(section("Provider ASes", kv_table(&rows)));
    }
    if let Some(digests) = aspa.digests.as_ref() {
        parts.push(section("Digests", digests_table(digests)));
    }
    append_common(&mut parts, authority, oc, &aspa.common, anchor);
    render(parts, anchor)
}

/// Renders an X.509 Resource Certificate object.
pub(crate) fn x509_html(cert: &Rpk1X509ResourceCert, authority: &str, anchor: &str) -> String {
    let oc = &cert.object_common;
    let label = cert.subject.as_deref().or(oc.handle.as_deref());

    let mut summary = Vec::new();
    if let Some(h) = oc.handle.as_deref() {
        summary.push(row(
            "Handle",
            &with_copy(
                lookup_action(h, "rpki1_x509_resource_cert_handle", &mono(h)),
                h,
            ),
        ));
    }
    if let Some(s) = cert.serial_number.as_deref() {
        summary.push(row("Serial Number", &mono(s)));
    }
    if let Some(i) = cert.issuer.as_deref() {
        summary.push(row("Issuer", &escape(i)));
    }
    if let Some(s) = cert.subject.as_deref() {
        summary.push(row("Subject", &escape(s)));
    }
    if let Some(sa) = cert.signature_algorithm.as_deref() {
        summary.push(row("Signature Algorithm", &escape(sa)));
    }
    if let Some(pki) = cert.subject_public_key_info.as_ref() {
        if let Some(alg) = pki.public_key_algorithm.as_deref() {
            summary.push(row("Public Key Algorithm", &escape(alg)));
        }
        if let Some(pk) = pki.public_key.as_deref() {
            summary.push(row("Public Key", &mono(pk)));
        }
    }
    if let Some(ski) = cert.subject_key_identifier.as_deref() {
        summary.push(row("Subject Key Identifier", &mono(ski)));
    }
    if let Some(t) = cert.rpki_type.as_ref() {
        summary.push(row("RPKI Type", &escape(t.as_ref())));
    }
    push_validity(
        &mut summary,
        cert.not_valid_before.as_deref(),
        cert.not_valid_after.as_deref(),
    );
    push_uri(
        &mut summary,
        "Publication URI",
        cert.publication_uri.as_deref(),
    );
    push_uri(
        &mut summary,
        "Notification URI",
        cert.notification_uri.as_deref(),
    );

    let mut parts = vec![
        title_class("X.509 Resource Certificate", label),
        kv_table(&summary),
    ];
    if let Some(ips) = cert.ips.as_ref() {
        let rows: Vec<String> = ips.iter().map(|ip| row("IP", &ip_lookup(ip))).collect();
        parts.push(section("IPs", kv_table(&rows)));
    }
    if let Some(autnums) = cert.autnums.as_ref() {
        let rows: Vec<String> = autnums
            .iter()
            .map(|a| row("ASN", &as_lookup_link(a)))
            .collect();
        parts.push(section("Autonomous Systems", kv_table(&rows)));
    }
    if let Some(digests) = cert.digests.as_ref() {
        parts.push(section("Digests", digests_table(digests)));
    }
    append_common(&mut parts, authority, oc, &cert.common, anchor);
    render(parts, anchor)
}

/// A `data_title` heading with an optional mono name suffix.
fn title_class(heading: &str, name: Option<&str>) -> String {
    match name {
        Some(n) => format!(
            "<h2 class=\"data_title\">{} {}</h2>",
            escape(heading),
            mono(n)
        ),
        None => format!("<h2 class=\"data_title\">{}</h2>", escape(heading)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roa_fixture() -> Rpk1Roa {
        let json = r#"{
            "objectClassName": "rpki1_roa",
            "handle": "ROA-EXAMPLE-1",
            "name": "Example ROA",
            "rpkiType": "hosted",
            "originAutnum": 64496,
            "roaIps": [
                {"ip": "192.0.2.0/24", "maxLength": 24},
                {"ip": "2001:db8::/48", "maxLength": 64}
            ],
            "digests": [{"digest": "abc123def", "digestAlgorithm": "SHA-256"}],
            "notValidBefore": "2024-01-01T00:00:00Z",
            "notValidAfter": "2025-01-01T00:00:00Z",
            "publicationUri": "https://rpki.example/roa.mft",
            "status": ["valid"]
        }"#;
        serde_json::from_str(json).expect("roa fixture should deserialize")
    }

    #[test]
    fn roa_renders_summary_and_sections() {
        // GIVEN a ROA object
        let roa = roa_fixture();
        // WHEN rendered
        let html = roa_html(&roa, "rpki.example", "");
        // THEN the heading, scalar fields, and repeated sections all appear
        assert!(html.contains("RPKI ROA"), "{html}");
        assert!(html.contains("Example ROA"), "{html}");
        assert!(html.contains("Origin AS"), "{html}");
        assert!(html.contains("AS64496"), "{html}");
        assert!(html.contains("IP Prefixes"), "{html}");
        assert!(html.contains("192.0.2.0/24"), "{html}");
        assert!(html.contains("Digests"), "{html}");
        assert!(html.contains("SHA-256"), "{html}");
        assert!(html.contains("Valid From"), "{html}");
    }

    #[test]
    fn roa_origin_as_is_a_bare_number_lookup_link() {
        // GIVEN a ROA with an origin ASN
        let roa = roa_fixture();
        // WHEN rendered
        let html = roa_html(&roa, "rpki.example", "");
        // THEN the origin AS links as an as_number query with a bare-number copy
        assert!(
            html.contains("query = '64496'; queryType = 'as_number'; lookup()"),
            "{html}"
        );
        assert!(html.contains("copyToClipboard('64496')"), "{html}");
        assert!(
            !html.contains("query = 'AS"),
            "AS prefix must not leak into the query value: {html}"
        );
    }

    #[test]
    fn roa_prefixes_pick_query_base_by_address_family() {
        // GIVEN a ROA with a v4 and a v6 prefix
        let roa = roa_fixture();
        // WHEN rendered
        let html = roa_html(&roa, "rpki.example", "");
        // THEN each prefix uses the matching cidr query type
        assert!(
            html.contains("query = '192.0.2.0/24'; queryType = 'ip_v4_cidr'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '2001:db8::/48'; queryType = 'ip_v6_cidr'; lookup()"),
            "{html}"
        );
    }

    #[test]
    fn roa_handle_is_a_roa_handle_lookup_link() {
        // GIVEN a ROA with a handle
        let roa = roa_fixture();
        // WHEN rendered
        let html = roa_html(&roa, "rpki.example", "");
        // THEN the handle links as a rpki1_roa_handle query
        assert!(
            html.contains("query = 'ROA-EXAMPLE-1'; queryType = 'rpki1_roa_handle'; lookup()"),
            "{html}"
        );
    }

    #[test]
    fn roa_publication_uri_is_off_site_link() {
        // GIVEN a ROA with an https publication URI
        let roa = roa_fixture();
        // WHEN rendered
        let html = roa_html(&roa, "rpki.example", "");
        // THEN it renders as a new-tab off-site anchor
        assert!(
            html.contains(
                "<a class=\"off_site_link\" href=\"https://rpki.example/roa.mft\" target=\"_blank\""
            ),
            "{html}"
        );
    }

    #[test]
    fn roa_name_and_publication_uri_have_copy_buttons() {
        // GIVEN a ROA with a name and an https publication URI
        let roa = roa_fixture();
        // WHEN rendered
        let html = roa_html(&roa, "rpki.example", "");
        // THEN the name copies the name and the URI copies the raw URI
        assert!(html.contains("copyToClipboard('Example ROA')"), "{html}");
        assert!(
            html.contains("copyToClipboard('https://rpki.example/roa.mft')"),
            "{html}"
        );
    }

    #[test]
    fn roa_escapes_hostile_name() {
        // GIVEN a ROA whose name carries markup
        let json = r#"{
            "objectClassName": "rpki1_roa",
            "handle": "X",
            "name": "<script>alert(1)</script>"
        }"#;
        let roa: Rpk1Roa = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = roa_html(&roa, "rpki.example", "");
        // THEN the markup is escaped
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }

    #[test]
    fn aspa_renders_customer_and_provider_ases() {
        // GIVEN an ASPA with a customer and two providers
        let json = r#"{
            "objectClassName": "rpki1_aspa",
            "handle": "ASPA-1",
            "name": "Example ASPA",
            "customerAutnum": 64500,
            "providerAutnums": [64501, 64502],
            "digests": [{"digest": "deadbeef", "digestAlgorithm": "SHA-256"}]
        }"#;
        let aspa: Rpk1Aspa = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = aspa_html(&aspa, "rpki.example", "");
        // THEN customer and each provider render as AS lookup links
        assert!(html.contains("RPKI ASPA"), "{html}");
        assert!(html.contains("Customer AS"), "{html}");
        assert!(
            html.contains("query = '64500'; queryType = 'as_number'; lookup()"),
            "{html}"
        );
        assert!(html.contains("Provider ASes"), "{html}");
        assert!(
            html.contains("query = '64501'; queryType = 'as_number'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = '64502'; queryType = 'as_number'; lookup()"),
            "{html}"
        );
        assert!(
            html.contains("query = 'ASPA-1'; queryType = 'rpki1_aspa_handle'; lookup()"),
            "{html}"
        );
    }

    #[test]
    fn x509_renders_cert_fields() {
        // GIVEN an X.509 resource certificate
        let json = r#"{
            "objectClassName": "rpki1_x509ResourceCert",
            "handle": "CERT-1",
            "serialNumber": "0A1B",
            "issuer": "CN=CA",
            "subject": "CN=EE",
            "signatureAlgorithm": "ecdsa-with-SHA256",
            "subjectPublicKeyInfo": {"publicKeyAlgorithm": "EC", "publicKey": "MFkw..."},
            "subjectKeyIdentifier": "AB:CD:EF",
            "ips": ["192.0.2.0/24"],
            "autnums": [64500],
            "digests": [{"digest": "cafe", "digestAlgorithm": "SHA-256"}]
        }"#;
        let cert: Rpk1X509ResourceCert = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = x509_html(&cert, "rpki.example", "");
        // THEN the certificate fields and resource sections appear
        assert!(html.contains("X.509 Resource Certificate"), "{html}");
        assert!(html.contains("CN=EE"), "{html}");
        assert!(html.contains("0A1B"), "{html}");
        assert!(html.contains("Subject Key Identifier"), "{html}");
        assert!(html.contains("IPs"), "{html}");
        assert!(html.contains("Autonomous Systems"), "{html}");
        assert!(
            html.contains(
                "query = 'CERT-1'; queryType = 'rpki1_x509_resource_cert_handle'; lookup()"
            ),
            "{html}"
        );
    }

    #[test]
    fn x509_bare_ip_uses_addr_query_base() {
        // GIVEN a cert listing a bare (non-CIDR) IPv4 address
        let json = r#"{
            "objectClassName": "rpki1_x509ResourceCert",
            "handle": "CERT-2",
            "ips": ["192.0.2.1"]
        }"#;
        let cert: Rpk1X509ResourceCert = serde_json::from_str(json).unwrap();
        // WHEN rendered
        let html = x509_html(&cert, "rpki.example", "");
        // THEN the address uses the addr (not cidr) query base
        assert!(
            html.contains("query = '192.0.2.1'; queryType = 'ip_v4_addr'; lookup()"),
            "{html}"
        );
    }
}
