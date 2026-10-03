//! Canonical query-type metadata and the code → [`QueryType`] mapper.
//!
//! This module is the single source of truth for the query-type dropdown:
//! the option list (codes, labels, grouping) is derived here from
//! [`QueryTypeVariant::VARIANTS`], and the wasm exports hand the selected
//! code back to [`query_type_from_code`] to build the concrete query.
//!
//! Codes are the snake_case of the variant's `Debug` name (e.g. `IpV4Cidr`
//! → `ip_v4_cidr`), plus the special `"auto"` code which preserves the
//! auto-detecting [`FromStr`] behavior.

use icann_rdap_client::rdap::{QueryType, QueryTypeVariant};
use icann_rdap_client::RdapClientError;
use serde::Serialize;
use strum::VariantArray;

/// A single selectable option in the query-type dropdown.
#[derive(Serialize)]
pub struct QueryTypeOption {
    pub code: String,
    pub label: String,
}

/// A labelled group of options (rendered as an `<optgroup>`).
#[derive(Serialize)]
pub struct QueryTypeGroup {
    pub label: String,
    pub options: Vec<QueryTypeOption>,
}

/// The curated set surfaced in the "Common" group.
const COMMON: &[QueryTypeVariant] = &[
    QueryTypeVariant::Domain,
    QueryTypeVariant::IpV4Addr,
    QueryTypeVariant::IpV6Addr,
    QueryTypeVariant::IpV4Cidr,
    QueryTypeVariant::IpV6Cidr,
    QueryTypeVariant::AsNumber,
    QueryTypeVariant::Nameserver,
    QueryTypeVariant::Entity,
    QueryTypeVariant::RdnsIpv4,
    QueryTypeVariant::RdnsIpv6,
    QueryTypeVariant::Help,
    QueryTypeVariant::Url,
];

/// RPKI digest lookups need two inputs (algorithm + hex digest) and cannot be
/// expressed in the single query box, so they are excluded from the dropdown.
fn is_digest(v: &QueryTypeVariant) -> bool {
    matches!(
        v,
        QueryTypeVariant::Rpki1RoaDigest
            | QueryTypeVariant::Rpki1AspaDigest
            | QueryTypeVariant::Rpki1X509ResourceCertDigest
    )
}

/// Stable snake_case code for a variant, derived from its `Debug` name.
pub fn code_of(v: &QueryTypeVariant) -> String {
    let name = format!("{v:?}");
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() && i > 0 {
            let prev = chars[i - 1];
            if prev.is_lowercase() || prev.is_ascii_digit() {
                out.push('_');
            }
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// Human-readable label auto-generated from a snake_case code.
fn humanize(code: &str) -> String {
    code.split('_')
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Hand-picked labels for the curated "Common" group.
fn common_label(code: &str) -> Option<&'static str> {
    Some(match code {
        "domain" => "Domain",
        "ip_v4_addr" => "IPv4 address",
        "ip_v6_addr" => "IPv6 address",
        "ip_v4_cidr" => "IPv4 CIDR",
        "ip_v6_cidr" => "IPv6 CIDR",
        "as_number" => "Autonomous system (ASN)",
        "nameserver" => "Nameserver",
        "entity" => "Entity handle",
        "rdns_ipv4" => "Reverse DNS (IPv4)",
        "rdns_ipv6" => "Reverse DNS (IPv6)",
        "help" => "Server help",
        "url" => "Explicit URL",
        _ => return None,
    })
}

/// Builds the grouped option list: "Common" (curated, auto-detect first)
/// followed by "All query types" (every non-digest variant not already in
/// Common). No code appears in both groups.
pub fn query_type_groups() -> Vec<QueryTypeGroup> {
    let mut common_options = vec![QueryTypeOption {
        code: "auto".to_string(),
        label: "Auto-detect".to_string(),
    }];
    let mut common_codes: Vec<String> = Vec::with_capacity(COMMON.len());
    for v in COMMON {
        let code = code_of(v);
        let label = common_label(&code)
            .map(str::to_string)
            .unwrap_or_else(|| humanize(&code));
        common_codes.push(code.clone());
        common_options.push(QueryTypeOption { code, label });
    }

    let all_options: Vec<QueryTypeOption> = QueryTypeVariant::VARIANTS
        .iter()
        .filter(|v| !is_digest(v) && !common_codes.contains(&code_of(v)))
        .map(|v| {
            let code = code_of(v);
            let label = humanize(&code);
            QueryTypeOption { code, label }
        })
        .collect();

    vec![
        QueryTypeGroup {
            label: "Common".to_string(),
            options: common_options,
        },
        QueryTypeGroup {
            label: "All query types".to_string(),
            options: all_options,
        },
    ]
}

/// Builds a concrete [`QueryType`] from a dropdown `code` and the raw `value`.
///
/// `"auto"` (or empty) defers to the auto-detecting [`FromStr`] parser;
/// otherwise the code is resolved to a [`QueryTypeVariant`] and constructed.
pub fn query_type_from_code(code: &str, value: &str) -> Result<QueryType, RdapClientError> {
    if code.is_empty() || code == "auto" {
        return value.parse::<QueryType>();
    }
    let variant = QueryTypeVariant::VARIANTS
        .iter()
        .copied()
        .find(|v| code_of(v) == code)
        .ok_or(RdapClientError::AmbiguousQueryType)?;
    build(variant, value)
}

/// Constructs the [`QueryType`] for a given variant from a single text value.
fn build(v: QueryTypeVariant, value: &str) -> Result<QueryType, RdapClientError> {
    use QueryTypeVariant as Q;
    match v {
        Q::IpV4Addr => QueryType::ipv4(value),
        Q::IpV6Addr => QueryType::ipv6(value),
        Q::IpV4Cidr => QueryType::ipv4cidr(value),
        Q::IpV6Cidr => QueryType::ipv6cidr(value),
        Q::IpV4AddrUp => QueryType::ipv4_up(value),
        Q::IpV6AddrUp => QueryType::ipv6_up(value),
        Q::IpV4CidrUp => QueryType::ipv4cidr_up(value),
        Q::IpV6CidrUp => QueryType::ipv6cidr_up(value),
        Q::IpV4AddrDown => QueryType::ipv4_down(value),
        Q::IpV6AddrDown => QueryType::ipv6_down(value),
        Q::IpV4CidrDown => QueryType::ipv4cidr_down(value),
        Q::IpV6CidrDown => QueryType::ipv6cidr_down(value),
        Q::IpV4AddrTop => QueryType::ipv4_top(value),
        Q::IpV6AddrTop => QueryType::ipv6_top(value),
        Q::IpV4CidrTop => QueryType::ipv4cidr_top(value),
        Q::IpV6CidrTop => QueryType::ipv6cidr_top(value),
        Q::IpV4AddrBottom => QueryType::ipv4_bottom(value),
        Q::IpV6AddrBottom => QueryType::ipv6_bottom(value),
        Q::IpV4CidrBottom => QueryType::ipv4cidr_bottom(value),
        Q::IpV6CidrBottom => QueryType::ipv6cidr_bottom(value),
        Q::AsNumber => QueryType::autnum(value),
        Q::AsNumberUp => QueryType::autnum_up(value),
        Q::AsNumberDown => QueryType::autnum_down(value),
        Q::AsNumberTop => QueryType::autnum_top(value),
        Q::AsNumberBottom => QueryType::autnum_bottom(value),
        Q::Domain => QueryType::domain(value),
        Q::ALabel => QueryType::alabel(value),
        Q::RdnsIpv4 => QueryType::rdns_ipv4(value),
        Q::RdnsIpv6 => QueryType::rdns_ipv6(value),
        Q::RdnsIpv4Up => QueryType::rdns_ipv4_up(value),
        Q::RdnsIpv6Up => QueryType::rdns_ipv6_up(value),
        Q::RdnsIpv4Down => QueryType::rdns_ipv4_down(value),
        Q::RdnsIpv6Down => QueryType::rdns_ipv6_down(value),
        Q::RdnsIpv4Top => QueryType::rdns_ipv4_top(value),
        Q::RdnsIpv6Top => QueryType::rdns_ipv6_top(value),
        Q::RdnsIpv4Bottom => QueryType::rdns_ipv4_bottom(value),
        Q::RdnsIpv6Bottom => QueryType::rdns_ipv6_bottom(value),
        Q::Entity => Ok(QueryType::Entity(value.to_string())),
        Q::Nameserver => QueryType::ns(value),
        Q::EntityNameSearch => Ok(QueryType::EntityNameSearch(value.to_string())),
        Q::EntityHandleSearch => Ok(QueryType::EntityHandleSearch(value.to_string())),
        Q::NetworkHandleSearch => Ok(QueryType::NetworkHandleSearch(value.to_string())),
        Q::NetworkNameSearch => Ok(QueryType::NetworkNameSearch(value.to_string())),
        Q::DomainNameSearch => Ok(QueryType::DomainNameSearch(value.to_string())),
        Q::DomainNsNameSearch => Ok(QueryType::DomainNsNameSearch(value.to_string())),
        Q::DomainNsIpSearch => QueryType::domain_ns_ip_search(value),
        Q::NameserverNameSearch => Ok(QueryType::NameserverNameSearch(value.to_string())),
        Q::NameserverIpSearch => QueryType::ns_ip_search(value),
        Q::AutnumHandleSearch => Ok(QueryType::AutnumHandleSearch(value.to_string())),
        Q::AutnumNameSearch => Ok(QueryType::AutnumNameSearch(value.to_string())),
        Q::Rpki1RoaHandle => Ok(QueryType::rpki1_roa_handle(value)),
        Q::Rpki1RoaIp => QueryType::rpki1_roa_ip(value),
        Q::Rpki1RoaCidr => QueryType::rpki1_roa_cidr(value),
        Q::Rpki1RoaDigest => Err(RdapClientError::InvalidQueryValue),
        Q::Rpki1RoaNameSearch => Ok(QueryType::rpki1_roa_name_search(value)),
        Q::Rpki1RoaOriginAutnumSearch => QueryType::rpki1_roa_origin_autnum_search(value),
        Q::Rpki1AspaHandle => Ok(QueryType::rpki1_aspa_handle(value)),
        Q::Rpki1AspaAutnum => QueryType::rpki1_aspa_autnum(value),
        Q::Rpki1AspaDigest => Err(RdapClientError::InvalidQueryValue),
        Q::Rpki1AspaNameSearch => Ok(QueryType::rpki1_aspa_name_search(value)),
        Q::Rpki1AspaProviderAutnumSearch => QueryType::rpki1_aspa_provider_autnum_search(value),
        Q::Rpki1X509ResourceCertHandle => Ok(QueryType::rpki1_x509_handle(value)),
        Q::Rpki1X509ResourceCertDigest => Err(RdapClientError::InvalidQueryValue),
        Q::Rpki1X509ResourceCertIssuerSearch => Ok(QueryType::rpki1_x509_issuer_search(value)),
        Q::Rpki1X509ResourceCertSubjectSearch => Ok(QueryType::rpki1_x509_subject_search(value)),
        Q::Rpki1X509ResourceCertSkiSearch => Ok(QueryType::rpki1_x509_ski_search(value)),
        Q::Rpki1X509ResourceCertIpSearch => QueryType::rpki1_x509_ip_search(value),
        Q::Rpki1X509ResourceCertCidrSearch => QueryType::rpki1_x509_cidr_search(value),
        Q::Rpki1X509ResourceCertAutnumSearch => QueryType::rpki1_x509_autnum_search(value),
        Q::Help => Ok(QueryType::Help),
        Q::Url => Ok(QueryType::Url(value.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_of_snake_cases_variant_names() {
        assert_eq!(code_of(&QueryTypeVariant::IpV4Addr), "ip_v4_addr");
        assert_eq!(code_of(&QueryTypeVariant::IpV4Cidr), "ip_v4_cidr");
        assert_eq!(code_of(&QueryTypeVariant::AsNumberUp), "as_number_up");
        assert_eq!(code_of(&QueryTypeVariant::Domain), "domain");
        assert_eq!(code_of(&QueryTypeVariant::Help), "help");
        assert_eq!(code_of(&QueryTypeVariant::Url), "url");
        assert_eq!(
            code_of(&QueryTypeVariant::Rpki1X509ResourceCertHandle),
            "rpki1_x509_resource_cert_handle"
        );
    }

    #[test]
    fn auto_code_uses_parse() {
        let q = query_type_from_code("auto", "example.com").unwrap();
        assert!(matches!(q, QueryType::Domain(_)));
        let q = query_type_from_code("", "192.0.2.1").unwrap();
        assert!(matches!(q, QueryType::IpV4Addr(_)));
    }

    #[test]
    fn explicit_codes_build_expected_types() {
        assert!(matches!(
            query_type_from_code("domain", "example.com").unwrap(),
            QueryType::Domain(_)
        ));
        assert!(matches!(
            query_type_from_code("ip_v4_addr", "192.0.2.1").unwrap(),
            QueryType::IpV4Addr(_)
        ));
        assert!(matches!(
            query_type_from_code("ip_v6_cidr", "2001:db8::/32").unwrap(),
            QueryType::IpV6Cidr(_)
        ));
        assert!(matches!(
            query_type_from_code("as_number", "as16509").unwrap(),
            QueryType::AsNumber(16509)
        ));
        assert!(matches!(
            query_type_from_code("nameserver", "ns.example.com").unwrap(),
            QueryType::Nameserver(_)
        ));
        assert!(matches!(
            query_type_from_code("entity", "HANDLE-1").unwrap(),
            QueryType::Entity(_)
        ));
        assert!(matches!(
            query_type_from_code("rdns_ipv4", "2.0.0.192.in-addr.arpa").unwrap(),
            QueryType::RdnsIpv4(_)
        ));
        assert!(matches!(
            query_type_from_code("help", "").unwrap(),
            QueryType::Help
        ));
        assert!(matches!(
            query_type_from_code("url", "https://rdap.example.com/domain/x").unwrap(),
            QueryType::Url(_)
        ));
    }

    #[test]
    fn unknown_code_is_ambiguous() {
        assert!(matches!(
            query_type_from_code("no_such_type", "x"),
            Err(RdapClientError::AmbiguousQueryType)
        ));
    }

    #[test]
    fn digest_codes_are_rejected() {
        for code in [
            "rpki1_roa_digest",
            "rpki1_aspa_digest",
            "rpki1_x509_resource_cert_digest",
        ] {
            assert!(
                query_type_from_code(code, "SHA-256:abcd").is_err(),
                "digest code {code} should be rejected"
            );
        }
    }

    #[test]
    fn every_offered_option_maps_to_a_query_type() {
        // Sample value chosen by inspecting the code, so each variant can be built.
        fn sample(code: &str) -> String {
            if code.contains("rdns_ipv4") {
                return "2.0.0.192.in-addr.arpa".to_string();
            }
            if code.contains("rdns_ipv6") {
                return "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
                    .to_string();
            }
            if code.contains("cidr") {
                return if code.contains("v6") {
                    "2001:db8::/32".to_string()
                } else {
                    "192.0.2.0/24".to_string()
                };
            }
            if code.contains("ip_v4") {
                return "192.0.2.1".to_string();
            }
            if code.contains("ip_v6") {
                return "2001:db8::1".to_string();
            }
            if code.contains("ip_search") || code.ends_with("_ip") {
                return "192.0.2.1".to_string();
            }
            if code.contains("as_number") || code.contains("autnum") {
                return "as64512".to_string();
            }
            if code.contains("domain") || code.contains("nameserver") || code.contains("alabel") {
                return "example.com".to_string();
            }
            if code == "help" {
                return String::new();
            }
            if code == "url" {
                return "https://rdap.example.com/domain/example.com".to_string();
            }
            "test".to_string()
        }
        for group in query_type_groups() {
            for opt in group.options {
                if opt.code == "auto" {
                    continue;
                }
                let result = query_type_from_code(&opt.code, &sample(&opt.code));
                assert!(
                    result.is_ok(),
                    "offered code {} failed to build: {:?}",
                    opt.code,
                    result.err()
                );
            }
        }
    }

    #[test]
    fn groups_have_no_duplicate_codes_and_exclude_digests() {
        let groups = query_type_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, "Common");
        assert_eq!(groups[1].label, "All query types");

        let mut seen: Vec<String> = Vec::new();
        for group in &groups {
            for opt in &group.options {
                assert!(
                    !seen.contains(&opt.code),
                    "duplicate code across groups: {}",
                    opt.code
                );
                assert!(
                    !opt.code.contains("digest"),
                    "digest type should not be offered: {}",
                    opt.code
                );
                seen.push(opt.code.clone());
            }
        }
        // auto + 12 common + the rest
        assert_eq!(groups[0].options[0].code, "auto");
        assert_eq!(groups[0].options.len(), COMMON.len() + 1);
    }

    #[test]
    fn all_non_digest_variants_are_covered() {
        let groups = query_type_groups();
        let offered: Vec<String> = groups
            .iter()
            .flat_map(|g| g.options.iter().map(|o| o.code.clone()))
            .filter(|c| c != "auto")
            .collect();
        for v in QueryTypeVariant::VARIANTS {
            if is_digest(v) {
                continue;
            }
            let code = code_of(v);
            assert!(offered.contains(&code), "variant {code} not offered");
        }
    }
}
