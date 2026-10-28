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

use std::net::IpAddr;

use icann_rdap_client::RdapClientError;
use icann_rdap_client::rdap::{QueryType, QueryTypeVariant};
use icann_rdap_common::rdns::ip_to_reverse_dns;
use ipnet::IpNet;
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

/// The curated set surfaced in the "Lookups" group.
const LOOKUPS: &[QueryTypeVariant] = &[
    QueryTypeVariant::Domain,
    QueryTypeVariant::ALabel,
    QueryTypeVariant::IpV4Addr,
    QueryTypeVariant::IpV6Addr,
    QueryTypeVariant::IpV4Cidr,
    QueryTypeVariant::IpV6Cidr,
    QueryTypeVariant::AsNumber,
    QueryTypeVariant::Nameserver,
    QueryTypeVariant::Entity,
    QueryTypeVariant::RdnsIpv4,
    QueryTypeVariant::RdnsIpv6,
    QueryTypeVariant::Url,
];

/// RPKI object queries (ROAs, ASPAs, X.509 resource certs), surfaced in the
/// "Experimental" group. Digest lookups are excluded entirely (see
/// [`is_digest`]); every other `Rpki1*` variant, searches included, lives here.
const EXPERIMENTAL: &[QueryTypeVariant] = &[
    QueryTypeVariant::Rpki1RoaHandle,
    QueryTypeVariant::Rpki1RoaIp,
    QueryTypeVariant::Rpki1RoaCidr,
    QueryTypeVariant::Rpki1RoaNameSearch,
    QueryTypeVariant::Rpki1RoaOriginAutnumSearch,
    QueryTypeVariant::Rpki1AspaHandle,
    QueryTypeVariant::Rpki1AspaAutnum,
    QueryTypeVariant::Rpki1AspaNameSearch,
    QueryTypeVariant::Rpki1AspaProviderAutnumSearch,
    QueryTypeVariant::Rpki1X509ResourceCertHandle,
    QueryTypeVariant::Rpki1X509ResourceCertIssuerSearch,
    QueryTypeVariant::Rpki1X509ResourceCertSubjectSearch,
    QueryTypeVariant::Rpki1X509ResourceCertSkiSearch,
    QueryTypeVariant::Rpki1X509ResourceCertIpSearch,
    QueryTypeVariant::Rpki1X509ResourceCertCidrSearch,
    QueryTypeVariant::Rpki1X509ResourceCertAutnumSearch,
];

/// Server help plus the non-RPKI targeted searches.
const TARGETED: &[QueryTypeVariant] = &[
    QueryTypeVariant::Help,
    QueryTypeVariant::EntityNameSearch,
    QueryTypeVariant::EntityHandleSearch,
    QueryTypeVariant::NetworkNameSearch,
    QueryTypeVariant::NetworkHandleSearch,
    QueryTypeVariant::DomainNameSearch,
    QueryTypeVariant::DomainNsNameSearch,
    QueryTypeVariant::DomainNsIpSearch,
    QueryTypeVariant::NameserverNameSearch,
    QueryTypeVariant::NameserverIpSearch,
    QueryTypeVariant::AutnumNameSearch,
    QueryTypeVariant::AutnumHandleSearch,
];

/// RIR scoped queries: every up/down/top/bottom variant.
const RIR_SEARCH: &[QueryTypeVariant] = &[
    QueryTypeVariant::IpV4AddrUp,
    QueryTypeVariant::IpV6AddrUp,
    QueryTypeVariant::IpV4CidrUp,
    QueryTypeVariant::IpV6CidrUp,
    QueryTypeVariant::IpV4AddrDown,
    QueryTypeVariant::IpV6AddrDown,
    QueryTypeVariant::IpV4CidrDown,
    QueryTypeVariant::IpV6CidrDown,
    QueryTypeVariant::IpV4AddrTop,
    QueryTypeVariant::IpV6AddrTop,
    QueryTypeVariant::IpV4CidrTop,
    QueryTypeVariant::IpV6CidrTop,
    QueryTypeVariant::IpV4AddrBottom,
    QueryTypeVariant::IpV6AddrBottom,
    QueryTypeVariant::IpV4CidrBottom,
    QueryTypeVariant::IpV6CidrBottom,
    QueryTypeVariant::AsNumberUp,
    QueryTypeVariant::AsNumberDown,
    QueryTypeVariant::AsNumberTop,
    QueryTypeVariant::AsNumberBottom,
    QueryTypeVariant::RdnsIpv4Up,
    QueryTypeVariant::RdnsIpv6Up,
    QueryTypeVariant::RdnsIpv4Down,
    QueryTypeVariant::RdnsIpv6Down,
    QueryTypeVariant::RdnsIpv4Top,
    QueryTypeVariant::RdnsIpv6Top,
    QueryTypeVariant::RdnsIpv4Bottom,
    QueryTypeVariant::RdnsIpv6Bottom,
];

/// A curated dropdown group: its display label, its variants, and whether the
/// auto-detect option is prepended to it.
struct GroupSpec {
    label: &'static str,
    variants: &'static [QueryTypeVariant],
    auto_detect: bool,
}

/// The dropdown groups in display order.
///
/// Every non-digest [`QueryTypeVariant`] appears in exactly one group; the
/// coverage test enforces this so a new upstream variant can't silently go
/// unoffered.
const GROUPS: &[GroupSpec] = &[
    GroupSpec {
        label: "Lookups",
        variants: LOOKUPS,
        auto_detect: true,
    },
    GroupSpec {
        label: "Targeted Query",
        variants: TARGETED,
        auto_detect: false,
    },
    GroupSpec {
        label: "RIR Search",
        variants: RIR_SEARCH,
        auto_detect: false,
    },
    GroupSpec {
        label: "Experimental",
        variants: EXPERIMENTAL,
        auto_detect: false,
    },
];

/// Directional code suffixes and their display words, shared by
/// [`pick_label`]'s composition and the RIR grouping tests.
const DIRECTIONS: [(&str, &str); 4] = [
    ("_up", "up"),
    ("_down", "down"),
    ("_top", "top"),
    ("_bottom", "bottom"),
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

/// Hand-picked labels for base (non-directional) query codes.
fn curated_label(code: &str) -> Option<&'static str> {
    Some(match code {
        // Lookups
        "domain" => "Domain",
        "alabel" => "A-Label (punycode)",
        "ip_v4_addr" => "IPv4 address",
        "ip_v6_addr" => "IPv6 address",
        "ip_v4_cidr" => "IPv4 CIDR",
        "ip_v6_cidr" => "IPv6 CIDR",
        "as_number" => "Autonomous system (ASN)",
        "nameserver" => "Nameserver",
        "entity" => "Entity handle",
        "rdns_ipv4" => "Reverse DNS (IPv4)",
        "rdns_ipv6" => "Reverse DNS (IPv6)",
        "url" => "Explicit URL",
        // Targeted Query
        "help" => "Server help",
        "entity_name_search" => "Entity name search",
        "entity_handle_search" => "Entity handle search",
        "network_name_search" => "Network name search",
        "network_handle_search" => "Network handle search",
        "domain_name_search" => "Domain name search",
        "domain_ns_name_search" => "Domain nameserver name search",
        "domain_ns_ip_search" => "Domain nameserver IP search",
        "nameserver_name_search" => "Nameserver name search",
        "nameserver_ip_search" => "Nameserver IP search",
        "autnum_name_search" => "ASN name search",
        "autnum_handle_search" => "ASN handle search",
        // Experimental (RPKI)
        "rpki1_roa_handle" => "ROA by handle",
        "rpki1_roa_ip" => "ROA by IP",
        "rpki1_roa_cidr" => "ROA by CIDR",
        "rpki1_roa_name_search" => "ROA name search",
        "rpki1_roa_origin_autnum_search" => "ROA origin ASN search",
        "rpki1_aspa_handle" => "ASPA by handle",
        "rpki1_aspa_autnum" => "ASPA by ASN",
        "rpki1_aspa_name_search" => "ASPA name search",
        "rpki1_aspa_provider_autnum_search" => "ASPA provider ASN search",
        "rpki1_x509_resource_cert_handle" => "X.509 resource cert by handle",
        "rpki1_x509_resource_cert_issuer_search" => "X.509 issuer search",
        "rpki1_x509_resource_cert_subject_search" => "X.509 subject search",
        "rpki1_x509_resource_cert_ski_search" => "X.509 SKI search",
        "rpki1_x509_resource_cert_ip_search" => "X.509 IP search",
        "rpki1_x509_resource_cert_cidr_search" => "X.509 CIDR search",
        "rpki1_x509_resource_cert_autnum_search" => "X.509 ASN search",
        _ => return None,
    })
}

/// Friendly label for any query code: a curated name when one exists, a
/// composed `<base label> <direction>` for the RIR scoped queries (codes
/// ending in `_up`/`_down`/`_top`/`_bottom`), or [`humanize`] as a fallback.
fn pick_label(code: &str) -> String {
    if let Some(label) = curated_label(code) {
        return label.to_string();
    }
    for (suffix, dir) in DIRECTIONS {
        if let Some(base) = code.strip_suffix(suffix)
            && let Some(base_label) = curated_label(base)
        {
            return format!("{base_label} {dir}");
        }
    }
    humanize(code)
}

/// Builds the grouped option list from [`GROUPS`]: "Lookups" (with
/// auto-detect first), "Experimental" (RPKI), "Targeted Query" (help and
/// the targeted searches) and "RIR Search" (up/down/top/bottom). No code
/// appears in more than one group.
pub fn query_type_groups() -> Vec<QueryTypeGroup> {
    GROUPS
        .iter()
        .map(|spec| {
            let mut options: Vec<QueryTypeOption> = spec
                .variants
                .iter()
                .filter(|v| !is_digest(v))
                .map(|v| {
                    let code = code_of(v);
                    let label = pick_label(&code);
                    QueryTypeOption { code, label }
                })
                .collect();
            if spec.auto_detect {
                options.insert(
                    0,
                    QueryTypeOption {
                        code: "auto".to_string(),
                        label: "Auto-detect".to_string(),
                    },
                );
            }
            QueryTypeGroup {
                label: spec.label.to_string(),
                options,
            }
        })
        .collect()
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

/// Builds an rDNS query from `value`, auto-detecting the address family.
///
/// `v4`/`v6` are the same-scope reverse-DNS constructors (e.g. `rdns_ipv4`
/// and `rdns_ipv6`). The selected dropdown code only fixes the *scope*; the
/// *family* is taken from the value itself:
/// - a plain IPv4/IPv6 address is converted to its reverse DNS domain and
///   routed to the matching-family constructor, so a family mismatch with the
///   chosen type is corrected rather than rejected;
/// - a CIDR block (e.g. `192.0.2.0/24`) is converted to the reverse DNS zone
///   that covers it (see [`ipnet_to_reverse_dns`]);
/// - a non-IP value (an already-valid `*.in-addr.arpa` / `*.ip6.arpa` name)
///   is passed through unchanged, trying the IPv4 then IPv6 constructor so
///   either family's domain resolves under any rdns code.
fn rdns_build(
    value: &str,
    v4: fn(&str) -> Result<QueryType, RdapClientError>,
    v6: fn(&str) -> Result<QueryType, RdapClientError>,
) -> Result<QueryType, RdapClientError> {
    let v = value.trim();
    if let Ok(net) = v.parse::<IpNet>() {
        let domain = ipnet_to_reverse_dns(&net);
        return match net {
            IpNet::V4(_) => v4(&domain),
            IpNet::V6(_) => v6(&domain),
        };
    }
    match v.parse::<IpAddr>() {
        Ok(ip @ IpAddr::V4(_)) => v4(&ip_to_reverse_dns(&ip)),
        Ok(ip @ IpAddr::V6(_)) => v6(&ip_to_reverse_dns(&ip)),
        Err(_) => v4(v).or_else(|_| v6(v)),
    }
}

/// Converts an [`IpNet`] to the reverse DNS zone name that covers it.
///
/// The reverse DNS format can only express prefixes on label boundaries:
/// IPv4 on octet boundaries (`/8`, `/16`, `/24`, `/32`) and IPv6 on nibble
/// boundaries (multiples of 4). A prefix that isn't label-aligned is floored
/// to the nearest coarser boundary, so the returned zone always contains the
/// input network (e.g. `192.0.2.128/25` → `2.0.192.in-addr.arpa`, a `/24`).
fn ipnet_to_reverse_dns(net: &IpNet) -> String {
    match net {
        IpNet::V4(v4) => {
            let octets = v4.network().octets();
            let labels = (v4.prefix_len() / 8) as usize;
            let parts: Vec<String> = octets[..labels]
                .iter()
                .rev()
                .map(|o| o.to_string())
                .collect();
            format!("{}.in-addr.arpa", parts.join("."))
        }
        IpNet::V6(v6) => {
            let nibbles: Vec<u8> = v6
                .network()
                .octets()
                .iter()
                .flat_map(|b| [b >> 4, b & 0x0f])
                .collect();
            let take = (v6.prefix_len() / 4) as usize;
            let parts: Vec<String> = nibbles[..take]
                .iter()
                .rev()
                .map(|n| format!("{n:x}"))
                .collect();
            format!("{}.ip6.arpa", parts.join("."))
        }
    }
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
        // The dropdown code fixes the scope; the address family is auto-detected
        // from the value (first arg = IPv4 ctor, second = IPv6 ctor).
        Q::RdnsIpv4 | Q::RdnsIpv6 => rdns_build(value, QueryType::rdns_ipv4, QueryType::rdns_ipv6),
        Q::RdnsIpv4Up | Q::RdnsIpv6Up => {
            rdns_build(value, QueryType::rdns_ipv4_up, QueryType::rdns_ipv6_up)
        }
        Q::RdnsIpv4Down | Q::RdnsIpv6Down => {
            rdns_build(value, QueryType::rdns_ipv4_down, QueryType::rdns_ipv6_down)
        }
        Q::RdnsIpv4Top | Q::RdnsIpv6Top => {
            rdns_build(value, QueryType::rdns_ipv4_top, QueryType::rdns_ipv6_top)
        }
        Q::RdnsIpv4Bottom | Q::RdnsIpv6Bottom => rdns_build(
            value,
            QueryType::rdns_ipv4_bottom,
            QueryType::rdns_ipv6_bottom,
        ),
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
    fn rdns_ipv4_converts_plain_ip() {
        // GIVEN the rdns_ipv4 code and a plain IPv4 address
        // WHEN built
        let q = query_type_from_code("rdns_ipv4", "192.0.2.1").unwrap();
        // THEN it becomes the /32 reverse-DNS query for that address
        match q {
            QueryType::RdnsIpv4(net) => assert_eq!(net.to_string(), "192.0.2.1/32"),
            other => panic!("expected RdnsIpv4, got {other:?}"),
        }
    }

    #[test]
    fn rdns_ipv6_converts_plain_ip() {
        // GIVEN the rdns_ipv6 code and a plain IPv6 address
        // WHEN built
        let q = query_type_from_code("rdns_ipv6", "2001:db8::1").unwrap();
        // THEN it becomes the /128 reverse-DNS query for that address
        match q {
            QueryType::RdnsIpv6(net) => assert_eq!(net.to_string(), "2001:db8::1/128"),
            other => panic!("expected RdnsIpv6, got {other:?}"),
        }
    }

    #[test]
    fn rdns_auto_routes_family_mismatch() {
        // GIVEN rdns_ipv4 chosen but an IPv6 address entered (and vice versa)
        // WHEN built
        let q = query_type_from_code("rdns_ipv4", "2001:db8::1").unwrap();
        let r = query_type_from_code("rdns_ipv6", "192.0.2.1").unwrap();
        // THEN each routes to the constructor matching the IP's actual family
        assert!(matches!(q, QueryType::RdnsIpv6(_)), "{q:?}");
        assert!(matches!(r, QueryType::RdnsIpv4(_)), "{r:?}");
    }

    #[test]
    fn rdns_auto_route_preserves_scope() {
        // GIVEN scoped rdns codes with a mismatched-family IP
        // WHEN built
        let up = query_type_from_code("rdns_ipv4_up", "2001:db8::1").unwrap();
        let bottom = query_type_from_code("rdns_ipv6_bottom", "192.0.2.1").unwrap();
        // THEN the scope is kept while the family is corrected
        assert!(matches!(up, QueryType::RdnsIpv6Up(_)), "{up:?}");
        assert!(matches!(bottom, QueryType::RdnsIpv4Bottom(_)), "{bottom:?}");
    }

    #[test]
    fn rdns_existing_domain_unchanged() {
        // GIVEN an already-valid reverse DNS domain (not a plain IP)
        // WHEN built with rdns_ipv4
        let q = query_type_from_code("rdns_ipv4", "1.2.0.192.in-addr.arpa").unwrap();
        // THEN it parses unchanged to the same /32 the IP conversion would give
        match q {
            QueryType::RdnsIpv4(net) => assert_eq!(net.to_string(), "192.0.2.1/32"),
            other => panic!("expected RdnsIpv4, got {other:?}"),
        }
    }

    #[test]
    fn rdns_ipv4_accepts_cidr() {
        // GIVEN the rdns_ipv4 code and a CIDR block
        // WHEN built
        let q = query_type_from_code("rdns_ipv4", "192.0.2.0/24").unwrap();
        // THEN it becomes the /24 reverse-DNS query for that network
        match q {
            QueryType::RdnsIpv4(net) => assert_eq!(net.to_string(), "192.0.2.0/24"),
            other => panic!("expected RdnsIpv4, got {other:?}"),
        }
    }

    #[test]
    fn rdns_ipv6_accepts_cidr() {
        // GIVEN the rdns_ipv6 code and an IPv6 CIDR block
        // WHEN built
        let q = query_type_from_code("rdns_ipv6", "2001:db8::/32").unwrap();
        // THEN it becomes the /32 reverse-DNS query for that network
        match q {
            QueryType::RdnsIpv6(net) => assert_eq!(net.to_string(), "2001:db8::/32"),
            other => panic!("expected RdnsIpv6, got {other:?}"),
        }
    }

    #[test]
    fn rdns_cidr_floors_to_label_boundary() {
        // GIVEN a prefix that isn't on a reverse-DNS label boundary
        // WHEN built
        let q = query_type_from_code("rdns_ipv4", "192.0.2.128/25").unwrap();
        // THEN it floors to the containing /24 zone
        match q {
            QueryType::RdnsIpv4(net) => assert_eq!(net.to_string(), "192.0.2.0/24"),
            other => panic!("expected RdnsIpv4, got {other:?}"),
        }
    }

    #[test]
    fn rdns_cidr_normalizes_host_bits() {
        // GIVEN a CIDR whose address carries host bits
        // WHEN built
        let q = query_type_from_code("rdns_ipv4", "192.0.2.7/24").unwrap();
        // THEN it normalizes to the network address
        match q {
            QueryType::RdnsIpv4(net) => assert_eq!(net.to_string(), "192.0.2.0/24"),
            other => panic!("expected RdnsIpv4, got {other:?}"),
        }
    }

    #[test]
    fn rdns_cidr_auto_routes_family_and_scope() {
        // GIVEN a scoped rdns code with a CIDR of the other family
        // WHEN built
        let up = query_type_from_code("rdns_ipv4_up", "2001:db8::/32").unwrap();
        let down = query_type_from_code("rdns_ipv6_down", "192.0.2.0/24").unwrap();
        // THEN family is corrected while the scope is preserved
        assert!(matches!(up, QueryType::RdnsIpv6Up(_)), "{up:?}");
        assert!(matches!(down, QueryType::RdnsIpv4Down(_)), "{down:?}");
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
        let labels: Vec<&str> = groups.iter().map(|g| g.label.as_str()).collect();
        assert_eq!(
            labels,
            ["Lookups", "Targeted Query", "RIR Search", "Experimental"]
        );

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
        // auto-detect leads the Lookups group
        assert_eq!(groups[0].options[0].code, "auto");
        assert_eq!(groups[0].options.len(), LOOKUPS.len() + 1);
    }

    #[test]
    fn lookups_group_contains_expected_codes() {
        // GIVEN the generated groups
        let groups = query_type_groups();
        let lookups: Vec<&str> = groups[0].options.iter().map(|o| o.code.as_str()).collect();
        // THEN auto-detect and the curated lookup codes are present, including
        // the A-Label that was added when "Common" became "Lookups"
        for code in [
            "auto",
            "domain",
            "alabel",
            "ip_v4_addr",
            "ip_v6_addr",
            "ip_v4_cidr",
            "ip_v6_cidr",
            "as_number",
            "nameserver",
            "entity",
            "rdns_ipv4",
            "rdns_ipv6",
            "url",
        ] {
            assert!(lookups.contains(&code), "lookups missing {code}");
        }
        // AND help is not a lookup (it moved to Targeted Query)
        assert!(!lookups.contains(&"help"));
    }

    /// Codes of the group with the given label.
    fn group_codes<'a>(groups: &'a [QueryTypeGroup], label: &str) -> Vec<&'a str> {
        groups
            .iter()
            .find(|g| g.label == label)
            .unwrap_or_else(|| panic!("no group labelled {label}"))
            .options
            .iter()
            .map(|o| o.code.as_str())
            .collect()
    }

    #[test]
    fn targeted_query_group_has_help_and_non_rpki_searches() {
        // GIVEN the generated groups
        let groups = query_type_groups();
        let targeted = group_codes(&groups, "Targeted Query");
        // THEN server help and every non-RPKI search is present
        assert_eq!(targeted[0], "help");
        for code in [
            "entity_name_search",
            "entity_handle_search",
            "network_name_search",
            "network_handle_search",
            "domain_name_search",
            "domain_ns_name_search",
            "domain_ns_ip_search",
            "nameserver_name_search",
            "nameserver_ip_search",
            "autnum_name_search",
            "autnum_handle_search",
        ] {
            assert!(targeted.contains(&code), "targeted missing {code}");
        }
        // AND no RPKI search leaked in (those live in Experimental)
        assert!(
            !targeted.iter().any(|c| c.starts_with("rpki1_")),
            "rpki search leaked into Targeted Query"
        );
    }

    #[test]
    fn experimental_group_holds_all_non_digest_rpki_variants() {
        // GIVEN the generated groups
        let groups = query_type_groups();
        let experimental = group_codes(&groups, "Experimental");
        // THEN every non-digest Rpki1* variant is in Experimental
        for v in QueryTypeVariant::VARIANTS {
            let code = code_of(v);
            if code.starts_with("rpki1_") && !is_digest(v) {
                assert!(
                    experimental.iter().any(|c| *c == code),
                    "rpki {code} not in Experimental"
                );
            }
        }
        // AND Experimental contains nothing but RPKI codes
        assert!(
            experimental.iter().all(|c| c.starts_with("rpki1_")),
            "non-rpki code leaked into Experimental"
        );
    }

    #[test]
    fn rir_search_group_holds_all_directional_variants() {
        // GIVEN the generated groups
        let groups = query_type_groups();
        let rir = group_codes(&groups, "RIR Search");
        // THEN every up/down/top/bottom variant is in RIR Search
        for v in QueryTypeVariant::VARIANTS {
            let code = code_of(v);
            let directional = DIRECTIONS.iter().any(|(suffix, _)| code.ends_with(suffix));
            if directional {
                assert!(
                    rir.iter().any(|c| *c == code),
                    "directional {code} not in RIR Search"
                );
            }
        }
        assert_eq!(rir.len(), RIR_SEARCH.len());
    }

    #[test]
    fn composed_direction_labels_read_naturally() {
        // GIVEN directional codes over curated base types
        // WHEN labeled
        // THEN the base label carries through with the direction appended
        assert_eq!(pick_label("ip_v4_addr_up"), "IPv4 address up");
        assert_eq!(
            pick_label("as_number_bottom"),
            "Autonomous system (ASN) bottom"
        );
        assert_eq!(pick_label("rdns_ipv6_top"), "Reverse DNS (IPv6) top");
        // AND a directional code over an uncurated base falls back to humanize
        assert_eq!(pick_label("widget_up"), "Widget Up");
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
