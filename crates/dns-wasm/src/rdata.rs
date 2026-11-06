//! Typed extraction of DNS record data for display.
//!
//! The renderer needs record-specific labels and styling without parsing the
//! string form of `RData`. This module turns common `RData` variants into
//! display-ready fields and leaves unmapped variants empty so the renderer can
//! fall back to a plain `Data` row.

use std::fmt::Write;
use std::net::IpAddr;

use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::{A, AAAA};
use icann_rdap_common::rdns::ip_to_reverse_dns;

/// A display-ready value extracted from record data.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RdataValue {
    /// Normal-font text.
    Text(String),
    /// A monospace IP address with reverse-DNS and RDAP query affordances.
    Address {
        /// Visible IP address text.
        display: String,
        /// Reverse DNS name to query for this address.
        reverse_dns: String,
        /// RDAP Explorer query-type code for this address family.
        rdap_query_type: &'static str,
    },
    /// A nameserver host name with `A`/`AAAA` query links and a copy button.
    Nameserver {
        /// Visible nameserver name (trailing dot stripped).
        display: String,
    },
    /// A CNAME canonical target with `A`/`AAAA` query links and a copy button.
    CanonicalName {
        /// Visible canonical name (trailing dot stripped).
        display: String,
    },
    /// A PTR record's domain name with `A`/`AAAA` query links and a copy button.
    DomainName {
        /// Visible domain name (trailing dot stripped).
        display: String,
    },
}

/// One labeled field extracted from record data.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RdataField {
    /// Stable display label for the field.
    pub label: &'static str,
    /// Value and its display styling.
    pub value: RdataValue,
}

/// Returns the IP address and RDAP query type carried by an address record.
///
/// This is intentionally pure and only understands the two address record
/// types. It lets the renderer decide monospace styling and the RDAP
/// address query type from typed data instead of scanning rendered strings
/// for IP-like tokens.
fn address_from_rdata(rdata: &RData) -> Option<(IpAddr, &'static str)> {
    match rdata {
        RData::A(A(ipv4)) => Some((IpAddr::V4(*ipv4), "ip_v4_addr")),
        RData::AAAA(AAAA(ipv6)) => Some((IpAddr::V6(*ipv6), "ip_v6_addr")),
        _ => None,
    }
}

/// Extracts display fields from common record types.
///
/// Returns an empty vector for unmapped types. The renderer treats that as
/// the fallback case and renders the record's string form as a single
/// `Data` row.
pub(crate) fn rdata_fields(rdata: &RData) -> Vec<RdataField> {
    if let Some((ip, rdap_query_type)) = address_from_rdata(rdata) {
        return vec![address_field(
            "Address",
            ip.to_string(),
            ip_to_reverse_dns(&ip),
            rdap_query_type,
        )];
    }

    match rdata {
        RData::CNAME(cname) => vec![canonical_name_field("Canonical Name", cname.to_string())],
        RData::NS(ns) => vec![nameserver_field("Nameserver", ns.to_string())],
        RData::PTR(ptr) => vec![domain_name_field("Domain Name", ptr.to_string())],
        RData::MX(mx) => vec![
            text("Preference", mx.preference.to_string()),
            text("Exchange", mx.exchange.to_string()),
        ],
        RData::SOA(soa) => vec![
            text("Primary Server", soa.mname.to_string()),
            text("Responsible Person", soa.rname.to_string()),
            text("Serial", soa.serial.to_string()),
            text("Refresh", soa.refresh.to_string()),
            text("Retry", soa.retry.to_string()),
            text("Expire", soa.expire.to_string()),
            text("Minimum", soa.minimum.to_string()),
        ],
        RData::SRV(srv) => vec![
            text("Priority", srv.priority.to_string()),
            text("Weight", srv.weight.to_string()),
            text("Port", srv.port.to_string()),
            text("Target", srv.target.to_string()),
        ],
        RData::CAA(caa) => vec![
            text("Issuer Critical", caa.issuer_critical.to_string()),
            text("Reserved Flags", caa.reserved_flags.to_string()),
            text("Tag", caa.tag.clone()),
            text("Value", String::from_utf8_lossy(&caa.value).into_owned()),
        ],
        RData::SSHFP(sshfp) => vec![
            text("Algorithm", u8::from(sshfp.algorithm).to_string()),
            text(
                "Fingerprint Type",
                u8::from(sshfp.fingerprint_type).to_string(),
            ),
            text("Fingerprint", hex_lower(&sshfp.fingerprint)),
        ],
        RData::TLSA(tlsa) => vec![
            text("Cert Usage", u8::from(tlsa.cert_usage).to_string()),
            text("Selector", u8::from(tlsa.selector).to_string()),
            text("Matching", u8::from(tlsa.matching).to_string()),
            text("Certificate Data", hex_lower(&tlsa.cert_data)),
        ],
        RData::NAPTR(naptr) => vec![
            text("Order", naptr.order.to_string()),
            text("Preference", naptr.preference.to_string()),
            text("Flags", String::from_utf8_lossy(&naptr.flags).into_owned()),
            text(
                "Services",
                String::from_utf8_lossy(&naptr.services).into_owned(),
            ),
            text(
                "Regexp",
                String::from_utf8_lossy(&naptr.regexp).into_owned(),
            ),
            text("Replacement", naptr.replacement.to_string()),
        ],
        _ => Vec::new(),
    }
}

fn text(label: &'static str, value: impl Into<String>) -> RdataField {
    RdataField {
        label,
        value: RdataValue::Text(value.into()),
    }
}

fn address_field(
    label: &'static str,
    display: impl Into<String>,
    reverse_dns: impl Into<String>,
    rdap_query_type: &'static str,
) -> RdataField {
    RdataField {
        label,
        value: RdataValue::Address {
            display: display.into(),
            reverse_dns: reverse_dns.into(),
            rdap_query_type,
        },
    }
}

/// Builds a nameserver field, stripping the trailing dot from the fully
/// qualified name for display, copy and query use.
fn nameserver_field(label: &'static str, value: impl Into<String>) -> RdataField {
    let display = value.into();
    let display = display.strip_suffix('.').unwrap_or(&display).to_string();
    RdataField {
        label,
        value: RdataValue::Nameserver { display },
    }
}

/// Builds a canonical-name field, stripping the trailing dot from the
/// fully qualified name for display, copy and query use.
fn canonical_name_field(label: &'static str, value: impl Into<String>) -> RdataField {
    let display = value.into();
    let display = display.strip_suffix('.').unwrap_or(&display).to_string();
    RdataField {
        label,
        value: RdataValue::CanonicalName { display },
    }
}

/// Builds a PTR domain-name field, stripping the trailing dot from the
/// fully qualified name for display, copy and query use.
fn domain_name_field(label: &'static str, value: impl Into<String>) -> RdataField {
    let display = value.into();
    let display = display.strip_suffix('.').unwrap_or(&display).to_string();
    RdataField {
        label,
        value: RdataValue::DomainName { display },
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to an owned `String` only fails if allocation fails; the
        // capacity above is exact for the hex representation.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::sshfp::{Algorithm, FingerprintType};
    use hickory_proto::rr::rdata::tlsa::{CertUsage, Matching, Selector};
    use hickory_proto::rr::rdata::{CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, SSHFP, TLSA, TXT};
    use hickory_proto::rr::{Name, RecordData};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn name(value: &str) -> Name {
        value.parse().expect("valid DNS name")
    }

    #[test]
    fn address_from_rdata_returns_ipv4_and_rdap_type_for_a_record() {
        // GIVEN an A record's rdata
        let rdata = RData::A(A(Ipv4Addr::new(203, 0, 113, 7)));

        // WHEN converted to an address and RDAP query type
        let address = address_from_rdata(&rdata);

        // THEN the IPv4 address and IPv4 RDAP query type are returned.
        assert_eq!(
            address,
            Some((IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), "ip_v4_addr"))
        );
    }

    #[test]
    fn address_from_rdata_returns_ipv6_and_rdap_type_for_aaaa_record() {
        // GIVEN an AAAA record's rdata
        let rdata = RData::AAAA(AAAA(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c6, 0x1970,
        )));

        // WHEN converted to an address and RDAP query type
        let address = address_from_rdata(&rdata);

        // THEN the IPv6 address and IPv6 RDAP query type are returned.
        assert_eq!(
            address,
            Some((
                IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c6, 0x1970,
                )),
                "ip_v6_addr"
            ))
        );
    }

    #[test]
    fn address_from_rdata_returns_none_for_non_address_record() {
        // GIVEN a TXT record's rdata
        let rdata = RData::TXT(TXT::new(vec!["backup 198.51.100.3".to_string()]));

        // WHEN converted to an address and RDAP query type
        let address = address_from_rdata(&rdata);

        // THEN no IP address is inferred from the string content.
        assert_eq!(address, None);
    }

    #[test]
    fn rdata_fields_a_returns_address_with_reverse_dns_and_rdap_type() {
        // GIVEN an A record's rdata
        let rdata = RData::A(A(Ipv4Addr::new(93, 184, 216, 34)));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN there is one Address field carrying the reverse DNS target
        // and the IPv4 RDAP query type.
        assert_eq!(
            fields,
            vec![address_field(
                "Address",
                "93.184.216.34",
                "34.216.184.93.in-addr.arpa",
                "ip_v4_addr"
            )]
        );
    }

    #[test]
    fn rdata_fields_aaaa_returns_address_with_reverse_dns_and_rdap_type() {
        // GIVEN an AAAA record's rdata
        let rdata = RData::AAAA(AAAA(Ipv6Addr::new(
            0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c6, 0x1970,
        )));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN there is one Address field carrying the IPv6 reverse DNS
        // target and the IPv6 RDAP query type.
        assert_eq!(
            fields,
            vec![address_field(
                "Address",
                "2606:2800:220:1:248:1893:25c6:1970",
                "0.7.9.1.6.c.5.2.3.9.8.1.8.4.2.0.1.0.0.0.0.2.2.0.0.0.8.2.6.0.6.2.ip6.arpa",
                "ip_v6_addr"
            )]
        );
    }

    #[test]
    fn rdata_fields_aaaa_uses_full_reverse_target_for_compressed_ipv6() {
        // GIVEN a compressed IPv6 address
        let rdata = RData::AAAA(AAAA(Ipv6Addr::LOCALHOST));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the visible address stays compressed while the PTR target is
        // the full reverse name and the RDAP query remains address-based.
        assert_eq!(
            fields,
            vec![address_field(
                "Address",
                "::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
                "ip_v6_addr"
            )]
        );
    }

    #[test]
    fn rdata_fields_cname_returns_canonical_name() {
        // GIVEN a CNAME record's rdata
        let rdata = RData::CNAME(CNAME(name("target.example.")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN there is one Canonical Name field with the trailing dot stripped.
        assert_eq!(
            fields,
            vec![RdataField {
                label: "Canonical Name",
                value: RdataValue::CanonicalName {
                    display: "target.example".to_string()
                }
            }]
        );
    }

    #[test]
    fn rdata_fields_ns_returns_nameserver() {
        // GIVEN an NS record's rdata
        let rdata = RData::NS(NS(name("ns1.example.")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN there is one Nameserver field with the trailing dot stripped.
        assert_eq!(
            fields,
            vec![RdataField {
                label: "Nameserver",
                value: RdataValue::Nameserver {
                    display: "ns1.example".to_string()
                }
            }]
        );
    }

    #[test]
    fn rdata_fields_ns_strips_trailing_dot() {
        // GIVEN an NS record whose name carries a trailing dot
        let rdata = RData::NS(NS(name("a.iana-servers.net.")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the display name has no trailing dot.
        assert_eq!(
            fields[0].value,
            RdataValue::Nameserver {
                display: "a.iana-servers.net".to_string()
            }
        );
    }

    #[test]
    fn rdata_fields_ns_without_trailing_dot_is_unchanged() {
        // GIVEN an NS record whose name has no trailing dot
        let rdata = RData::NS(NS(name("ns1.example")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the display name is unchanged.
        assert_eq!(
            fields[0].value,
            RdataValue::Nameserver {
                display: "ns1.example".to_string()
            }
        );
    }

    #[test]
    fn rdata_fields_ptr_returns_domain_name() {
        // GIVEN a PTR record's rdata
        let rdata = RData::PTR(PTR(name("host.example.")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN there is one Domain Name field with the trailing dot stripped.
        assert_eq!(
            fields,
            vec![RdataField {
                label: "Domain Name",
                value: RdataValue::DomainName {
                    display: "host.example".to_string()
                }
            }]
        );
    }

    #[test]
    fn rdata_fields_mx_returns_preference_and_exchange() {
        // GIVEN an MX record's rdata
        let rdata = RData::MX(MX::new(10, name("mail.example.")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN preference and exchange are separate fields.
        assert_eq!(
            fields,
            vec![text("Preference", "10"), text("Exchange", "mail.example."),]
        );
    }

    #[test]
    fn rdata_fields_soa_returns_all_soa_fields() {
        // GIVEN an SOA record's rdata
        let rdata = RData::SOA(SOA::new(
            name("ns1.example."),
            name("admin.example."),
            2026010101,
            7200,
            3600,
            1209600,
            3600,
        ));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN every SOA field is labeled.
        assert_eq!(
            fields,
            vec![
                text("Primary Server", "ns1.example."),
                text("Responsible Person", "admin.example."),
                text("Serial", "2026010101"),
                text("Refresh", "7200"),
                text("Retry", "3600"),
                text("Expire", "1209600"),
                text("Minimum", "3600"),
            ]
        );
    }

    #[test]
    fn rdata_fields_srv_returns_all_srv_fields() {
        // GIVEN an SRV record's rdata
        let rdata = RData::SRV(SRV::new(10, 20, 443, name("svc.example.")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN priority, weight, port and target are separate fields.
        assert_eq!(
            fields,
            vec![
                text("Priority", "10"),
                text("Weight", "20"),
                text("Port", "443"),
                text("Target", "svc.example."),
            ]
        );
    }

    #[test]
    fn rdata_fields_caa_returns_all_caa_fields() {
        // GIVEN a CAA record's rdata
        let rdata = RData::CAA(CAA::new_issue(true, Some(name("ca.example.")), Vec::new()));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the CAA flag, tag and value are separate fields.
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], text("Issuer Critical", "true"));
        assert_eq!(fields[1], text("Reserved Flags", "0"));
        assert_eq!(fields[2], text("Tag", "issue"));
        assert!(
            String::from_utf8_lossy(caa_value(&rdata)).contains("ca.example."),
            "CAA value should carry the issuer name"
        );
    }

    #[test]
    fn rdata_fields_sshfp_uses_lowercase_hex_fingerprint() {
        // GIVEN an SSHFP record's rdata
        let rdata = RData::SSHFP(SSHFP::new(
            Algorithm::Ed25519,
            FingerprintType::SHA256,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        ));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the fingerprint is lowercase hex.
        assert_eq!(
            fields,
            vec![
                text("Algorithm", "4"),
                text("Fingerprint Type", "2"),
                text("Fingerprint", "deadbeef"),
            ]
        );
    }

    #[test]
    fn rdata_fields_tlsa_uses_lowercase_hex_certificate_data() {
        // GIVEN a TLSA record's rdata
        let rdata = TLSA::new(
            CertUsage::DaneEe,
            Selector::Full,
            Matching::Sha256,
            vec![0x0A, 0x1B, 0x2C],
        )
        .into_rdata();

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the certificate association data is lowercase hex.
        assert_eq!(
            fields,
            vec![
                text("Cert Usage", "3"),
                text("Selector", "0"),
                text("Matching", "1"),
                text("Certificate Data", "0a1b2c"),
            ]
        );
    }

    #[test]
    fn rdata_fields_naptr_returns_all_naptr_fields() {
        // GIVEN a NAPTR record's rdata
        let rdata = NAPTR::new(
            1,
            2,
            b"U".to_vec().into_boxed_slice(),
            b"E2U+sip".to_vec().into_boxed_slice(),
            b"!^.*$!sip:info@example.com!".to_vec().into_boxed_slice(),
            name("replacement.example."),
        )
        .into_rdata();

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN every NAPTR field is labeled.
        assert_eq!(
            fields,
            vec![
                text("Order", "1"),
                text("Preference", "2"),
                text("Flags", "U"),
                text("Services", "E2U+sip"),
                text("Regexp", "!^.*$!sip:info@example.com!"),
                text("Replacement", "replacement.example."),
            ]
        );
    }

    #[test]
    fn rdata_fields_naptr_uses_lossy_utf8_for_invalid_bytes() {
        // GIVEN a NAPTR record whose flags byte is not valid UTF-8
        let rdata = NAPTR::new(
            1,
            2,
            vec![0xff].into_boxed_slice(),
            b"".to_vec().into_boxed_slice(),
            b"".to_vec().into_boxed_slice(),
            name("replacement.example."),
        )
        .into_rdata();

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the invalid byte is replaced with the Unicode replacement
        // character instead of panicking.
        assert_eq!(fields[2], text("Flags", "\u{FFFD}"));
    }

    #[test]
    fn rdata_fields_sshfp_empty_fingerprint_is_empty_hex() {
        // GIVEN an SSHFP record with no fingerprint bytes
        let rdata = SSHFP::new(Algorithm::RSA, FingerprintType::SHA1, Vec::new()).into_rdata();

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the fingerprint renders as an empty hex string.
        assert_eq!(fields[2], text("Fingerprint", ""));
    }

    #[test]
    fn rdata_fields_tlsa_empty_cert_data_is_empty_hex() {
        // GIVEN a TLSA record with no certificate association data
        let rdata =
            TLSA::new(CertUsage::PkixTa, Selector::Full, Matching::Raw, Vec::new()).into_rdata();

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the certificate data renders as an empty hex string.
        assert_eq!(fields[3], text("Certificate Data", ""));
    }

    #[test]
    fn rdata_fields_txt_is_empty_for_renderer_fallback() {
        // GIVEN a TXT record's rdata
        let rdata = RData::TXT(TXT::new(vec![
            "backup nameserver 198.51.100.3 available".to_string(),
        ]));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN no typed fields are returned, so the renderer uses the plain
        // fallback row.
        assert!(fields.is_empty());
    }

    fn caa_value(rdata: &RData) -> &[u8] {
        match rdata {
            RData::CAA(caa) => &caa.value,
            _ => panic!("expected CAA rdata"),
        }
    }
}
