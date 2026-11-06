//! Typed extraction of DNS record data for display.
//!
//! The renderer needs record-specific labels and styling without parsing the
//! string form of `RData`. This module turns common `RData` variants into
//! display-ready fields and leaves unmapped variants empty so the renderer can
//! fall back to a plain `Data` row.

use std::fmt::Write;
use std::net::IpAddr;

use hickory_proto::rr::Name;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::{A, AAAA};
use icann_rdap_common::check::StringCheck;
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
    /// An MX record's mail exchanger host with `A`/`AAAA` query links and a
    /// copy button.
    MailExchange {
        /// Visible mail exchanger host (trailing dot stripped).
        display: String,
    },
    /// An SOA record's primary (master) nameserver with `A`/`AAAA`/RDAP
    /// query links and a copy button.
    PrimaryServer {
        /// Visible primary server host (trailing dot stripped).
        display: String,
    },
    /// An SRV record's target host with `A`/`AAAA` query links and a copy
    /// button.
    ServiceTarget {
        /// Visible target host (trailing dot stripped).
        display: String,
    },
    /// A CAA record value that is an LDH host name (the authorized issuer
    /// domain), with `A`/`AAAA` query links and a copy button.
    CaaIssuer {
        /// Visible issuer host (trailing dot stripped).
        display: String,
    },
    /// A CAA `iodef` value that is a `mailto:` address, with a copy
    /// button.
    CaaEmail {
        /// Visible email address (the `mailto:` scheme stripped).
        display: String,
    },
    /// An SOA record's responsible-person mailbox, rendered as an email
    /// address with a copy button.
    ResponsibleEmail {
        /// Visible email address (the first label as the local part and the
        /// remaining labels as the domain).
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
            mail_exchange_field("Exchange", mx.exchange.to_string()),
        ],
        RData::SOA(soa) => vec![
            primary_server_field("Primary Server", soa.mname.to_string()),
            responsible_person_field("Responsible Person", &soa.rname),
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
            service_target_field("Target", srv.target.to_string()),
        ],
        RData::CAA(caa) => vec![
            text("Issuer Critical", caa.issuer_critical.to_string()),
            text("Reserved Flags", caa.reserved_flags.to_string()),
            text("Tag", caa.tag.clone()),
            caa_value_field("Value", &caa.value),
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

/// Builds a mail-exchanger field, stripping the trailing dot from the
/// fully qualified host for display, copy and query use.
fn mail_exchange_field(label: &'static str, value: impl Into<String>) -> RdataField {
    let display = value.into();
    let display = display.strip_suffix('.').unwrap_or(&display).to_string();
    RdataField {
        label,
        value: RdataValue::MailExchange { display },
    }
}

/// Builds an SOA primary-server field, stripping the trailing dot from the
/// fully qualified host for display, copy and query use.
fn primary_server_field(label: &'static str, value: impl Into<String>) -> RdataField {
    let display = value.into();
    let display = display.strip_suffix('.').unwrap_or(&display).to_string();
    RdataField {
        label,
        value: RdataValue::PrimaryServer { display },
    }
}

/// Builds an SRV target field, stripping the trailing dot from the fully
/// qualified host for display, copy and query use.
fn service_target_field(label: &'static str, value: impl Into<String>) -> RdataField {
    let display = value.into();
    let display = display.strip_suffix('.').unwrap_or(&display).to_string();
    RdataField {
        label,
        value: RdataValue::ServiceTarget { display },
    }
}

/// Builds a CAA value field, classifying the raw value bytes by shape.
///
/// A value that is an LDH host name (at least two labels, per
/// [`StringCheck::is_ldh_hostname`]) becomes a [`RdataValue::CaaIssuer`]
/// so the renderer can offer `A`/`AAAA` queries and a copy button. A
/// `mailto:` URI becomes a [`RdataValue::CaaEmail`] carrying just the
/// email address for copying. Anything else — including an `issue` value
/// carrying `;` parameters, which is not a bare hostname — stays plain
/// [`RdataValue::Text`].
///
/// The host is tested on the raw decoded value (`is_ldh_hostname` already
/// tolerates a single trailing dot) and the trailing dot is then stripped
/// for display, so a `..`-terminated value is correctly rejected rather
/// than shown with a stray dot.
fn caa_value_field(label: &'static str, value: &[u8]) -> RdataField {
    let decoded = String::from_utf8_lossy(value).into_owned();
    if decoded.is_ldh_hostname() {
        let display = decoded.strip_suffix('.').unwrap_or(&decoded).to_string();
        RdataField {
            label,
            value: RdataValue::CaaIssuer { display },
        }
    } else if let Some(email) = mailto_address(&decoded) {
        RdataField {
            label,
            value: RdataValue::CaaEmail { display: email },
        }
    } else {
        text(label, decoded)
    }
}

/// Extracts the email address from a `mailto:` URI.
///
/// The scheme match is case-insensitive (per RFC 3986) and compares bytes
/// so a non-ASCII prefix never slices a character boundary. Any `?`/`#`
/// parameters (e.g. `?subject=CAA`) are dropped so only the address is
/// returned. Returns `None` when the value is not a `mailto:` URI, the
/// address portion is empty, or it lacks an `@` (so a bare `mailto:` or a
/// non-address like `mailto:hello` falls through to plain text).
fn mailto_address(text: &str) -> Option<String> {
    const PREFIX: &[u8] = b"mailto:";
    let bytes = text.as_bytes();
    if bytes.len() < PREFIX.len() || !bytes[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let address = text[PREFIX.len()..]
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim();
    if address.is_empty() || !address.contains('@') {
        None
    } else {
        Some(address.to_string())
    }
}

/// Builds the SOA responsible-person field, rendering the `rname` mailbox
/// as an email address with a copy button when it can be formed.
///
/// Falls back to plain text (the raw `rname` presentation form) when the
/// name has no usable local-part/domain split — e.g. the root name or a
/// single label with no domain.
fn responsible_person_field(label: &'static str, rname: &Name) -> RdataField {
    match rname_to_email(rname) {
        Some(display) => RdataField {
            label,
            value: RdataValue::ResponsibleEmail { display },
        },
        None => text(label, rname.to_string()),
    }
}

/// Converts an SOA `rname` (DNS mailbox form) into an email address.
///
/// In the DNS wire format the first label is the mailbox local-part and the
/// remaining labels are the domain, so `admin.example.com.` becomes
/// `admin@example.com`. Labels are read as raw bytes via `Name::iter`, so a
/// dot escaped in the local part (e.g. `email\.name.example.com.`) comes
/// through as a literal dot: `email.name@example.com`.
///
/// Returns `None` when there is no local-part, the local-part is empty, or
/// there is no domain (root name or a single label), so the caller can fall
/// back to plain text.
fn rname_to_email(rname: &Name) -> Option<String> {
    let mut labels = rname.iter();
    let local_bytes = labels.next()?;
    if local_bytes.is_empty() {
        return None;
    }
    let domain = labels
        .map(|label| String::from_utf8_lossy(label).into_owned())
        .collect::<Vec<_>>();
    if domain.is_empty() {
        return None;
    }
    let local = String::from_utf8_lossy(local_bytes);
    Some(format!("{local}@{}", domain.join(".")))
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

        // THEN preference is plain text and the exchange is a MailExchange
        // field with the trailing dot stripped.
        assert_eq!(
            fields,
            vec![
                text("Preference", "10"),
                RdataField {
                    label: "Exchange",
                    value: RdataValue::MailExchange {
                        display: "mail.example".to_string()
                    }
                },
            ]
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

        // THEN every SOA field is labeled, with the primary server carrying
        // the trailing-dot-stripped host.
        assert_eq!(
            fields,
            vec![
                RdataField {
                    label: "Primary Server",
                    value: RdataValue::PrimaryServer {
                        display: "ns1.example".to_string()
                    }
                },
                RdataField {
                    label: "Responsible Person",
                    value: RdataValue::ResponsibleEmail {
                        display: "admin@example".to_string()
                    }
                },
                text("Serial", "2026010101"),
                text("Refresh", "7200"),
                text("Retry", "3600"),
                text("Expire", "1209600"),
                text("Minimum", "3600"),
            ]
        );
    }

    #[test]
    fn rname_to_email_maps_first_label_to_local_part() {
        // GIVEN an SOA rname in DNS mailbox form
        // WHEN converted
        let email = rname_to_email(&name("admin.example.com."));
        // THEN the first label is the local part and the rest is the domain.
        assert_eq!(email, Some("admin@example.com".to_string()));
    }

    #[test]
    fn rname_to_email_keeps_escaped_dot_in_local_part() {
        // GIVEN an rname whose local part carries an escaped dot
        // WHEN converted
        let email = rname_to_email(&name("email\\.name.example.com."));
        // THEN the escaped dot becomes a literal dot in the local part.
        assert_eq!(email, Some("email.name@example.com".to_string()));
    }

    #[test]
    fn rname_to_email_joins_multi_label_domain() {
        // GIVEN an rname with a multi-label domain after the local part
        // WHEN converted
        let email = rname_to_email(&name("host.admin.example.com."));
        // THEN all remaining labels form the domain.
        assert_eq!(email, Some("host@admin.example.com".to_string()));
    }

    #[test]
    fn rname_to_email_root_is_none() {
        // GIVEN the root name (no labels)
        // WHEN converted
        let email = rname_to_email(&Name::root());
        // THEN there is no email address.
        assert_eq!(email, None);
    }

    #[test]
    fn rname_to_email_single_label_is_none() {
        // GIVEN an rname with only a local part and no domain
        // WHEN converted
        let email = rname_to_email(&name("admin."));
        // THEN there is no email address (no domain to append).
        assert_eq!(email, None);
    }

    #[test]
    fn responsible_person_field_falls_back_to_text_for_single_label() {
        // GIVEN an SOA rname that cannot form an email
        // WHEN the field is built
        let field = responsible_person_field("Responsible Person", &name("admin."));
        // THEN it falls back to plain text with the raw presentation form.
        assert_eq!(field, text("Responsible Person", "admin."));
    }

    #[test]
    fn responsible_person_field_falls_back_to_text_for_root() {
        // GIVEN the root rname (no labels)
        // WHEN the field is built
        let field = responsible_person_field("Responsible Person", &Name::root());
        // THEN it falls back to plain text with the root presentation form.
        assert_eq!(field, text("Responsible Person", "."));
    }

    #[test]
    fn rname_to_email_is_lossy_for_invalid_utf8() {
        // GIVEN an rname whose local part carries an invalid UTF-8 byte
        let rname = Name::from_labels(vec![
            [0xffu8, 0x61].as_slice(),
            b"example".as_slice(),
            b"com".as_slice(),
        ])
        .expect("rname");
        // WHEN converted
        let email = rname_to_email(&rname);
        // THEN the invalid byte is replaced with the replacement character.
        assert_eq!(email, Some("\u{FFFD}a@example.com".to_string()));
    }

    #[test]
    fn rdata_fields_srv_returns_all_srv_fields() {
        // GIVEN an SRV record's rdata
        let rdata = RData::SRV(SRV::new(10, 20, 443, name("svc.example.")));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN priority, weight and port are plain text and the target is a
        // ServiceTarget field with the trailing dot stripped.
        assert_eq!(
            fields,
            vec![
                text("Priority", "10"),
                text("Weight", "20"),
                text("Port", "443"),
                RdataField {
                    label: "Target",
                    value: RdataValue::ServiceTarget {
                        display: "svc.example".to_string()
                    }
                },
            ]
        );
    }

    #[test]
    fn rdata_fields_caa_returns_all_caa_fields() {
        // GIVEN a CAA record's rdata
        let rdata = RData::CAA(CAA::new_issue(true, Some(name("ca.example.")), Vec::new()));

        // WHEN fields are extracted
        let fields = rdata_fields(&rdata);

        // THEN the CAA flag, tag and value are separate fields, with the
        // issuer value classified as a CaaIssuer host (trailing dot
        // stripped).
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], text("Issuer Critical", "true"));
        assert_eq!(fields[1], text("Reserved Flags", "0"));
        assert_eq!(fields[2], text("Tag", "issue"));
        assert_eq!(
            fields[3],
            RdataField {
                label: "Value",
                value: RdataValue::CaaIssuer {
                    display: "ca.example".to_string()
                }
            }
        );
    }

    #[test]
    fn caa_value_field_classifies_ldh_host_as_issuer() {
        // GIVEN a CAA value that is a bare LDH host name
        // WHEN classified
        let field = caa_value_field("Value", b"ca.example.net");
        // THEN it is a CaaIssuer with the value unchanged.
        assert_eq!(
            field,
            RdataField {
                label: "Value",
                value: RdataValue::CaaIssuer {
                    display: "ca.example.net".to_string()
                }
            }
        );
    }

    #[test]
    fn caa_value_field_strips_trailing_dot_from_issuer() {
        // GIVEN a CAA value carrying a trailing dot
        // WHEN classified
        let field = caa_value_field("Value", b"ca.example.net.");
        // THEN the display host has no trailing dot.
        assert_eq!(
            field.value,
            RdataValue::CaaIssuer {
                display: "ca.example.net".to_string()
            }
        );
    }

    #[test]
    fn caa_value_field_classifies_mailto_as_email() {
        // GIVEN a CAA iodef value that is a mailto URI
        // WHEN classified
        let field = caa_value_field("Value", b"mailto:security@example.com");
        // THEN it is a CaaEmail carrying the bare address.
        assert_eq!(
            field.value,
            RdataValue::CaaEmail {
                display: "security@example.com".to_string()
            }
        );
    }

    #[test]
    fn caa_value_field_mailto_is_case_insensitive() {
        // GIVEN a mailto URI with an uppercase scheme
        // WHEN classified
        let field = caa_value_field("Value", b"MAILTO:Alerts@Example.COM");
        // THEN the address is still extracted with its case preserved.
        assert_eq!(
            field.value,
            RdataValue::CaaEmail {
                display: "Alerts@Example.COM".to_string()
            }
        );
    }

    #[test]
    fn caa_value_field_drops_mailto_query_params() {
        // GIVEN a mailto URI with a subject parameter
        // WHEN classified
        let field = caa_value_field("Value", b"mailto:report@example.com?subject=CAA");
        // THEN only the address before the `?` is kept.
        assert_eq!(
            field.value,
            RdataValue::CaaEmail {
                display: "report@example.com".to_string()
            }
        );
    }

    #[test]
    fn caa_value_field_non_host_non_mailto_stays_text() {
        // GIVEN a CAA value that is neither a host nor a mailto URI
        // WHEN classified
        let field = caa_value_field("Value", b"https://iodef.example.com/");
        // THEN it stays plain Text.
        assert_eq!(field, text("Value", "https://iodef.example.com/"));
    }

    #[test]
    fn caa_value_field_issue_with_params_stays_text() {
        // GIVEN an issue value carrying a `;` parameter (not a bare host)
        // WHEN classified
        let field = caa_value_field("Value", b"ca.example.net; account=230123");
        // THEN it stays plain Text (strict whole-value check).
        assert_eq!(field, text("Value", "ca.example.net; account=230123"));
    }

    #[test]
    fn caa_value_field_empty_value_is_empty_text() {
        // GIVEN an empty CAA value
        // WHEN classified
        let field = caa_value_field("Value", b"");
        // THEN it is empty Text.
        assert_eq!(field, text("Value", ""));
    }

    #[test]
    fn caa_value_field_double_trailing_dot_is_text() {
        // GIVEN a value with a doubled trailing dot (not a valid host)
        // WHEN classified
        let field = caa_value_field("Value", b"ca.example.net..");
        // THEN it is plain Text rather than a host with a stray dot.
        assert_eq!(field, text("Value", "ca.example.net.."));
    }

    #[test]
    fn caa_value_field_single_label_is_text() {
        // GIVEN a single-label value (is_ldh_hostname needs two labels)
        // WHEN classified
        let field = caa_value_field("Value", b"localhost");
        // THEN it is plain Text.
        assert_eq!(field, text("Value", "localhost"));
    }

    #[test]
    fn caa_value_field_mailto_drops_fragment() {
        // GIVEN a mailto URI with a `#` fragment
        // WHEN classified
        let field = caa_value_field("Value", b"mailto:report@example.com#frag");
        // THEN only the address before the `#` is kept.
        assert_eq!(
            field.value,
            RdataValue::CaaEmail {
                display: "report@example.com".to_string()
            }
        );
    }

    #[test]
    fn caa_value_field_mailto_without_at_is_text() {
        // GIVEN a mailto value that is not an address (no `@`)
        // WHEN classified
        let field = caa_value_field("Value", b"mailto:hello");
        // THEN it falls through to plain Text.
        assert_eq!(field, text("Value", "mailto:hello"));
    }

    #[test]
    fn caa_value_field_bare_mailto_is_text() {
        // GIVEN a bare `mailto:` with no address
        // WHEN classified
        let field = caa_value_field("Value", b"mailto:");
        // THEN it falls through to plain Text.
        assert_eq!(field, text("Value", "mailto:"));
    }

    #[test]
    fn caa_value_field_invalid_utf8_is_lossy_text() {
        // GIVEN a CAA value with an invalid UTF-8 byte
        // WHEN classified
        let field = caa_value_field("Value", &[0xff, 0x41]);
        // THEN the invalid byte is replaced and the value stays plain Text.
        assert_eq!(field, text("Value", "\u{FFFD}A"));
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
}
