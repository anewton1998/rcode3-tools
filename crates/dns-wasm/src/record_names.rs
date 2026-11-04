//! Formal (human-readable) names for DNS record-type mnemonics, per the
//! defining RFCs.
//!
//! Shared by the record-type dropdown (which works from the mnemonic `code`)
//! and the results panel (which derives the mnemonic from
//! `RecordType::to_string()`). Keying on the mnemonic string keeps a single
//! source of truth for both surfaces.

/// Formal name for a record-type mnemonic, or `None` when no curated formal
/// name is known.
///
/// Covers the dropdown's offered types plus the common response-only types
/// (DNSSEC and service-binding records) that appear in a response's
/// Authority/Additional sections. Two types are intentionally absent:
/// `DLV` is not modelled by `hickory-proto` 0.26 (it surfaces as an
/// unknown type), and the EDNS0 `OPT` pseudo-record is lifted into
/// `message.edns` rather than the record tables (and is not parseable as a
/// `RecordType`), so neither can ever match a curated key here.
pub(crate) fn formal_record_name(code: &str) -> Option<&'static str> {
    match code {
        // Dropdown types.
        "A" => Some("Address"),
        "AAAA" => Some("IPv6 Address"),
        "CNAME" => Some("Canonical Name"),
        "NS" => Some("Name Server"),
        "PTR" => Some("Pointer"),
        "SOA" => Some("Start of Authority"),
        "MX" => Some("Mail Exchange"),
        "TXT" => Some("Text"),
        "SRV" => Some("Service Location"),
        "NAPTR" => Some("Naming Authority Pointer"),
        "CAA" => Some("Certification Authority Authorization"),
        "DNSKEY" => Some("DNS Public Key"),
        "DS" => Some("Delegation Signer"),
        "SSHFP" => Some("SSH Fingerprint"),
        "TLSA" => Some("TLSA Certificate Association"),
        // Common response-only types (DNSSEC / service binding).
        "RRSIG" => Some("Resource Record Signature"),
        "NSEC" => Some("Next Secure"),
        "NSEC3" => Some("Next Secure v3"),
        "HTTPS" => Some("HTTPS Service Binding"),
        "SVCB" => Some("Service Binding"),
        _ => None,
    }
}

/// Display label for a record-type mnemonic: `"Formal Name (MNEMONIC)"` when
/// a formal name is curated, otherwise `"Unknown (MNEMONIC)"`.
///
/// The literal `"Unknown"` mnemonic (produced by `hickory_proto`'s
/// `RecordType::Unknown` display) and the empty string are returned unwrapped
/// so the results panel never renders a doubled `"Unknown (Unknown)"`.
pub(crate) fn record_type_label(code: &str) -> String {
    match formal_record_name(code) {
        Some(formal) => format!("{formal} ({code})"),
        None if code == "Unknown" || code.is_empty() => code.to_string(),
        None => format!("Unknown ({code})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formal_record_name_covers_dropdown_and_response_types() {
        // GIVEN the curated mnemonics
        // WHEN looked up
        // THEN each maps to its formal name.
        assert_eq!(formal_record_name("A"), Some("Address"));
        assert_eq!(formal_record_name("MX"), Some("Mail Exchange"));
        assert_eq!(
            formal_record_name("TLSA"),
            Some("TLSA Certificate Association")
        );
        assert_eq!(
            formal_record_name("RRSIG"),
            Some("Resource Record Signature")
        );
        assert_eq!(formal_record_name("NSEC3"), Some("Next Secure v3"));
    }

    #[test]
    fn formal_record_name_returns_none_for_uncurated() {
        // GIVEN a real mnemonic with no curated formal name
        // WHEN looked up
        // THEN it is reported as uncurated.
        assert_eq!(formal_record_name("AFSDB"), None);
        assert_eq!(formal_record_name(""), None);
    }

    #[test]
    fn record_type_label_wraps_formal_name_around_mnemonic() {
        // GIVEN a curated mnemonic
        // WHEN labelled
        // THEN it reads "Formal (MNEMONIC)".
        assert_eq!(record_type_label("A"), "Address (A)");
        assert_eq!(record_type_label("MX"), "Mail Exchange (MX)");
    }

    #[test]
    fn record_type_label_falls_back_to_unknown() {
        // GIVEN an uncurated mnemonic
        // WHEN labelled
        // THEN it reads "Unknown (MNEMONIC)".
        assert_eq!(record_type_label("AFSDB"), "Unknown (AFSDB)");
    }

    #[test]
    fn record_type_label_does_not_double_the_unknown() {
        // GIVEN the literal "Unknown" display of RecordType::Unknown, or empty
        // WHEN labelled
        // THEN it is returned unwrapped (no "Unknown (Unknown)").
        assert_eq!(record_type_label("Unknown"), "Unknown");
        assert_eq!(record_type_label(""), "");
    }

    #[test]
    fn curated_codes_round_trip_through_hickory_display() {
        // The results panel derives its mnemonic from `RecordType`'s Display,
        // while the map keys are hand-written. This locks the two together so
        // a hickory upgrade that renames a mnemonic fails loudly. Mirrors the
        // keys in `formal_record_name`.
        use hickory_proto::rr::RecordType;
        const CURATED: &[&str] = &[
            "A", "AAAA", "CNAME", "NS", "PTR", "SOA", "MX", "TXT", "SRV", "NAPTR", "CAA", "DNSKEY",
            "DS", "SSHFP", "TLSA", "RRSIG", "NSEC", "NSEC3", "HTTPS", "SVCB",
        ];
        // GIVEN each curated code
        // WHEN parsed as a RecordType and re-displayed
        // THEN the mnemonic matches the map key exactly.
        for code in CURATED {
            let record_type: RecordType = code
                .parse()
                .unwrap_or_else(|_| panic!("curated code {code} must parse"));
            assert_eq!(
                record_type.to_string(),
                *code,
                "hickory Display diverged from curated key {code}"
            );
            assert!(
                formal_record_name(code).is_some(),
                "{code} is in the round-trip list but not curated"
            );
        }
    }
}
