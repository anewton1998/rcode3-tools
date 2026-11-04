//! DNS-over-HTTPS (RFC 8484) query construction and transport.
//!
//! The DNS wire format comes from `hickory-proto`; the HTTPS transport is
//! `reqwest`, which uses the browser's `fetch` on wasm32 and hyper+rustls on
//! native. Queries are sent as `GET {server}?dns=<base64url>` with
//! `Accept: application/dns-message`, the wire-format equivalent of a stub
//! resolver asking for recursion.

use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};

/// Per-request timeout. reqwest's wasm backend enforces this via
/// `AbortController`, so a dead or captive DoH server cannot wedge the
/// browser's busy state indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// EDNS0 advertised response size. Without an OPT record servers assume a
/// 512-byte buffer and silently truncate large answers (DNSKEY, DS, NAPTR,
/// multi-string TXT) with `TC=1`. 4096 is the common DoH practice.
const MAX_RESPONSE_BYTES: u16 = 4096;

/// Shared HTTP client: one TLS config / connection pool on native, and a
/// single (cheap) fetch-backed client on wasm. The per-request timeout is
/// applied on the `RequestBuilder` (available on both targets) rather than
/// the client builder (native-only).
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .build()
            .expect("default reqwest client is infallible")
    })
}

/// Failures of a DoH lookup, in pipeline order.
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// The query name could not be parsed as a DNS name.
    #[error("invalid DNS name: {0}")]
    InvalidName(String),
    /// The DNS query message could not be encoded.
    #[error("failed to encode DNS query: {0}")]
    Encode(String),
    /// The HTTPS request failed or the server returned a non-success status.
    #[error("DoH transport error: {0}")]
    Transport(String),
    /// The response body was not a parseable DNS message.
    #[error("failed to decode DNS response: {0}")]
    Decode(String),
}

/// Builds a standard recursive DNS query for `name`/`record_type` and
/// returns its wire-format bytes.
pub fn build_query(name: &str, record_type: RecordType) -> Result<Vec<u8>, LookupError> {
    let name =
        Name::parse(name, None).map_err(|e| LookupError::InvalidName(format!("{name}: {e}")))?;
    let mut query = Query::new();
    query.name = name;
    query.query_type = record_type;
    query.query_class = DNSClass::IN;

    // `Message::query()` assigns a random 16-bit message id.
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    // EDNS0 OPT record so the server may return responses larger than the
    // 512-byte classic-DNS ceiling instead of truncating them.
    let mut edns = Edns::new();
    edns.set_max_payload(MAX_RESPONSE_BYTES);
    message.set_edns(edns);
    message.add_query(query);
    message
        .to_vec()
        .map_err(|e| LookupError::Encode(e.to_string()))
}

/// Asks `server` (a DoH endpoint, e.g. `https://cloudflare-dns.com/dns-query`)
/// for `name`/`record_type` and returns the parsed response message together
/// with the UTC instant the response body was received.
///
/// The `received` timestamp is the reference point for the record TTL
/// countdown (a record's `ttl` is relative to when the client received it),
/// so it is captured the moment the body arrives rather than at render time.
pub async fn query_doh(
    server: &str,
    name: &str,
    record_type: RecordType,
) -> Result<(Message, DateTime<Utc>), LookupError> {
    let query_bytes = build_query(name, record_type)?;
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(&query_bytes);
    let separator = if server.contains('?') { '&' } else { '?' };
    let url = format!("{server}{separator}dns={encoded}");

    let response = http_client()
        .get(&url)
        .timeout(REQUEST_TIMEOUT)
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .send()
        .await
        .map_err(|e| LookupError::Transport(e.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(LookupError::Transport(format!(
            "DoH server responded with HTTP {}",
            status.as_u16()
        )));
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| LookupError::Transport(e.to_string()))?;
    // Capture the receipt instant before parsing so the TTL countdown is
    // anchored to when the bytes actually arrived.
    let received = chrono::Utc::now();
    Message::from_vec(&body)
        .map(|message| (message, received))
        .map_err(|e| LookupError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};

    #[test]
    fn build_query_roundtrips_through_the_wire_format() {
        // GIVEN a name and record type
        // WHEN the query is built and re-parsed
        let bytes = build_query("example.com", RecordType::A).expect("build");
        let message = Message::from_vec(&bytes).expect("parse");
        // THEN it is a recursive IN/A query for the same name
        assert_eq!(message.metadata.message_type, MessageType::Query);
        assert_eq!(message.metadata.op_code, OpCode::Query);
        assert!(message.metadata.recursion_desired);
        assert_eq!(message.queries.len(), 1);
        assert_eq!(message.queries[0].name.to_string(), "example.com.");
        assert_eq!(message.queries[0].query_type, RecordType::A);
        assert_eq!(message.queries[0].query_class, DNSClass::IN);
    }

    #[test]
    fn build_query_advertises_edns0() {
        // GIVEN a built query
        let bytes = build_query("example.com", RecordType::DNSKEY).expect("build");
        let message = Message::from_vec(&bytes).expect("parse");
        // THEN it carries an OPT record with an enlarged payload so large
        // answers are not truncated to the 512-byte classic ceiling.
        let edns = message.edns.as_ref().expect("EDNS0 OPT record");
        assert!(edns.max_payload() >= 4096, "max_payload too small");
    }

    #[test]
    fn build_query_rejects_invalid_names() {
        // GIVEN a name that cannot be a DNS name
        // WHEN the query is built
        let result = build_query("not a valid name!", RecordType::A);
        // THEN it fails with the InvalidName variant
        assert!(matches!(result, Err(LookupError::InvalidName(_))));
    }

    #[tokio::test]
    async fn query_doh_resolves_a_real_name() {
        // GIVEN the public Cloudflare DoH endpoint
        // WHEN example.com/A is queried
        let before = Utc::now();
        let (message, received) = query_doh(
            "https://cloudflare-dns.com/dns-query",
            "example.com",
            RecordType::A,
        )
        .await
        .expect("doh lookup");
        let after = Utc::now();
        // THEN the response is a successful answer with at least one record
        assert_eq!(
            message.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert!(!message.answers.is_empty(), "expected an A record");
        assert_eq!(message.answers[0].record_type(), RecordType::A);
        // AND the received timestamp falls inside the call window (captured
        // at response receipt, not a default/epoch value).
        assert!(
            received >= before && received <= after,
            "received {received} outside call window [{before}, {after}]"
        );
    }
}
