//! Integration tests for the RDAP result store (inet round-trip + latest-per-
//! address upsert), against a real Postgres via `db::testutil`.
//! Run with `cargo test -p db --features testutil`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use db::results::{self, RdapResult};
use db::testutil::fresh_db;

#[tokio::test]
async fn upsert_then_get_roundtrips_an_ipv4() {
    // GIVEN a fresh database
    let ctx = fresh_db().await;
    let addr: IpAddr = "192.0.2.10".parse().unwrap();
    // WHEN a result is upserted and read back
    results::upsert_rdap_result(
        &ctx.db,
        addr,
        "arin",
        Some(42),
        Some("https://rdap.example/ip/192.0.2.10"),
        r#"{"objectClassName":"ip network"}"#,
        Some("https://example.com/geo.csv"),
        Some(b"prefix,geo\n"),
    )
    .await
    .expect("upsert");
    let got = results::get_rdap_result(&ctx.db, addr)
        .await
        .expect("get")
        .expect("present");
    // THEN the inet column round-trips to the same address and fields persist
    assert_eq!(got.address, addr);
    assert_eq!(got.registry, "arin");
    assert_eq!(got.job_id, Some(42));
    assert_eq!(
        got.geofeed_href.as_deref(),
        Some("https://example.com/geo.csv")
    );
    assert_eq!(got.geofeed_csv.as_deref(), Some(&b"prefix,geo\n"[..]));
}

#[tokio::test]
async fn upsert_roundtrips_an_ipv6() {
    // GIVEN a fresh database
    let ctx = fresh_db().await;
    let addr: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    // WHEN a v6 result is stored and read back
    results::upsert_rdap_result(&ctx.db, addr, "ripencc", None, None, "{}", None, None)
        .await
        .expect("upsert v6");
    let got = results::get_rdap_result(&ctx.db, addr)
        .await
        .expect("get")
        .expect("present");
    // THEN the address survives the inet round-trip
    assert_eq!(got.address, addr);
    assert_eq!(got.registry, "ripencc");
}

#[tokio::test]
async fn upsert_overwrites_latest_per_address() {
    // GIVEN an address that already has a stored result
    let ctx = fresh_db().await;
    let addr: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
    results::upsert_rdap_result(
        &ctx.db,
        addr,
        "old-reg",
        Some(1),
        None,
        r#"{"v":1}"#,
        None,
        None,
    )
    .await
    .expect("first upsert");
    // WHEN the same address is upserted again with new data
    results::upsert_rdap_result(
        &ctx.db,
        addr,
        "new-reg",
        Some(2),
        Some("https://new/url"),
        r#"{"v":2}"#,
        None,
        None,
    )
    .await
    .expect("second upsert");
    // THEN there is still exactly one row and it reflects the latest write
    let got: RdapResult = results::get_rdap_result(&ctx.db, addr)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(got.registry, "new-reg");
    assert_eq!(got.job_id, Some(2));
    assert_eq!(got.request_url.as_deref(), Some("https://new/url"));
    // jsonb normalises whitespace, so assert on content rather than exact text:
    // the new body (value 2) replaced the old one (value 1).
    assert!(got.response.contains('2'), "expected the new body: {got:?}");
    assert!(
        !got.response.contains('1'),
        "old body should be gone: {got:?}"
    );
}

#[tokio::test]
async fn get_missing_returns_none() {
    // GIVEN a fresh database
    let ctx = fresh_db().await;
    // WHEN an unknown address is looked up
    let got = results::get_rdap_result(&ctx.db, "198.51.100.9".parse().unwrap())
        .await
        .expect("get");
    // THEN nothing is returned
    assert!(got.is_none());
}
