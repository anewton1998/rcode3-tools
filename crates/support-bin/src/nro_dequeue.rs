//! Dequeue pipeline for the `nro-dequeue` support binary.
//!
//! Drains the durable Postgres job queue produced by `nro-enqueue` and, for
//! every IP delegation record, issues an RDAP query through `icann-rdap-client`
//! (resolved via the IANA bootstrap), UPSERTs the JSON response into
//! [`db::results`], and — when the response advertises an RFC 9877 *geofeed*
//! link — downloads that geofeed and stores it alongside.
//!
//! Design notes:
//! - **DB-backed, at-least-once.** Work is claimed with
//!   [`queue::claim_one_per_partition`], which takes a lease and uses
//!   `FOR UPDATE SKIP LOCKED`. A crashed worker's in-flight rows become
//!   reclaimable once their lease lapses, and multiple consumers can run safely.
//! - **AS-number records are discarded.** A record whose type field is
//!   `asn`/`autnum` is not an IP resource, so it is dropped (counted as
//!   `discarded_asn`). Only `ipv4`/`ipv6` records are queried.
//! - **Round-robin + rate limiting.** The claim returns one record per registry
//!   each round (rotating so no tail registry starves), so registries interleave;
//!   the in-memory [`HostRateLimiter`] additionally spaces queries by
//!   `min_interval`, keyed on the registry name — which maps 1:1 to the RDAP
//!   host in practice (the geofeed host is tracked under its own key).
//! - **Dry-run restores the queue.** It claims (to exercise scheduling), counts,
//!   and then releases every claimed row back to `pending` with its `attempts`
//!   restored — no network, no stores.
//! - **Errors are per-item.** A failed query/store is logged and counted as
//!   `failed` and the row is retried with backoff until `max_attempts`; the run
//!   continues so a long drain is not aborted by one bad record.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use db::{Db, queue, results};
use icann_rdap_client::http::Client as RdapClient;
use icann_rdap_client::prelude::{MemoryBootstrapStore, QueryType, rdap_bootstrapped_request};
use icann_rdap_common::prelude::RdapResponse;
use thiserror::Error;

use crate::nro::should_skip_line;
use crate::nro_queue::NRO_TOPIC;

/// The RFC 9877 link relation type that marks a geofeed link.
const GEOFEED_REL: &str = "geofeed";

/// Errors that abort the whole dequeue run (as opposed to per-item failures,
/// which are logged, counted and retried).
#[derive(Debug, Error)]
pub enum DequeueError {
    /// A queue read/claim/mark operation failed.
    #[error("database error: {0}")]
    Db(#[from] db::DbError),
}

/// Running counts for a single dequeue pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DequeueStats {
    /// IP records that reached the query stage.
    pub processed: usize,
    /// RDAP queries that returned successfully.
    pub queried: usize,
    /// RDAP result rows stored.
    pub saved: usize,
    /// Geofeed files downloaded and stored.
    pub geofeeds: usize,
    /// AS-number (`asn`/`autnum`) records discarded.
    pub discarded_asn: usize,
    /// Serial / summary / iana records skipped.
    pub skipped: usize,
    /// Items that failed at the query/store stage.
    pub failed: usize,
}

/// What a queued line resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemKind {
    /// Not a queryable IP record (serial / summary / iana / malformed).
    Skip,
    /// An AS-number record — discarded, never queried.
    Asn,
    /// An IPv4 or IPv6 delegation record.
    Ip {
        /// The RIR registry field (rate-limit / bucket key).
        registry: String,
        /// The start address parsed from the record.
        addr: IpAddr,
    },
}

/// Classify one pipe-delimited NRO record into a [`ItemKind`].
///
/// Field layout (extended stats): `registry|country|type|start|count|…`, so
/// the type is field 2 and the start address is field 3.
pub fn classify_line(line: &str) -> ItemKind {
    if should_skip_line(line) {
        return ItemKind::Skip;
    }
    let fields: Vec<&str> = line.split('|').collect();
    if fields.len() < 4 {
        return ItemKind::Skip;
    }
    let registry = fields[0].to_string();
    match fields[2] {
        "asn" | "autnum" => ItemKind::Asn,
        "ipv4" => match fields[3].parse::<Ipv4Addr>() {
            Ok(addr) => ItemKind::Ip {
                registry,
                addr: IpAddr::V4(addr),
            },
            Err(_) => ItemKind::Skip,
        },
        "ipv6" => match fields[3].parse::<Ipv6Addr>() {
            Ok(addr) => ItemKind::Ip {
                registry,
                addr: IpAddr::V6(addr),
            },
            Err(_) => ItemKind::Skip,
        },
        _ => ItemKind::Skip,
    }
}

/// Extract the RFC 9877 geofeed URL from an RDAP response, if present.
///
/// Per RFC 9877 the geofeed is a link object with `rel = "geofeed"` on the
/// IP network object; the typed model preserves `links`, so no raw-JSON
/// scraping is needed.
pub fn geofeed_href(rdap: &RdapResponse) -> Option<String> {
    match rdap {
        RdapResponse::Network(network) => network
            .object_common
            .links
            .as_deref()?
            .iter()
            // Case-insensitive: RFC 9877 defines the lowercase `geofeed` rel,
            // but RDAP is JSON on the open internet.
            .find(|link| {
                link.rel
                    .as_deref()
                    .is_some_and(|rel| rel.eq_ignore_ascii_case(GEOFEED_REL))
            })
            .and_then(|link| link.href.clone()),
        _ => None,
    }
}

/// The host portion of a URL (scheme and path stripped).
fn host_of(url: &str) -> String {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Per-host minimum-interval rate limiter.
///
/// Tracks the last time each host was queried; [`wait_for`](Self::wait_for)
/// sleeps until the host is eligible again, then records the query time.
#[derive(Debug)]
pub struct HostRateLimiter {
    min_interval: Duration,
    last_queried: HashMap<String, Instant>,
}

impl HostRateLimiter {
    /// Create a limiter with the given minimum interval between queries to the
    /// same host.
    pub fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            last_queried: HashMap::new(),
        }
    }

    /// The instant at which `host` next becomes eligible to be queried.
    ///
    /// A never-queried host is eligible immediately (returns `now`).
    pub fn next_allowed(&self, host: &str) -> Instant {
        match self.last_queried.get(host) {
            Some(last) => *last + self.min_interval,
            None => Instant::now(),
        }
    }

    /// Sleep until `host` is eligible, then mark it as queried now.
    pub async fn wait_for(&mut self, host: &str) {
        let next = self.next_allowed(host);
        let now = Instant::now();
        if now < next {
            tokio::time::sleep(next - now).await;
        }
        self.last_queried.insert(host.to_string(), Instant::now());
    }
}

/// Tunables for a dequeue run.
pub struct DequeueConfig {
    /// Minimum interval between queries to the same host.
    pub min_interval: Duration,
    /// How long a claimed job's lease is held before it becomes reclaimable.
    pub lease: Duration,
    /// Attempts allowed before a failing job goes terminal `failed`.
    pub max_attempts: i32,
    /// Backoff applied when a failed job is requeued (its next-claim lease).
    pub retry_backoff: Duration,
    /// Max jobs claimed per round (one per partition, up to this cap).
    pub claim_batch: i64,
    /// When `true`, skip all network + stores (exercise scheduling only).
    pub dry_run: bool,
    /// Stop after processing this many IP records (caps a run for testing; the
    /// rest of the queue is left pending). `None` = drain all.
    pub max_items: Option<usize>,
}

/// Drain the queue and process every IP record round-robin by registry.
///
/// See the module docs for the claim / rate-limiting / dry-run model.
///
/// # Errors
///
/// Returns [`DequeueError::Db`] if a queue read/claim/mark fails. Per-item RDAP
/// or store failures do **not** abort the run; they are logged, counted in
/// [`DequeueStats::failed`] and retried with backoff.
pub async fn dequeue_all(
    db: &Db,
    client: &RdapClient,
    store: &MemoryBootstrapStore,
    geofeed_client: &reqwest::Client,
    config: &DequeueConfig,
) -> Result<DequeueStats, DequeueError> {
    let mut stats = DequeueStats::default();
    let mut limiter = HostRateLimiter::new(config.min_interval);
    // Rotating cursor: the last partition served, so the claim's cut-off advances
    // each round and no tail partition starves when `claim_batch` is small.
    let mut start_after: Option<String> = None;
    // Jobs claimed but left unfinished (dry-run, or beyond `max_items`). They are
    // released only AFTER the loop: during the loop every claimed row stays
    // `running`, so the loop keeps draining instead of re-claiming them.
    let mut to_release: Vec<i64> = Vec::new();

    loop {
        let jobs = queue::claim_one_per_partition(
            db,
            NRO_TOPIC,
            config.claim_batch,
            config.lease,
            start_after.as_deref(),
        )
        .await?;
        if jobs.is_empty() {
            break;
        }
        // Advance the cursor to the last partition served this round.
        start_after = jobs.last().map(|j| j.partition_key.clone());

        for job in jobs {
            if config.max_items.is_some_and(|max| stats.processed >= max) {
                to_release.push(job.id);
                continue;
            }

            match classify_line(&job.payload) {
                ItemKind::Skip => {
                    stats.skipped += 1;
                    finalize_or_release(db, job.id, config.dry_run, &mut to_release).await?;
                }
                ItemKind::Asn => {
                    stats.discarded_asn += 1;
                    finalize_or_release(db, job.id, config.dry_run, &mut to_release).await?;
                }
                ItemKind::Ip { registry, addr } => {
                    stats.processed += 1;
                    if config.dry_run {
                        tracing::info!(%addr, "dry-run: would query RDAP");
                        to_release.push(job.id);
                        continue;
                    }
                    limiter.wait_for(&registry).await;
                    // The rate-limit wait + geofeed download can be slow; renew
                    // the lease so this row isn't re-claimed mid-processing.
                    queue::renew_lease(db, job.id, config.lease).await?;
                    match process_item(
                        db,
                        job.id,
                        addr,
                        &registry,
                        client,
                        store,
                        geofeed_client,
                        &mut limiter,
                        &mut stats,
                    )
                    .await
                    {
                        Ok(()) => queue::mark_done(db, job.id).await?,
                        Err(err) => {
                            stats.failed += 1;
                            let outcome = queue::mark_failed(
                                db,
                                job.id,
                                config.max_attempts,
                                config.retry_backoff,
                                &err.to_string(),
                            )
                            .await?;
                            match outcome {
                                queue::JobOutcome::Requeued => {
                                    tracing::warn!(%registry, error = %err, "item failed, will retry");
                                }
                                queue::JobOutcome::Failed => {
                                    tracing::error!(%registry, error = %err, "item failed permanently");
                                }
                            }
                        }
                    }
                }
            }
        }

        if config.max_items.is_some_and(|max| stats.processed >= max) {
            break;
        }
    }

    // Release the unfinished rows in bounded chunks (a full-file dry-run can
    // accumulate a very large id list).
    for chunk in to_release.chunks(RELEASE_CHUNK) {
        queue::release(db, chunk).await?;
    }
    Ok(stats)
}

/// Max ids passed to a single [`queue::release`] call, to keep the
/// `id = ANY($1)` array bounded.
const RELEASE_CHUNK: usize = 1000;

/// In a real run a non-IP row is marked done; in dry-run it is released so the
/// queue is left unchanged.
async fn finalize_or_release(
    db: &Db,
    id: i64,
    dry_run: bool,
    to_release: &mut Vec<i64>,
) -> Result<(), DequeueError> {
    if dry_run {
        to_release.push(id);
    } else {
        queue::mark_done(db, id).await?;
    }
    Ok(())
}

/// Query RDAP for one IP record, store the response, and fetch any geofeed.
#[allow(clippy::too_many_arguments)]
async fn process_item(
    db: &Db,
    job_id: i64,
    addr: IpAddr,
    registry: &str,
    client: &RdapClient,
    store: &MemoryBootstrapStore,
    geofeed_client: &reqwest::Client,
    limiter: &mut HostRateLimiter,
    stats: &mut DequeueStats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let query = match addr {
        IpAddr::V4(v4) => QueryType::IpV4Addr(v4),
        IpAddr::V6(v6) => QueryType::IpV6Addr(v6),
    };

    let response = rdap_bootstrapped_request(&query, client, store, |_| {}).await?;
    stats.queried += 1;

    // Fall back to an address-keyed pseudo-URL if the client did not record the
    // request URI, so the stored row stays attributable to the address.
    let url = response
        .http_data
        .request_uri
        .clone()
        .unwrap_or_else(|| format!("unknown/{addr}"));
    let json = serde_json::to_string(&response.rdap)?;

    let href = geofeed_href(&response.rdap);
    let mut csv: Option<Vec<u8>> = None;
    if let Some(href) = href.as_deref() {
        limiter.wait_for(&host_of(href)).await;
        let bytes = geofeed_client.get(href).send().await?.bytes().await?;
        stats.geofeeds += 1;
        csv = Some(bytes.to_vec());
    }

    results::upsert_rdap_result(
        db,
        addr,
        registry,
        Some(job_id),
        Some(&url),
        &json,
        href.as_deref(),
        csv.as_deref(),
    )
    .await?;
    stats.saved += 1;
    tracing::info!(%url, %addr, "rdap result stored");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_resolves_ip_records() {
        // GIVEN an ipv4 and an ipv6 delegation record
        let v4 = "apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A91872ED|e-stats";
        let v6 = "ripencc|DE|ipv6|2001:db8::|32|20100101|assigned|abc|e-stats";
        // WHEN classified
        // THEN each yields an Ip item with the registry and start address
        assert_eq!(
            classify_line(v4),
            ItemKind::Ip {
                registry: "apnic".to_string(),
                addr: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)),
            }
        );
        assert_eq!(
            classify_line(v6),
            ItemKind::Ip {
                registry: "ripencc".to_string(),
                addr: IpAddr::V6("2001:db8::".parse().unwrap()),
            }
        );
    }

    #[test]
    fn classify_discards_asn_and_autnum() {
        // GIVEN AS-number records under both spellings
        // WHEN classified
        // THEN both are discarded (never queried)
        assert_eq!(
            classify_line("arin|US|asn|1|1|20010920|assigned|e5|e-stats"),
            ItemKind::Asn
        );
        assert_eq!(
            classify_line("ripencc|EU|autnum|7|1|19930901|assigned|x|e-stats"),
            ItemKind::Asn
        );
    }

    #[test]
    fn classify_skips_non_ip_and_malformed() {
        // GIVEN serial / summary / iana / short / bad-address lines
        // WHEN classified
        // THEN all are Skip
        assert_eq!(
            classify_line("2|nro|20261108|775178|19821213|20261108|+0000"),
            ItemKind::Skip
        );
        assert_eq!(classify_line("nro|*|ipv4|*|271419|summary"), ItemKind::Skip);
        assert_eq!(
            classify_line("iana|ZZ|ipv4|0.0.0.0|16777216|19810901|reserved|ietf|iana"),
            ItemKind::Skip
        );
        assert_eq!(classify_line("arin|US|ipv4"), ItemKind::Skip);
        assert_eq!(
            classify_line("arin|US|ipv4|not-an-ip|24|20010101|assigned|x|e-stats"),
            ItemKind::Skip
        );
    }

    #[test]
    fn host_of_extracts_the_authority() {
        // GIVEN URLs with and without a scheme, with a path
        // WHEN the host is extracted
        assert_eq!(
            host_of("https://rdap.arin.net/registry/ip/1.0.0.0"),
            "rdap.arin.net"
        );
        assert_eq!(host_of("example.com/a/b"), "example.com");
        assert_eq!(host_of("https://h.example/p?x=1#f"), "h.example");
    }

    #[test]
    fn geofeed_href_reads_the_geofeed_link_from_a_network_response() {
        // GIVEN an RDAP ip-network response carrying a geofeed link
        let json = r#"{
            "objectClassName": "ip network",
            "handle": "TEST-RIR",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "v4",
            "links": [
                {"value": "https://x/ip/192.0.2.0", "rel": "self", "href": "https://x/ip/192.0.2.0", "type": "application/rdap+json"},
                {"value": "https://x/ip/192.0.2.0", "rel": "geofeed", "href": "https://example.com/geo.csv", "type": "application/geofeed+csv"}
            ]
        }"#;
        let rdap: RdapResponse = serde_json::from_str(json).expect("parse rdap");
        // WHEN the geofeed href is extracted
        // THEN it is the geofeed link's href
        assert_eq!(
            geofeed_href(&rdap).as_deref(),
            Some("https://example.com/geo.csv")
        );
    }

    #[test]
    fn geofeed_href_is_none_without_a_geofeed_link() {
        // GIVEN a network response with only a self link
        let json = r#"{
            "objectClassName": "ip network",
            "handle": "TEST-RIR",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "ipVersion": "v4",
            "links": [
                {"value": "https://x/ip/192.0.2.0", "rel": "self", "href": "https://x/ip/192.0.2.0", "type": "application/rdap+json"}
            ]
        }"#;
        let rdap: RdapResponse = serde_json::from_str(json).expect("parse rdap");
        // WHEN extracted
        // THEN there is no geofeed
        assert_eq!(geofeed_href(&rdap), None);
    }

    #[tokio::test]
    async fn rate_limiter_spaces_consecutive_queries_by_the_interval() {
        // GIVEN a limiter with a 50 ms interval
        let mut limiter = HostRateLimiter::new(Duration::from_millis(50));
        // WHEN the same host is queried twice back to back
        limiter.wait_for("h").await;
        let start = Instant::now();
        limiter.wait_for("h").await;
        // THEN the second wait was at least ~one interval
        assert!(
            start.elapsed() >= Duration::from_millis(45),
            "expected >= ~50ms spacing, got {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn rate_limiter_lets_unknown_hosts_through_immediately() {
        // GIVEN a fresh limiter
        let mut limiter = HostRateLimiter::new(Duration::from_secs(60));
        // WHEN an unknown host is waited on
        let start = Instant::now();
        limiter.wait_for("fresh").await;
        // THEN it did not block
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
