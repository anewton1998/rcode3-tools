//! Dequeue pipeline for the `nro-dequeue` support binary.
//!
//! Drains the [`yaque`] queue produced by `nro-enqueue` and, for every IP
//! delegation record, issues an RDAP query through `icann-rdap-client`
//! (resolved via the IANA bootstrap), writes the JSON response to the work
//! directory, and — when the response advertises an RFC 9877 *geofeed* link —
//! downloads that geofeed file too.
//!
//! Design notes:
//! - **AS-number records are discarded.** A queued line whose type field is
//!   `asn`/`autnum` is not an IP resource, so it is dropped (counted as
//!   `discarded_asn`). Only `ipv4`/`ipv6` records are queried.
//! - **Rate limiting.** RDAP queries are rate limited **per registry** (each
//!   RIR maps to exactly one RDAP host, so this is effectively per-host for
//!   RDAP); geofeed downloads are rate limited by their own host. The queue
//!   is registry-grouped, so items are bucketed by registry and processed
//!   **round-robin** across buckets; this keeps every server progressing each
//!   interval instead of stalling on one registry's long run of consecutive
//!   records. (In the rare case a geofeed is served from the same host as its
//!   RIR's RDAP service, that host can see one RDAP + one geofeed request
//!   per interval — the two are tracked under different keys.)
//! - **Read-all-then-process.** A `yaque::RecvGuard` holds a *mutable* borrow
//!   of the receiver, so only one uncommitted item can exist at a time. To
//!   round-robin across the grouped input we therefore read the whole queue
//!   into owned `String`s (committing each as it is read) and then process the
//!   buckets. The crash window is the unread remainder; a run can be resumed
//!   by re-enqueueing (`nro-enqueue`) and starting again.
//! - **Filenames** mirror the query URL: the scheme is stripped and the
//!   `host/path…` becomes nested directories under the results dir, with a
//!   compact RFC 3339 stamp ([`STAMP_FORMAT`]) as the leaf file name.
//! - **Errors are per-item.** A failed query/save is logged and counted as
//!   `failed`; the run continues so a long drain is not aborted by one bad
//!   record. `failed` means "hit an error at some stage" — an item whose RDAP
//!   JSON saved but whose geofeed download failed is counted in both `saved`
//!   and `failed`, so `processed != queried + failed` in general.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Utc;
use icann_rdap_client::http::Client as RdapClient;
use icann_rdap_client::prelude::{MemoryBootstrapStore, QueryType, rdap_bootstrapped_request};
use icann_rdap_common::prelude::RdapResponse;
use thiserror::Error;
use yaque::Receiver;

use crate::nro::{STAMP_FORMAT, should_skip_line};

/// The RFC 9877 link relation type that marks a geofeed link.
const GEOFEED_REL: &str = "geofeed";

/// Errors that abort the whole dequeue run (as opposed to per-item failures,
/// which are logged and counted).
#[derive(Debug, Error)]
pub enum DequeueError {
    /// A yaque receive/commit operation failed.
    #[error("yaque queue error: {0}")]
    Queue(#[from] std::io::Error),
}

/// Running counts for a single dequeue pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DequeueStats {
    /// IP records that reached the query stage.
    pub processed: usize,
    /// RDAP queries that returned successfully.
    pub queried: usize,
    /// RDAP JSON response files written.
    pub saved: usize,
    /// Geofeed files downloaded and written.
    pub geofeeds: usize,
    /// AS-number (`asn`/`autnum`) records discarded.
    pub discarded_asn: usize,
    /// Serial / summary / iana records skipped.
    pub skipped: usize,
    /// Items that failed at the query/save stage.
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

/// Build the on-disk path for a saved artifact from its source URL.
///
/// The URL scheme is stripped and the remaining `host/path…` becomes nested
/// directories under `work_dir`, with `<stamp>.<ext>` as the leaf. For
/// example `("work/rdap-results", "https://rdap.arin.net/registry/ip/1.0.0.0",
/// "20261108T120000Z", "json")` yields
/// `work/rdap-results/rdap.arin.net/registry/ip/1.0.0.0/20261108T120000Z.json`.
pub fn result_path(work_dir: &Path, url: &str, stamp: &str, ext: &str) -> PathBuf {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let mut path = work_dir.to_path_buf();
    for segment in without_scheme.split('/').filter(|s| !s.is_empty()) {
        path = path.join(segment);
    }
    path.join(format!("{stamp}.{ext}"))
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
pub struct DequeueConfig<'a> {
    /// Directory the result files are written under.
    pub results_dir: &'a Path,
    /// Minimum interval between queries to the same host.
    pub min_interval: Duration,
    /// How long to wait for the next queued item before treating the queue as
    /// drained (yaque has no "producer finished" signal).
    pub idle_timeout: Duration,
    /// When `true`, skip all network + disk writes (exercise scheduling only).
    pub dry_run: bool,
    /// Stop after bucketing this many IP records (caps a run for testing; the
    /// rest of the queue is left unread and uncommitted). `None` = drain all.
    pub max_items: Option<usize>,
}

/// Drain `receiver` and process every IP record round-robin by registry.
///
/// See the module docs for the read-all-then-process and rate-limiting model.
///
/// # Errors
///
/// Returns [`DequeueError::Queue`] if a yaque receive/commit fails. Per-item
/// RDAP/save failures do **not** abort the run; they are logged and counted in
/// [`DequeueStats::failed`].
pub async fn dequeue_all(
    receiver: &mut Receiver,
    client: &RdapClient,
    store: &MemoryBootstrapStore,
    geofeed_client: &reqwest::Client,
    config: &DequeueConfig<'_>,
) -> Result<DequeueStats, DequeueError> {
    let mut stats = DequeueStats::default();

    // Phase 1 — read the whole queue into per-registry buckets, committing
    // each item as it is read (see module docs for why). A `max_items` cap
    // stops the read early, leaving the remainder queued and uncommitted.
    let mut buckets: HashMap<String, VecDeque<String>> = HashMap::new();
    let mut bucketed: usize = 0;
    loop {
        if config.max_items.is_some_and(|max| bucketed >= max) {
            break;
        }
        match tokio::time::timeout(config.idle_timeout, receiver.recv()).await {
            Ok(Ok(guard)) => {
                let line = String::from_utf8_lossy(&guard).into_owned();
                guard.commit()?;
                match classify_line(&line) {
                    ItemKind::Skip => stats.skipped += 1,
                    ItemKind::Asn => stats.discarded_asn += 1,
                    ItemKind::Ip { registry, .. } => {
                        buckets.entry(registry).or_default().push_back(line);
                        bucketed += 1;
                    }
                }
            }
            Ok(Err(err)) => return Err(DequeueError::Queue(err)),
            Err(_elapsed) => break,
        }
    }

    // Phase 2 — round-robin across registries, honouring the per-host
    // interval. The registry with the soonest next-allowed time is picked
    // each round, so no single registry monopolises the run.
    let mut limiter = HostRateLimiter::new(config.min_interval);
    loop {
        let next_registry = buckets
            .iter()
            .filter(|(_, queue)| !queue.is_empty())
            .min_by_key(|(registry, _)| limiter.next_allowed(registry))
            .map(|(registry, _)| registry.clone());
        let Some(registry) = next_registry else {
            break;
        };

        // In dry-run we exercise the bucketing / commit / counting path only,
        // so skip the rate-limit sleep (the limiter itself is unit-tested).
        if !config.dry_run {
            limiter.wait_for(&registry).await;
        }

        let Some(line) = buckets.get_mut(&registry).and_then(VecDeque::pop_front) else {
            continue;
        };

        stats.processed += 1;
        if let Err(err) = process_item(
            &line,
            client,
            store,
            geofeed_client,
            config,
            &mut limiter,
            &mut stats,
        )
        .await
        {
            tracing::warn!(%registry, error = %err, "item failed");
            stats.failed += 1;
        }
    }

    Ok(stats)
}

/// Query RDAP for one IP record, save the response, and fetch any geofeed.
async fn process_item(
    line: &str,
    client: &RdapClient,
    store: &MemoryBootstrapStore,
    geofeed_client: &reqwest::Client,
    config: &DequeueConfig<'_>,
    limiter: &mut HostRateLimiter,
    stats: &mut DequeueStats,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ItemKind::Ip { addr, .. } = classify_line(line) else {
        return Ok(());
    };
    let query = match addr {
        IpAddr::V4(v4) => QueryType::IpV4Addr(v4),
        IpAddr::V6(v6) => QueryType::IpV6Addr(v6),
    };

    if config.dry_run {
        tracing::info!(%addr, "dry-run: would query RDAP");
        return Ok(());
    }

    let response = rdap_bootstrapped_request(&query, client, store, |_| {}).await?;
    stats.queried += 1;

    let stamp = Utc::now().format(STAMP_FORMAT).to_string();
    // Fall back to an address-keyed pseudo-URL if the client did not record
    // the request URI, so the output path stays deterministic per address
    // rather than collapsing to a shared, silently-overwritten location.
    let url = response
        .http_data
        .request_uri
        .clone()
        .unwrap_or_else(|| format!("unknown/{addr}"));
    let json = serde_json::to_vec_pretty(&response.rdap)?;
    let out_path = result_path(config.results_dir, &url, &stamp, "json");
    write_file(&out_path, &json)?;
    stats.saved += 1;
    tracing::info!(%url, path = %out_path.display(), "rdap response saved");

    if let Some(href) = geofeed_href(&response.rdap) {
        limiter.wait_for(&host_of(&href)).await;
        let bytes = geofeed_client.get(&href).send().await?.bytes().await?;
        let feed_path = result_path(config.results_dir, &href, &stamp, "csv");
        write_file(&feed_path, &bytes)?;
        stats.geofeeds += 1;
        tracing::info!(%href, path = %feed_path.display(), "geofeed saved");
    }

    Ok(())
}

/// Write `bytes` to `path`, creating parent directories as needed.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A uniquely-named temp dir, removed on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "support-bin-nro-dequeue-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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
    fn result_path_strips_scheme_and_nests_host_path() {
        // GIVEN a query URL with a scheme and a multi-segment path
        let path = result_path(
            Path::new("work/rdap-results"),
            "https://rdap.arin.net/registry/ip/1.0.0.0",
            "20261108T120000Z",
            "json",
        );
        // THEN the scheme is gone and host/path become nested dirs under the
        // results dir, with the stamped leaf file
        assert_eq!(
            path,
            PathBuf::from("work/rdap-results")
                .join("rdap.arin.net")
                .join("registry")
                .join("ip")
                .join("1.0.0.0")
                .join("20261108T120000Z.json")
        );
    }

    #[test]
    fn result_path_handles_a_schemeless_url() {
        // GIVEN a URL with no scheme
        let path = result_path(Path::new("out"), "example.com/feed", "STAMP", "csv");
        // THEN the whole thing is treated as host/path
        assert_eq!(
            path,
            PathBuf::from("out")
                .join("example.com")
                .join("feed")
                .join("STAMP.csv")
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

    #[tokio::test]
    async fn dequeue_all_dry_run_buckets_and_counts_without_network() {
        // GIVEN a fixture queue with a mix of record kinds
        let queue = TempDir::new("dryrun-queue");
        let results = TempDir::new("dryrun-results");
        let mut sender = yaque::Sender::open(queue.path()).expect("open sender");
        let fixture = "2|nro|20261108|775178|19821213|20261108|+0000\n\
nro|*|asn|*|117676|summary\n\
iana|ZZ|asn|0|1|20140311|reserved|ietf|iana\n\
apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A91872ED|e-stats\n\
arin|US|asn|1|1|20010920|assigned|e5|e-stats\n\
ripencc|DE|ipv6|2001:db8::|32|20100101|assigned|abc|e-stats\n";
        let mut batch: Vec<String> = fixture.lines().map(str::to_string).collect();
        sender.try_send_batch(batch.iter()).expect("enqueue");
        batch.clear();

        // WHEN drained in dry-run mode (no RDAP client is ever touched)
        let client = icann_rdap_client::prelude::create_client(
            &icann_rdap_client::prelude::ClientConfig::default(),
        )
        .expect("client");
        let store = MemoryBootstrapStore::new();
        let geofeed_client = reqwest::Client::new();
        let mut receiver = Receiver::open(queue.path()).expect("open receiver");
        let config = DequeueConfig {
            results_dir: results.path(),
            min_interval: Duration::from_millis(1),
            idle_timeout: Duration::from_millis(200),
            dry_run: true,
            max_items: None,
        };
        let stats = dequeue_all(&mut receiver, &client, &store, &geofeed_client, &config)
            .await
            .expect("dequeue");

        // THEN the counts reflect the fixture and nothing was queried/saved
        assert_eq!(
            stats,
            DequeueStats {
                processed: 2,
                queried: 0,
                saved: 0,
                geofeeds: 0,
                discarded_asn: 1,
                skipped: 3,
                failed: 0,
            }
        );
        // AND the results dir was never populated (it is not even created in
        // dry-run, so NotFound or an empty dir are both acceptable).
        match std::fs::read_dir(results.path()) {
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(mut entries) => assert!(
                entries.next().is_none(),
                "results dir must be empty in dry-run"
            ),
            Err(e) => panic!("unexpected error reading results dir: {e}"),
        }
    }

    #[tokio::test]
    async fn max_items_leaves_the_remainder_queued_and_uncommitted() {
        // GIVEN a queue with two IP records and a run capped at one
        let queue = TempDir::new("maxitems-queue");
        let results = TempDir::new("maxitems-results");
        let mut sender = yaque::Sender::open(queue.path()).expect("open sender");
        let first = "apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A|e-stats";
        let second = "ripencc|DE|ipv4|192.0.2.0|256|20110811|assigned|B|e-stats";
        let mut batch = vec![first.to_string(), second.to_string()];
        sender.try_send_batch(batch.iter()).expect("enqueue");
        batch.clear();
        drop(sender);

        let client = icann_rdap_client::prelude::create_client(
            &icann_rdap_client::prelude::ClientConfig::default(),
        )
        .expect("client");
        let store = MemoryBootstrapStore::new();
        let geofeed_client = reqwest::Client::new();

        // WHEN drained with `max_items = 1` (dry-run, no network)
        {
            let mut receiver = Receiver::open(queue.path()).expect("open receiver");
            let config = DequeueConfig {
                results_dir: results.path(),
                min_interval: Duration::from_millis(1),
                idle_timeout: Duration::from_millis(200),
                dry_run: true,
                max_items: Some(1),
            };
            let stats = dequeue_all(&mut receiver, &client, &store, &geofeed_client, &config)
                .await
                .expect("dequeue");
            // THEN only the capped record was processed
            assert_eq!(stats.processed, 1);
        } // drop the receiver to release the recv.lock

        // AND the second record is still queued (never read or committed)
        let mut receiver2 = Receiver::open(queue.path()).expect("reopen receiver");
        let guard = tokio::time::timeout(Duration::from_secs(2), receiver2.recv())
            .await
            .expect("remaining record should still be queued")
            .expect("recv ok");
        assert_eq!(&*guard, second.as_bytes());
    }
}
