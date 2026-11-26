//! `nro-dequeue` — drain the `nro-delegations` Postgres queue and query RDAP.
//!
//! For every IP delegation record in the queue this binary issues an RDAP
//! query through `icann-rdap-client` (resolved via the IANA bootstrap), UPSERTs
//! the JSON response into the `rdap_results` table, and downloads any RFC 9877
//! geofeed file the response advertises. AS-number (`asn`/`autnum`) records are
//! discarded. Work is claimed one-registry-per-round with a lease (so the run is
//! crash-safe and concurrent-safe), and queries are rate limited to one per host
//! per `--min-interval-secs`.
//!
//! The classification, rate limiting and the async claim loop all live in
//! `support_bin::nro_dequeue`; this binary is a thin CLI that wires up the
//! clients, the database and the tracing subscriber.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use db::Db;
use icann_rdap_client::http::Client as RdapClient;
use icann_rdap_client::iana::qtype_to_bootstrap_url;
use icann_rdap_client::prelude::{ClientConfig, MemoryBootstrapStore, QueryType, create_client};
use support_bin::nro_dequeue::{DequeueConfig, dequeue_all};

/// Default minimum interval (seconds) between queries to the same server.
const DEFAULT_MIN_INTERVAL_SECS: u64 = 60;
/// Default per-request timeout (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Default lease (seconds) a claimed job is held before it becomes reclaimable.
const DEFAULT_LEASE_SECS: u64 = 300;
/// Default attempts allowed before a failing job goes terminal.
const DEFAULT_MAX_ATTEMPTS: i32 = 3;
/// Default backoff (seconds) before a failed job is re-claimable.
const DEFAULT_RETRY_BACKOFF_SECS: u64 = 60;
/// Default number of jobs claimed per round (one per registry, up to this cap).
const DEFAULT_CLAIM_BATCH: i64 = 50;

/// Dequeue the NRO Postgres queue and query RDAP for each IP record.
#[derive(Parser)]
#[command(name = "nro-dequeue", version, about)]
struct Cli {
    /// Minimum interval (seconds) between queries to the same server.
    #[arg(
        long,
        default_value_t = DEFAULT_MIN_INTERVAL_SECS,
        value_parser = clap::value_parser!(u64).range(1..=3600)
    )]
    min_interval_secs: u64,

    /// Per-request timeout in seconds.
    #[arg(
        long,
        default_value_t = DEFAULT_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=300)
    )]
    timeout_secs: u64,

    /// Lease (seconds) a claimed job is held before it becomes reclaimable.
    #[arg(
        long,
        default_value_t = DEFAULT_LEASE_SECS,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    lease_secs: u64,

    /// Attempts allowed before a failing job is marked terminal `failed`.
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_ATTEMPTS,
        value_parser = clap::value_parser!(i32).range(1..=100)
    )]
    max_attempts: i32,

    /// Backoff (seconds) before a failed job is re-claimable.
    #[arg(
        long,
        default_value_t = DEFAULT_RETRY_BACKOFF_SECS,
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    retry_backoff_secs: u64,

    /// Jobs claimed per round (one per registry, up to this cap).
    #[arg(
        long,
        default_value_t = DEFAULT_CLAIM_BATCH,
        value_parser = clap::value_parser!(i64).range(1..=10_000)
    )]
    claim_batch: i64,

    /// String appended to the RDAP client user-agent.
    #[arg(long, default_value = "support-bin-nro-dequeue")]
    user_agent_suffix: String,

    /// Resolve and schedule only — make no network calls and store no results;
    /// claimed jobs are released back to the queue.
    #[arg(long)]
    dry_run: bool,

    /// Stop after this many IP records (caps a run for testing; the rest of
    /// the queue is left pending). Defaults to draining the whole queue.
    #[arg(long, value_parser = clap::value_parser!(usize))]
    max_items: Option<usize>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nro-dequeue: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Wire up the RDAP + geofeed clients and the database, then run the pipeline.
async fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::builder()
        .timeout_secs(cli.timeout_secs)
        .user_agent_suffix(cli.user_agent_suffix.clone())
        .build();
    let client = create_client(&config)?;
    let store = MemoryBootstrapStore::new();
    let geofeed_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cli.timeout_secs))
        .build()?;

    // Connect (and migrate) before any network work.
    let db = Db::connect_from_env().await?;

    if !cli.dry_run {
        warm_up_bootstrap(&client, &store).await?;
    }

    let dequeue_config = DequeueConfig {
        min_interval: Duration::from_secs(cli.min_interval_secs),
        lease: Duration::from_secs(cli.lease_secs),
        max_attempts: cli.max_attempts,
        retry_backoff: Duration::from_secs(cli.retry_backoff_secs),
        claim_batch: cli.claim_batch,
        dry_run: cli.dry_run,
        max_items: cli.max_items,
    };

    let stats = dequeue_all(&db, &client, &store, &geofeed_client, &dequeue_config).await?;

    tracing::info!(
        processed = stats.processed,
        queried = stats.queried,
        saved = stats.saved,
        geofeeds = stats.geofeeds,
        discarded_asn = stats.discarded_asn,
        skipped = stats.skipped,
        failed = stats.failed,
        "dequeue complete"
    );
    Ok(())
}

/// Pre-fetch the IPv4 and IPv6 IANA bootstrap registries so the first real
/// query does not pay the bootstrap download and any bootstrap error surfaces
/// up front rather than mid-drain.
async fn warm_up_bootstrap(
    client: &RdapClient,
    store: &MemoryBootstrapStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let v4 = QueryType::IpV4Addr(Ipv4Addr::new(1, 0, 0, 1));
    let v6 = QueryType::IpV6Addr(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0));
    qtype_to_bootstrap_url(client, store, &v4, |_| {}).await?;
    qtype_to_bootstrap_url(client, store, &v6, |_| {}).await?;
    tracing::info!("IANA bootstrap warmed up (ipv4 + ipv6)");
    Ok(())
}
