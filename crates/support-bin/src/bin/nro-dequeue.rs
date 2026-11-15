//! `nro-dequeue` — drain the `nro-enqueue` yaque queue and query RDAP.
//!
//! For every IP delegation record in the queue this binary issues an RDAP
//! query through `icann-rdap-client` (resolved via the IANA bootstrap),
//! writes the JSON response under the results directory, and downloads any
//! RFC 9877 geofeed file the response advertises. AS-number (`asn`/`autnum`)
//! records are discarded. Queries are rate limited to one per host per
//! `--min-interval-secs`, processed round-robin across registries so the
//! registry-grouped input does not stall.
//!
//! The classification, rate limiting, filename layout and the async drain
//! loop all live in `support_bin::nro_dequeue`; this binary is a thin CLI
//! that wires up the clients, the queue and the tracing subscriber.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use icann_rdap_client::http::Client as RdapClient;
use icann_rdap_client::iana::qtype_to_bootstrap_url;
use icann_rdap_client::prelude::{ClientConfig, MemoryBootstrapStore, QueryType, create_client};
use support_bin::nro_dequeue::{DequeueConfig, dequeue_all};
use yaque::Receiver;

/// Default minimum interval (seconds) between queries to the same server.
const DEFAULT_MIN_INTERVAL_SECS: u64 = 60;
/// Default per-request timeout (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// How long to wait for the next queued item before treating the queue as
/// drained (yaque has no "producer finished" signal).
const IDLE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Dequeue the NRO yaque queue and query RDAP for each IP record.
#[derive(Parser)]
#[command(name = "nro-dequeue", version, about)]
struct Cli {
    /// Work directory — the default parent of the queue and results dirs.
    #[arg(long, default_value = "work")]
    work_dir: PathBuf,

    /// yaque queue directory to drain (default: `<work-dir>/nro-queue`).
    #[arg(long)]
    queue_dir: Option<PathBuf>,

    /// Directory the RDAP / geofeed result files are written under
    /// (default: `<work-dir>/rdap-results`).
    #[arg(long)]
    results_dir: Option<PathBuf>,

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

    /// String appended to the RDAP client user-agent.
    #[arg(long, default_value = "support-bin-nro-dequeue")]
    user_agent_suffix: String,

    /// Resolve and schedule only — make no network calls and write no files.
    #[arg(long)]
    dry_run: bool,

    /// Stop after this many IP records (caps a run for testing; the rest of
    /// the queue is left unread). Defaults to draining the whole queue.
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

/// Wire up the RDAP + geofeed clients and the queue, then run the pipeline.
async fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // `--queue-dir` / `--results-dir` default to `<work-dir>/…` so a single
    // `--work-dir` relocates everything; an explicit flag overrides.
    let queue_dir = cli
        .queue_dir
        .clone()
        .unwrap_or_else(|| cli.work_dir.join("nro-queue"));
    let results_dir = cli
        .results_dir
        .clone()
        .unwrap_or_else(|| cli.work_dir.join("rdap-results"));

    let config = ClientConfig::builder()
        .timeout_secs(cli.timeout_secs)
        .user_agent_suffix(cli.user_agent_suffix.clone())
        .build();
    let client = create_client(&config)?;
    let store = MemoryBootstrapStore::new();
    let geofeed_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cli.timeout_secs))
        .build()?;

    // Open the queue first so a missing queue fails before any network work.
    let mut receiver = Receiver::open(&queue_dir)?;

    if !cli.dry_run {
        warm_up_bootstrap(&client, &store).await?;
    }

    let dequeue_config = DequeueConfig {
        results_dir: &results_dir,
        min_interval: Duration::from_secs(cli.min_interval_secs),
        idle_timeout: IDLE_DRAIN_TIMEOUT,
        dry_run: cli.dry_run,
        max_items: cli.max_items,
    };

    let stats = dequeue_all(
        &mut receiver,
        &client,
        &store,
        &geofeed_client,
        &dequeue_config,
    )
    .await?;

    tracing::info!(
        processed = stats.processed,
        queried = stats.queried,
        saved = stats.saved,
        geofeeds = stats.geofeeds,
        discarded_asn = stats.discarded_asn,
        skipped = stats.skipped,
        failed = stats.failed,
        results_dir = %results_dir.display(),
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
