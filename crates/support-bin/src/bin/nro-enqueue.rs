//! `nro-enqueue` — read the latest NRO extended-stats file from the work
//! directory and enqueue each delegation entry into a yaque queue.
//!
//! The companion `nro-extended-stats` binary downloads timestamped snapshots
//! (`work/nro-delegated-stats-<stamp>`). This binary picks the most recent of
//! those (or an explicit `--stats-file`), streams it, and pushes every
//! per-RIR delegation record into a [`yaque`] disk-backed queue under the
//! work directory — creating the queue directory if it does not exist. The
//! NRO serial record, the aggregate-summary records and the IANA reserved
//! records are skipped.
//!
//! The record classification lives in `support_bin::nro` and the
//! yaque-backed pipeline in `support_bin::nro_queue`; this binary is a thin
//! CLI that resolves the input file, opens the queue and reports the result.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use support_bin::cli::run_or_exit;
use support_bin::nro::{self, NRO_BASE_NAME, NroError};
use support_bin::nro_queue::enqueue_stats;
use yaque::Sender;

/// Default number of entries buffered per yaque batch (one flush per batch).
const DEFAULT_BATCH_SIZE: usize = 1000;

/// Enqueue the latest NRO extended-stats file into a yaque queue directory.
#[derive(Parser)]
#[command(name = "nro-enqueue", version, about)]
struct Cli {
    /// Work directory that holds the timestamped stats files.
    #[arg(long, default_value = "work")]
    work_dir: PathBuf,

    /// yaque queue directory to enqueue into (created if missing).
    #[arg(long, default_value = "work/nro-queue")]
    queue_dir: PathBuf,

    /// Base name used to discover the latest stats file in the work directory.
    #[arg(long, default_value = NRO_BASE_NAME)]
    base_name: String,

    /// Explicit stats file to read instead of auto-discovering the latest.
    #[arg(long)]
    stats_file: Option<PathBuf>,

    /// Number of entries buffered per yaque batch.
    #[arg(
        long,
        default_value_t = DEFAULT_BATCH_SIZE as u64,
        value_parser = clap::value_parser!(u64).range(1..=1_000_000)
    )]
    batch_size: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run_or_exit("nro-enqueue", || run(&cli))
}

/// Resolve the input file, open the queue, and run the enqueue pipeline.
fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let stats_path = resolve_stats_file(cli)?;

    // Open the input first so a missing/unreadable file fails before we create
    // the queue directory or take the send lock.
    let file = File::open(&stats_path)?;
    // A larger buffer keeps the read-syscall count low over the ~57 MB stream.
    let reader = BufReader::with_capacity(256 * 1024, file);

    // `Sender::open` creates the queue directory (and parents) if missing.
    let mut sender = Sender::open(&cli.queue_dir)?;

    let stats = enqueue_stats(reader, &mut sender, cli.batch_size as usize)?;

    println!(
        "enqueued {} entries from {} into {} (skipped {} serial + {} summary + {} iana)",
        stats.enqueued,
        stats_path.display(),
        cli.queue_dir.display(),
        stats.skipped_serial,
        stats.skipped_summary,
        stats.skipped_iana,
    );
    Ok(())
}

/// Resolve which stats file to read: the explicit `--stats-file`, or the
/// latest `<base>-<stamp>` file in the work directory.
fn resolve_stats_file(cli: &Cli) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = &cli.stats_file {
        if !path.is_file() {
            return Err(NroError::NoStatsFile(path.clone()).into());
        }
        return Ok(path.clone());
    }

    let entries = std::fs::read_dir(&cli.work_dir)
        .map_err(|_| NroError::NoStatsFile(cli.work_dir.clone()))?;
    // Per-entry IO errors and non-UTF-8 file names are skipped during discovery.
    let names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    let latest = nro::latest_stats_file(names.iter().map(String::as_str), &cli.base_name)
        .ok_or_else(|| NroError::NoStatsFile(cli.work_dir.clone()))?;
    Ok(cli.work_dir.join(latest))
}
