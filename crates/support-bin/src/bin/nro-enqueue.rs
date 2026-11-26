//! `nro-enqueue` — read the latest NRO extended-stats file from the work
//! directory and enqueue each delegation entry into the durable Postgres queue.
//!
//! The companion `nro-extended-stats` binary downloads timestamped snapshots
//! (`work/nro-delegated-stats-<stamp>`). This binary picks the most recent of
//! those (or an explicit `--stats-file`), streams it, and pushes every
//! per-RIR delegation record into the `db` crate's job queue under the
//! `nro-delegations` topic. The NRO serial record, the aggregate-summary
//! records and the IANA reserved records are skipped.
//!
//! Enqueue is idempotent per file: each row's dedup key is derived from the
//! file's NRO serial (or `--source-id`), so re-running against the same file
//! inserts nothing.
//!
//! The record classification lives in `support_bin::nro` and the DB-backed
//! pipeline in `support_bin::nro_queue`; this binary is a thin CLI that resolves
//! the input file, connects the database and reports the result.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use db::Db;
use support_bin::nro::{self, NRO_BASE_NAME, NroError};
use support_bin::nro_queue::enqueue_stats;

/// Default number of entries buffered per insert batch (one flush per batch).
const DEFAULT_BATCH_SIZE: usize = 1000;

/// Enqueue the latest NRO extended-stats file into the Postgres job queue.
#[derive(Parser)]
#[command(name = "nro-enqueue", version, about)]
struct Cli {
    /// Work directory that holds the timestamped stats files.
    #[arg(long, default_value = "work")]
    work_dir: PathBuf,

    /// Base name used to discover the latest stats file in the work directory.
    #[arg(long, default_value = NRO_BASE_NAME)]
    base_name: String,

    /// Explicit stats file to read instead of auto-discovering the latest.
    #[arg(long)]
    stats_file: Option<PathBuf>,

    /// Source id used for the per-row dedup key. Defaults to the file's NRO
    /// serial record, so re-enqueueing the same file is a no-op.
    #[arg(long)]
    source_id: Option<String>,

    /// Number of entries buffered per insert batch.
    #[arg(
        long,
        default_value_t = DEFAULT_BATCH_SIZE as u64,
        value_parser = clap::value_parser!(u64).range(1..=1_000_000)
    )]
    batch_size: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nro-enqueue: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Resolve the input file, connect the database, and run the enqueue pipeline.
async fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let stats_path = resolve_stats_file(cli)?;

    // Derive the per-file dedup scope before opening the stream.
    let source_serial = match &cli.source_id {
        Some(id) => id.clone(),
        None => derive_source_serial(&stats_path)?,
    };

    // Open the input first so a missing/unreadable file fails before we connect.
    let file = std::fs::File::open(&stats_path)?;
    // A larger buffer keeps the read-syscall count low over the ~57 MB stream.
    let reader = BufReader::with_capacity(256 * 1024, file);

    let db = Db::connect_from_env().await?;

    let stats = enqueue_stats(&db, reader, &source_serial, cli.batch_size as usize).await?;

    println!(
        "enqueued {} entries from {} (deduped {}, skipped {} serial + {} summary + {} iana)",
        stats.enqueued,
        stats_path.display(),
        stats.deduped,
        stats.skipped_serial,
        stats.skipped_summary,
        stats.skipped_iana,
    );
    Ok(())
}

/// Derive the per-file dedup scope from the NRO serial record (field 3 of the
/// `2|nro|<date>|<serial>|…` first line), falling back to the file name.
fn derive_source_serial(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let first = support_bin::cli::read_first_line(path)?;
    if nro::is_serial_line(&first)
        && let Some(serial) = first.split('|').nth(3)
        && !serial.is_empty()
    {
        return Ok(serial.to_string());
    }
    // Fall back to the file name so the dedup scope is still stable per file.
    Ok(path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string()))
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
