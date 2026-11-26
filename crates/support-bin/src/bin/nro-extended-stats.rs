//! `nro-extended-stats` — download the NRO extended (combined) delegated-stats
//! file into the work directory.
//!
//! The Number Resource Organization merges the five RIR registries' delegated
//! resource records into one pipe-delimited *extended* stream (per-record
//! integrity hashes + `e-stats` markers). This binary fetches the live file and
//! writes it to disk under a name stamped with the download time, e.g.
//! `work/nro-delegated-stats-20261108T145855Z`, so each run leaves a
//! timestamped snapshot of the moment the download completed.
//!
//! The download is published **atomically**: the body is streamed to a
//! per-process `.part` staging file, validated, and only then renamed to the
//! final timestamped path. A mid-stream failure, an empty body, or a payload
//! that fails the format guard therefore never leaves a corrupt file under the
//! name consumers glob for.
//!
//! The pure logic (URL, filename stamp, payload guard) lives in the
//! `support_bin::nro` library; the streaming download and first-line read are
//! shared plumbing in `support_bin::cli`. This binary is a thin CLI over both.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use support_bin::cli::{download_to_file, http_client, read_first_line, run_or_exit};
use support_bin::nro::{self, NRO_BASE_NAME, NRO_EXTENDED_STATS_URL, NroError, STAMP_FORMAT};

/// How long to wait for the ~57 MB download before giving up.
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Download the NRO extended stats file into the work directory, stamping the
/// file name with the download time.
#[derive(Parser)]
#[command(name = "nro-extended-stats", version, about)]
struct Cli {
    /// Directory to write the timestamped file into.
    #[arg(long, default_value = "work")]
    out_dir: PathBuf,

    /// Base file name before the download timestamp is appended.
    #[arg(long, default_value = NRO_BASE_NAME)]
    base_name: String,

    /// Source URL of the NRO extended stats file.
    #[arg(long, default_value = NRO_EXTENDED_STATS_URL)]
    url: String,

    /// Request timeout in seconds (the file is ~57 MB).
    #[arg(
        long,
        default_value_t = DEFAULT_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    timeout: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run_or_exit("nro-extended-stats", || run(&cli))
}

/// Run the download → guard → atomic-publish pipeline.
fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let client = http_client(Duration::from_secs(cli.timeout))?;

    // Stream into a per-process staging file so a failed or rejected download
    // never leaves a corrupt file under the final timestamped name. The
    // process id keeps concurrent runs from clobbering each other's staging.
    let staging = cli
        .out_dir
        .join(format!("{}.{}.part", cli.base_name, std::process::id()));

    let outcome = (|| -> Result<u64, Box<dyn std::error::Error>> {
        let bytes = download_to_file(&client, &cli.url, &staging)?;
        if bytes == 0 {
            return Err(NroError::EmptyPayload.into());
        }
        // Guard against a truncated or wrong download before publishing.
        let first_line = read_first_line(&staging)?;
        nro::validate_first_line(&first_line)?;
        Ok(bytes)
    })();

    if outcome.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    let bytes = outcome?;

    // Stamp with the completion time and publish atomically.
    let when = chrono::Utc::now();
    let out_path = nro::default_output_path(&cli.out_dir, &cli.base_name, when);
    std::fs::rename(&staging, &out_path)?;

    println!(
        "wrote {} bytes to {} (source {}, downloaded {})",
        bytes,
        out_path.display(),
        cli.url,
        when.format(STAMP_FORMAT)
    );
    Ok(())
}
