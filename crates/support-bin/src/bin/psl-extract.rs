//! `psl-extract` — download the Public Suffix List and emit a compact, committed
//! artifact of ICANN public suffixes with at least `--min-labels` labels.
//!
//! The heavy lifting lives in the `support_bin` library; this binary is a thin CLI
//! that downloads the payload, runs the extract/filter/render pipeline, and writes
//! the result to disk for `include_str!` by a consuming crate.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use support_bin::cli::{fetch_text, http_client, run_or_exit};
use support_bin::psl::{
    PSL_URL, RDAP_BOOTSTRAP_URL, extract_icann, filter_by_rdap, filter_entries, rdap_tlds, render,
};

/// How long to wait for the list download before giving up.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Download the Public Suffix List and emit a compact ICANN-only suffix list.
#[derive(Parser)]
#[command(name = "psl-extract", version, about)]
struct Cli {
    /// Output path for the generated artifact (relative to the current directory).
    #[arg(long, default_value = "crates/support-bin/data/psl_2plus.txt")]
    out: PathBuf,

    /// Minimum number of dot-separated labels an entry must have to be kept.
    #[arg(long, default_value_t = 2)]
    min_labels: usize,

    /// Source URL of the Public Suffix List `.dat` payload.
    #[arg(long, default_value = PSL_URL)]
    url: String,

    /// Source URL of the IANA RDAP bootstrap file used to gate TLDs.
    #[arg(long, default_value = RDAP_BOOTSTRAP_URL)]
    rdap_url: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run_or_exit("psl-extract", || run(&cli))
}

/// Run the download → extract → filter → render → write pipeline.
fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let client = http_client(HTTP_TIMEOUT)?;

    let dat = fetch_text(&client, &cli.url)?;
    let extracted = extract_icann(&dat)?;
    let by_labels = filter_entries(&extracted.entries, cli.min_labels);
    if by_labels.is_empty() {
        return Err(format!(
            "no entries with >= {} labels; refusing to write an empty artifact",
            cli.min_labels
        )
        .into());
    }

    let rdap_json = fetch_text(&client, &cli.rdap_url)?;
    let tlds = rdap_tlds(&rdap_json).map_err(|e| format!("{}: {e}", cli.rdap_url))?;
    let entries = filter_by_rdap(&by_labels, &tlds);
    if entries.is_empty() {
        return Err(
            "no entries survive the RDAP bootstrap filter; refusing to write an empty artifact"
                .into(),
        );
    }
    let dropped = by_labels.len() - entries.len();

    let text = render(&extracted, cli.min_labels, &entries);

    if let Some(parent) = cli.out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cli.out, text)?;

    println!(
        "wrote {} entries (>= {} labels, RDAP-gated) to {}",
        entries.len(),
        cli.min_labels,
        cli.out.display()
    );
    println!("  source version: {}", extracted.version);
    println!("  source commit:  {}", extracted.commit);
    println!("  rdap bootstrap: {}", cli.rdap_url);
    println!("  dropped by RDAP filter: {dropped}");
    Ok(())
}
