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
use support_bin::{PSL_URL, extract_icann, filter_entries, render};

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("psl-extract: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Run the download → extract → filter → render → write pipeline.
fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()?;
    let response = client.get(&cli.url).send()?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET {} failed: HTTP {status}", cli.url).into());
    }
    let dat = response.text()?;

    let extracted = extract_icann(&dat)?;
    let entries = filter_entries(&extracted.entries, cli.min_labels);
    if entries.is_empty() {
        return Err(format!(
            "no entries with >= {} labels; refusing to write an empty artifact",
            cli.min_labels
        )
        .into());
    }
    let text = render(&extracted, cli.min_labels, &entries);

    if let Some(parent) = cli.out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cli.out, text)?;

    println!(
        "wrote {} entries (>= {} labels) to {}",
        entries.len(),
        cli.min_labels,
        cli.out.display()
    );
    println!("  source version: {}", extracted.version);
    println!("  source commit:  {}", extracted.commit);
    Ok(())
}
