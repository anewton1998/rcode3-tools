//! `psl-extract` — download the Public Suffix List and the IANA RDAP bootstrap,
//! then emit three committed artifacts:
//!
//! 1. the compact, RDAP-gated, `>= --min-labels` suffix list (the original
//!    `psl_2plus.txt`),
//! 2. the **full** ICANN public suffix list (all labels, wildcards and
//!    exceptions; not RDAP-gated) — the authoritative source for eTLD+1, and
//! 3. the **RDAP-covered TLD set** — the positive signal for whether a TLD has
//!    RDAP service (a TLD absent here, e.g. `de`, has none).
//!
//! The heavy lifting lives in the `support_bin` library; this binary is a thin CLI
//! that downloads the payloads, runs the extract/filter/render pipeline, and
//! writes the results to disk for `include_str!` by a consuming crate.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use support_bin::cli::{fetch_text, http_client, run_or_exit};
use support_bin::psl::{
    PSL_URL, RDAP_BOOTSTRAP_URL, extract_icann, filter_by_rdap, filter_entries, rdap_publication,
    rdap_tlds, render, render_icann_psl, render_rdap_tlds,
};

/// How long to wait for the list download before giving up.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Download the Public Suffix List and emit a compact ICANN-only suffix list.
#[derive(Parser)]
#[command(name = "psl-extract", version, about)]
struct Cli {
    /// Output path for the generated artifact (relative to the current directory).
    #[arg(long, default_value = "work/psl_2plus.txt")]
    out: PathBuf,

    /// Output path for the full ICANN public suffix list (all labels, wildcards
    /// and exceptions; not RDAP-gated).
    #[arg(long, default_value = "work/icann_psl.txt")]
    psl_out: PathBuf,

    /// Output path for the RDAP-covered TLD set.
    #[arg(long, default_value = "work/rdap_tlds.txt")]
    rdap_out: PathBuf,

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

    // 1. The compact, RDAP-gated, >= min-labels artifact (original purpose).
    let gated_text = render(&extracted, cli.min_labels, &entries);
    write_artifact(&cli.out, &gated_text)?;

    // 2. The full ICANN PSL (all labels, wildcards, exceptions) — the
    //    authoritative source for eTLD+1, independent of RDAP coverage.
    let full = filter_entries(&extracted.entries, 1);
    let psl_text = render_icann_psl(&extracted, &full);
    write_artifact(&cli.psl_out, &psl_text)?;

    // 3. The RDAP-covered TLD set — the positive signal for "is this TLD in
    //    RDAP" (a TLD absent here, e.g. `de`, has no RDAP service).
    let publication = rdap_publication(&rdap_json).map_err(|e| format!("{}: {e}", cli.rdap_url))?;
    let tlds_text = render_rdap_tlds(&tlds, &publication);
    write_artifact(&cli.rdap_out, &tlds_text)?;

    println!(
        "wrote {} entries (>= {} labels, RDAP-gated) to {}",
        entries.len(),
        cli.min_labels,
        cli.out.display()
    );
    println!(
        "wrote {} full ICANN entries to {}",
        full.len(),
        cli.psl_out.display()
    );
    println!(
        "wrote {} RDAP-covered TLDs to {}",
        tlds.len(),
        cli.rdap_out.display()
    );
    println!("  source version: {}", extracted.version);
    println!("  source commit:  {}", extracted.commit);
    println!(
        "  rdap bootstrap: {} (published {publication})",
        cli.rdap_url
    );
    println!("  dropped by RDAP filter: {dropped}");
    Ok(())
}

/// Create the parent directory if needed and write `text` to `path`.
fn write_artifact(path: &Path, text: &str) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)
}
