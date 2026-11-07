//! Support binaries for the rcode3-tools workspace.
//!
//! The library half holds the pure, offline-testable logic and the shared CLI
//! plumbing; the binary half (`src/bin/*.rs`) is a thin CLI over it. Each file in
//! `src/bin/` is auto-discovered by Cargo as its own binary, so adding a new
//! support tool means dropping a new `src/bin/<name>.rs` that leans on these
//! modules — no `Cargo.toml` churn required.
//!
//! Modules:
//! - [`psl`] — the Public Suffix List extract / RDAP-gate / render pipeline
//!   behind the `psl-extract` binary.
//! - [`cli`] — shared plumbing (HTTP client, one-shot fetch, exit-code wrapper)
//!   reused by every binary so they stay thin.

pub mod cli;
pub mod psl;
