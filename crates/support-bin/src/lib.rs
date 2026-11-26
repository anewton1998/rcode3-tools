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
//! - [`nro`] — the URL, timestamped-filename builder, payload guard and
//!   record classifiers shared by the `nro-extended-stats` and `nro-enqueue`
//!   binaries.
//! - [`nro_queue`] — the Postgres-backed enqueue pipeline behind the
//!   `nro-enqueue` binary (writes to the `db` crate's `queue_jobs` table).
//! - [`nro_dequeue`] — the RDAP-querying dequeue pipeline behind the
//!   `nro-dequeue` binary (claims from `queue_jobs`, stores results in
//!   `rdap_results`).
//! - [`cli`] — shared plumbing (HTTP client, one-shot fetch, streaming
//!   download, exit-code wrapper) reused by every binary so they stay thin.

pub mod cli;
pub mod nro;
pub mod nro_dequeue;
pub mod nro_queue;
pub mod psl;
