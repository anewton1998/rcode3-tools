#!/usr/bin/env bash
# Manual fallback: `cargo build -p rdap-lookup` already rebuilds the wasm
# automatically via apps/rdap-lookup/build.rs when crates/rdap-wasm changes.
# This script is just a convenience alias for forcing that path in CI.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p rdap-lookup
