#!/usr/bin/env bash
# Builds the rdap-wasm crate for the browser and copies the artifacts into
# the app's static directory. Requires wasm-pack (cargo install wasm-pack)
# and the wasm32-unknown-unknown rust target (rustup target add).
set -euo pipefail
cd "$(dirname "$0")/.."

wasm-pack build crates/rdap-wasm --target web --release

PKG=crates/rdap-wasm/pkg
mkdir -p apps/rdap-lookup/static/wasm
cp "$PKG/rdap_wasm.js" "$PKG/rdap_wasm_bg.wasm" apps/rdap-lookup/static/wasm/
rm -rf "$PKG"

echo "artifacts copied to apps/rdap-lookup/static/wasm/"
