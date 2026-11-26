# Development tasks for rcode3-tools.
# Run `just` (or `just --list`) to see available recipes.
# Override host/port/base either as a just variable before the recipe
# (`just port=8080 run`) or as an env var (`PORT=8080 just run`).

# Default host/port/base for the rdap-explorer dev server.
host := env_var_or_default("HOST", "0.0.0.0")
port := env_var_or_default("PORT", "3000")
base := env_var_or_default("BASE_PATH", "/")

default:
    @just --list

# ---- run dev servers -------------------------------------------------------

# Run the gateway
run:
    HOST={{host}} PORT={{port}} BASE_PATH={{base}} cargo run -p rcode3-gateway
    
# Run the rdap-explorer server (BOOTSTRAP_URL/IANA_REFRESH_SECS/etc. via env).
run-rdap:
    HOST={{host}} PORT={{port}} BASE_PATH={{base}} cargo run -p rdap-explorer

# Run the dns-explorer server.
run-dns:
    HOST={{host}} PORT={{port}} BASE_PATH={{base}} cargo run -p dns-explorer

# Run the combined rcode3-tools server.
run-tools:
    HOST={{host}} PORT={{port}} BASE_PATH={{base}} cargo run -p rcode3-tools

# ---- quality gates -------------------------------------------------------

# Build the whole workspace.
build:
    cargo build --workspace

# Run the whole workspace test suite.
test:
    cargo test --workspace

# Run tests for rdap-explorer + ui-components only.
test-rdap:
    cargo test -p rdap-explorer -p ui-components

# Lint the whole workspace.
clippy:
    cargo clippy --workspace --all-targets

# Format all Rust code.
fmt:
    cargo fmt --all

# Check formatting without writing (CI-style).
fmt-check:
    cargo fmt --all -- --check

# fmt + clippy + tests in one shot.
check: fmt-check clippy test

# ---- helpers -----------------------------------------------------------

# Print the base-URL groups the running explorer rendered (expects `run` up).
groups:
    @curl -s http://{{host}}:{{port}}/ | grep -o 'optgroup label="[^"]*"' || echo "server not reachable on {{host}}:{{port}}"

# Remove build artifacts.
clean:
    cargo clean
