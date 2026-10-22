# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build
# Compiles the rcode3-gateway binary (which merges rcode3-home + rdap-lookup)
# and, via apps/rdap-lookup/build.rs, the rdap-wasm browser module.
# ---------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS build

ARG WASM_PACK_VERSION=0.13.1

# curl/ca-certs are needed to fetch the pinned wasm-pack release.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Target required by the wasm crate + the wasm-pack binary itself.
RUN rustup target add wasm32-unknown-unknown \
    && curl -fsSL "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
        | tar -xz -C /usr/local/bin --strip-components=1 \
            "wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack" \
    && wasm-pack --version

WORKDIR /app

# Full workspace: backend source, templates, assets/ (symlink targets), manifests.
# static/wasm is gitignored, so build.rs regenerates it deterministically here.
COPY . .

RUN cargo build --release -p rcode3-gateway

# Assemble a self-contained, symlink-free payload at the exact absolute
# CARGO_MANIFEST_DIR paths the binary was compiled against (/app/apps/...),
# so ServeDir resolves at runtime without assets/ or symlinks.
RUN set -eux; \
    mkdir -p /payload/app/apps/rcode3-home /payload/app/apps/rdap-lookup; \
    cp -rL apps/rcode3-home/static /payload/app/apps/rcode3-home/static; \
    cp -rL apps/rdap-lookup/static /payload/app/apps/rdap-lookup/static; \
    cp target/release/rcode3-gateway /payload/app/rcode3-gateway

# ---------------------------------------------------------------------------
# Stage 2: runtime
# Minimal image: just the compiled binary + dereferenced static trees.
# No source, no toolchain, no assets/, no symlinks.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --user-group \
        --home-dir /app --shell /usr/sbin/nologin app

COPY --from=build --chown=10001:10001 /payload/app /app

WORKDIR /app
USER 10001:10001

# HOST defaults to 127.0.0.1 in code; override so the container is reachable.
ENV HOST=0.0.0.0 \
    PORT=8080 \
    RUST_LOG=info

EXPOSE 8080

CMD ["/app/rcode3-gateway"]
