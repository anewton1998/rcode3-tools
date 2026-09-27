# rcode3-tools

A server-rendered web toolkit built in Rust. The current app, **rdap-lookup**, is an
axum web service that combines three client-side strategies behind a single page:

- **HTMX** for server round-trips (HTML fragment swapping)
- **Alpine.js** for lightweight local interactivity
- **WebAssembly** (Rust compiled to wasm) for in-browser RDAP lookups, so domain/IP
  queries run entirely client-side against the official ICANN RDAP infrastructure

The whole project builds with **pure cargo** — no npm or node toolchain. JavaScript
libraries and fonts are vendored into git; the wasm module is built by `wasm-pack`
(a Rust binary) and is wired into the normal build via a build script.

## Workspace layout

```
rcode3-tools/
├── apps/
│   └── rdap-lookup/          # axum web app (the runnable service)
│       ├── build.rs          # auto-rebuilds the wasm module when it changes
│       ├── src/main.rs
│       ├── templates/        # layout.html, dashboard.html, status.html
│       └── static/
│           ├── vendor/       # committed: htmx.min.js, alpine.min.js
│           ├── fonts/        # committed: Poppins / Goldman / Inconsolata woff2
│           └── wasm/         # generated (gitignored): rdap_wasm.{js,wasm}
├── crates/
│   ├── ui-components/        # design system: askama components + global CSS
│   │   ├── css/              # fonts.css, rcode3.css, app.css
│   │   ├── src/components/   # button, text_input, text_area, status_text,
│   │   │                     # progress_bar, link_nav
│   │   └── src/theme.rs      # the 14-theme enum
│   └── rdap-wasm/            # wasm-bindgen crate wrapping icann-rdap-* crates
├── scripts/build-wasm.sh     # convenience alias for the wasm build path
└── .env                      # gitignored: HOST, PORT, THEME
```

## Architecture

```
                        browser
 ┌────────────────────────────────────────────────────────────┐
 │  layout.html (theme class on <html>, loaded from /)        │
 │  ├── /base.css          one global stylesheet              │
 │  ├── htmx.min.js        server round-trips                 │
 │  ├── alpine.min.js      local interactivity                │
 │  └── rdap_wasm.js       window.RdapClient (ES module)      │
 │        └── rdap_wasm_bg.wasm                                │
│             icann-rdap-client + custom Rust logic           │
│             (bootstrap URL redirector → registry RDAP srvrs)│
 └───────────────┬────────────────────────────┬───────────────┘
                 │ htmx: POST /api/settings   │ direct: https://rdap.<tld>/...
                 ▼                            ▼
        axum (apps/rdap-lookup)         public RDAP endpoints
```

### apps/rdap-lookup

An axum service. Routes:

| Route | Purpose |
|---|---|
| `GET /` | Dashboard page (askama: `layout.html` + `dashboard.html`) |
| `POST /api/settings` | HTMX fragment endpoint (`status.html`, no layout) |
| `GET /base.css` | The concatenated global stylesheet, embedded at compile time |
| `GET /static/*` | Static assets (vendor JS, fonts, wasm) via `ServeDir` |

Conventions: full pages live at `/…`, HTMX fragment responses under `/api/…`.
Requests are logged with `tower-http`'s `TraceLayer`; all logging goes through
`tracing` and is filtered by `RUST_LOG` (default `info`).

**build.rs** keeps the wasm module fresh: it watches `crates/rdap-wasm/src/**`,
the crate's `Cargo.toml`, the workspace `Cargo.lock`, and the two artifact files.
When a source is newer than the artifacts (or they are missing), it runs
`wasm-pack build --release` — with a separate `CARGO_TARGET_DIR`
(`target/wasm-build`) to avoid deadlocking on the outer cargo lock — and copies
`rdap_wasm.js` / `rdap_wasm_bg.wasm` into `static/wasm/`. A steady-state
`cargo build` therefore costs nothing extra.

### crates/ui-components

The design system. Two parts:

**Global CSS** — `global_css()` concatenates three files with `include_str!`:

1. `fonts.css` — `@font-face` rules for the vendored woff2 files
2. `rcode3.css` — the rcode3 design system (originally derived from the dialtone
   project and rebranded): 14 themes as CSS custom-property sets plus component
   classes with the `rcode3_` prefix
3. `app.css` — thin app-level layer (button padding, `.htmx-request` dimming)

The CSS is deliberately **global** rather than per-component scoped: themes set
variables on `<html>` and components reference them across selectors, so it is
served as one stylesheet at `/base.css`.

**Components** — askama template + struct pairs that emit markup using the design
system classes (builder-style APIs):

| Component | Class(es) |
|---|---|
| `Button` (`hx_post()`, `hx_target()`) | `rcode3_button` |
| `TextInput` (`value()`, `placeholder()`) | `rcode3_input_text` |
| `TextArea` (`value()`, `rows()`) | `rcode3_textarea` |
| `StatusText::info/warning/error()` (`.loading()`) | `info_text` / `warning_text` / `error_text` (+ `loading_text`) |
| `ProgressBar` | `rcode3_progress` + cylon-bar animation |
| `LinkNav` (`.item(label, url)`) | `link_nav` |

Layout composites (`basic_form`, `asymmetrical_split_page`, header tables,
`clickable_div`, …) are used directly as CSS classes in page templates rather
than being wrapped as components.

**Themes** — `Theme` (in `src/theme.rs`) covers all 14 themes; `Theme::from_env()`
reads the `THEME` variable and falls back to `green_on_black` for unknown values.
The chosen class is placed on `<html>` by `layout.html`.

### crates/rdap-wasm

A `cdylib` that runs in the browser via wasm-bindgen. It wraps
[`icann-rdap-client`](https://crates.io/crates/icann-rdap-client) and
`icann-rdap-common`, issuing RDAP queries over reqwest (browser fetch on wasm).

**Bootstrapping**: lookups go through a single configurable *bootstrap URL* —
a redirector that 302s each query to the correct registry server — instead of
fetching IANA bootstrap JSON. The default is `https://rdap.org`. It can be
changed at runtime with `RdapClient.set_bootstrap_url(url)` (trailing slashes
are trimmed), or page-wide by setting `window.RDAP_BOOTSTRAP_URL` before the
module script runs; `RdapClient.getBootstrapUrl()` returns the current value.

Exports:

- `rdap_lookup(query) → Promise<object>` — full parsed RDAP response as a JS object
- `rdap_lookup_html(query) → Promise<string>` — HTML fragment produced by the
  **custom client-side logic** in `src/custom.rs` (currently a domain summary);
  that module is where further browser-side Rust belongs

The page loads it as an ES module (`layout.html`), awaits `init()`, and exposes
`window.RdapClient` to htmx/Alpine code.

Two wasm-specific notes baked into this crate:

- `chrono = { features = ["wasmbind"] }` under `cfg(target_arch = "wasm32")` —
  `icann-rdap-common` calls `Utc::now()` on every response, and chrono without
  `wasmbind` panics on wasm ("time not implemented on this platform").
- `console_error_panic_hook` so Rust panics surface as readable JS errors instead
  of silent wasm traps.

The crate also builds natively (it is an `rlib` too) and carries tokio-based
integration tests that exercise the same lookup code path on the host.

## Building and running

Prerequisites: a Rust toolchain with the `wasm32-unknown-unknown` target
(`rustup target add wasm32-unknown-unknown`) and `wasm-pack`
(`cargo install wasm-pack`). No node/npm.

```sh
cp .env.example .env   # or create .env; all values have defaults
cargo run -p rdap-lookup
# → http://127.0.0.1:3000
```

The first build (or any change under `crates/rdap-wasm`) automatically runs the
wasm build as part of `cargo build`. To force it standalone, use
`scripts/build-wasm.sh`.

### Configuration (`.env`, gitignored)

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `127.0.0.1` | Listen address |
| `PORT` | `3000` | Listen port (must be a valid u16) |
| `THEME` | `green_on_black` | Any of the 14 theme names, with or without the `theme_` prefix |
| `RUST_LOG` | `info` | tracing filter, e.g. `info,rdap_lookup=debug` |

## Vendored assets

Committed to git so the build never needs a package manager:

- `static/vendor/` — htmx 2.0.11, Alpine.js 3.17.4 (see its README for versions
  and update commands)
- `static/fonts/` — Poppins 400/700, Goldman 400/700, Inconsolata 400/500, latin
  subset, SIL OFL (see its README; keep `css/fonts.css` in sync when updating)

## Testing

```sh
cargo test --workspace     # unit + native RDAP integration tests (hit the network)
cargo clippy --all-targets
```

Browser-side behavior (htmx swaps, Alpine state, wasm lookups) is verified
manually; the wasm module itself can be exercised headlessly with Node, since the
`--target web` output is a plain ES module.
