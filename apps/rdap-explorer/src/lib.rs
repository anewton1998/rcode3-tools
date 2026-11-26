use askama::Template;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Html,
    routing::{get, post},
};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use ui_components::{ProgressBar, Select, SelectOption, TextInput, Theme, ThemeAppSelect};

pub mod iana;

use iana::{IanaCache, IanaServer};

#[derive(Template)]
#[template(path = "explorer.html")]
struct Explorer {
    search_input_html: String,
    query_type_select_html: String,
    base_url_select_html: String,
    base_url_input_html: String,
    progress_bar_html: String,
    theme_app_html: String,
    theme: &'static str,
    base: String,
    home_url: String,
    bootstrap_url: String,
    bootstrap_servers: String,
    exts_list: String,
}

/// Shared request state: the mount base plus the refreshable IANA cache.
#[derive(Clone)]
struct AppState {
    base: String,
    iana: IanaCache,
}

/// The RDAP bootstrap servers offered in the base-URL dropdown, in display
/// order. Ingested from the (now-removed) `bootstrap-servers.txt`.
const BOOTSTRAP_SERVERS: &[&str] = &[
    "https://bootstrap.rcode3.com/rdap",
    "https://rdap-bootstrap.arin.net/bootstrap",
    "https://rdap.org",
];

/// Trims whitespace and trailing slashes so base-URLs compare equal regardless
/// of a trailing slash.
pub(crate) fn normalize_bootstrap(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

/// Builds the base-URL dropdown options and the default selection from the
/// configured `BOOTSTRAP_URL` value.
///
/// The env value is normalized (trimmed, trailing slashes stripped) before it
/// is compared or stored, so a value like `"/"` collapses to empty and a
/// trailing slash never leaks into the option/default that reaches the client.
///
/// - Env set (non-empty after normalization) → the env value is the default;
///   if it isn't already one of the listed servers it is prepended so it is
///   selectable.
/// - Empty (or degenerate) env → the default is the first server in the list.
fn compute_base_url(env_bootstrap: &str) -> (Vec<String>, String) {
    debug_assert!(
        !BOOTSTRAP_SERVERS.is_empty(),
        "BOOTSTRAP_SERVERS must contain at least one server"
    );
    let mut options: Vec<String> = BOOTSTRAP_SERVERS.iter().map(|s| s.to_string()).collect();
    let env = normalize_bootstrap(env_bootstrap);
    if env.is_empty() {
        let default = options[0].clone();
        return (options, default);
    }
    if !options.iter().any(|s| normalize_bootstrap(s) == env) {
        options.insert(0, env.clone());
    }
    (options, env)
}

/// Builds the "IANA Registered" dropdown options from the cached servers,
/// dropping any whose normalized URL is already offered under the Bootstrap
/// group (so a provider like `rcode3` that appears in both lists shows once).
///
/// The returned options borrow from `servers`, so the caller must keep the
/// cache read guard alive until the rendered HTML has been produced.
fn iana_display_options<'a>(
    servers: &'a [IanaServer],
    bootstrap: &[String],
) -> Vec<SelectOption<'a>> {
    let taken: HashSet<String> = bootstrap.iter().map(|s| normalize_bootstrap(s)).collect();
    servers
        .iter()
        .filter(|s| !taken.contains(&s.key))
        .map(|s| SelectOption {
            value: s.url.as_str(),
            label: s.tag.as_str(),
        })
        .collect()
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusMessage {
    text: String,
}

fn render_error(_: askama::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn render_explorer(
    State(state): State<AppState>,
) -> Result<(HeaderMap, Html<String>), StatusCode> {
    let home_url = std::env::var("HOME_URL").unwrap_or_else(|_| "/".to_string());

    let search_input = TextInput::new("query")
        .placeholder("example.com or 192.0.2.1")
        .x_model("query")
        .enter_activates("#lookup-btn");

    let query_type_select = Select::new("query_type")
        .x_model("queryType")
        .groups_expr("queryTypeGroups");

    // Base-URL dropdown: a "Bootstrap" group (the configured servers), an
    // "IANA Registered" group (fetched at runtime, deduped against the
    // bootstrap set), and a trailing "Custom" entry that reveals the text
    // box. Disabled (with a note) for the Explicit URL type, which ignores
    // any base URL.
    let (base_options, base_default) =
        compute_base_url(&std::env::var("BOOTSTRAP_URL").unwrap_or_default());

    // The IANA options borrow from the cached servers, so the read guard is
    // held until the select has been rendered to a String.
    let base_url_select_html = {
        let iana = state.iana.read().await;
        let bootstrap_opts: Vec<SelectOption<'_>> = base_options
            .iter()
            .map(|s| SelectOption {
                value: s.as_str(),
                label: s.as_str(),
            })
            .collect();
        let iana_opts = iana_display_options(&iana, &base_options);
        let mut select = Select::new("base_url")
            .x_model("baseUrlChoice")
            .x_bind_disabled("baseSelectDisabled")
            .selected(&base_default)
            .group("Bootstrap", bootstrap_opts);
        // Omit the IANA group entirely until the first fetch populates it,
        // rather than rendering an empty <optgroup>.
        if !iana_opts.is_empty() {
            select = select.group("IANA Registered", iana_opts);
        }
        select
            .option("custom", "Custom")
            .render()
            .map_err(render_error)?
    };

    let base_url_input = TextInput::new("base_url_custom")
        .x_model("baseUrlCustom")
        .x_bind_disabled("isUrlType")
        .placeholder("https://my-rdap.example.com/base");

    let page = Explorer {
        search_input_html: search_input.render().map_err(render_error)?,
        query_type_select_html: query_type_select.render().map_err(render_error)?,
        base_url_select_html,
        base_url_input_html: base_url_input.render().map_err(render_error)?,
        progress_bar_html: ProgressBar.render().map_err(render_error)?,
        theme_app_html: ThemeAppSelect::new().render().map_err(render_error)?,
        theme: Theme::from_env().class_name(),
        base: state.base.clone(),
        home_url,
        bootstrap_url: base_default,
        // The hardcoded bootstrap redirectors, as JSON, so the client can
        // warn when a targeted/experimental query is pointed at one of them.
        bootstrap_servers: serde_json::to_string(BOOTSTRAP_SERVERS)
            .unwrap_or_else(|_| "[]".to_string()),
        exts_list: std::env::var("EXTS_LIST").unwrap_or_default(),
    };

    // The page embeds runtime config (bootstrap default, exts list) and the
    // inline app JS, so it must never be cached — a stale copy would ship old
    // logic and a stale base-URL default.
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((headers, Html(page.render().map_err(render_error)?)))
}

async fn save_settings() -> Result<Html<String>, StatusCode> {
    let fragment = StatusMessage {
        text: "Settings saved".to_string(),
    };
    Ok(Html(fragment.render().map_err(render_error)?))
}

fn normalize_base(base: &str) -> String {
    let mut b = base.trim().to_string();
    if !b.starts_with('/') {
        b.insert(0, '/');
    }
    while b.len() > 1 && b.ends_with('/') {
        b.pop();
    }
    b
}

/// Builds the explorer router mounted at `base`.
///
/// Spawns the background IANA refresher, so this must be called from within a
/// Tokio runtime (the binary's `#[tokio::main]` satisfies this). Each call
/// starts one long-lived refresher task; call it once at startup.
pub fn router(base: &str) -> Router {
    let base = normalize_base(base);
    let url_base = if base == "/" {
        String::new()
    } else {
        base.clone()
    };

    let cors_origin = std::env::var("CORS_ORIGIN").unwrap_or_else(|_| "*".to_string());
    let cors_methods = std::env::var("CORS_METHODS").unwrap_or_else(|_| "*".to_string());
    let cors_headers = std::env::var("CORS_HEADERS").unwrap_or_else(|_| "*".to_string());

    // Seed an empty IANA cache and kick off the background refresher. The
    // server starts serving immediately; the "IANA Registered" group fills
    // in once the first fetch lands and degrades to bootstrap-only if IANA
    // is unreachable.
    let iana: IanaCache = Arc::new(RwLock::new(Vec::new()));
    iana::spawn_refresher(iana.clone());

    let app = Router::new()
        .route("/", get(render_explorer))
        .route("/api/settings", post(save_settings))
        .route(
            "/base.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    ui_components::global_css(),
                )
            }),
        )
        .nest_service(
            "/static",
            ServeDir::new(format!("{}/static", env!("CARGO_MANIFEST_DIR"))),
        )
        .layer(SetResponseHeaderLayer::overriding(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(&cors_origin).expect("CORS_ORIGIN must be a valid header value"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_str(&cors_methods)
                .expect("CORS_METHODS must be a valid header value"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_str(&cors_headers)
                .expect("CORS_HEADERS must be a valid header value"),
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(AppState {
            base: url_base,
            iana,
        });

    if base == "/" {
        app
    } else {
        Router::new().nest(&base, app)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_bootstrap_trims_slash_and_space() {
        assert_eq!(
            normalize_bootstrap("  https://a.example/rdap//  "),
            "https://a.example/rdap"
        );
        assert_eq!(
            normalize_bootstrap("https://a.example"),
            "https://a.example"
        );
    }

    #[test]
    fn empty_env_defaults_to_first_server() {
        // GIVEN no configured BOOTSTRAP_URL
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("");
        // THEN the options are the servers as-is and the first is the default
        assert_eq!(
            options,
            BOOTSTRAP_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(default, BOOTSTRAP_SERVERS[0]);
    }

    #[test]
    fn env_already_in_list_becomes_default() {
        // GIVEN a configured BOOTSTRAP_URL that is already a listed server
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("https://rdap.org");
        // THEN nothing is prepended and the configured server is the default
        assert_eq!(options.len(), BOOTSTRAP_SERVERS.len());
        assert_eq!(default, "https://rdap.org");
    }

    #[test]
    fn env_not_in_list_is_prepended_and_default() {
        // GIVEN a configured BOOTSTRAP_URL not present in the list
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("https://custom.example/rdap");
        // THEN it is prepended and becomes the default
        assert_eq!(options[0], "https://custom.example/rdap");
        assert_eq!(options.len(), BOOTSTRAP_SERVERS.len() + 1);
        assert_eq!(default, "https://custom.example/rdap");
    }

    #[test]
    fn env_match_ignores_trailing_slash() {
        // GIVEN a configured BOOTSTRAP_URL that matches a listed server only
        // after trailing-slash normalization
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("https://rdap.org/");
        // THEN it is treated as already present (not prepended) and the
        // normalized configured server is the default
        assert_eq!(options.len(), BOOTSTRAP_SERVERS.len());
        assert_eq!(default, "https://rdap.org");
    }

    #[test]
    fn whitespace_padded_env_in_list_is_not_prepended() {
        // GIVEN a listed server wrapped in whitespace
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("  https://rdap.org  ");
        // THEN it is recognized as present (not prepended) and is the default
        assert_eq!(options.len(), BOOTSTRAP_SERVERS.len());
        assert_eq!(default, "https://rdap.org");
    }

    #[test]
    fn whitespace_only_env_defaults_to_first_server() {
        // GIVEN a whitespace-only BOOTSTRAP_URL
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("   ");
        // THEN it collapses to empty and the first server is the default
        assert_eq!(options.len(), BOOTSTRAP_SERVERS.len());
        assert_eq!(default, BOOTSTRAP_SERVERS[0]);
    }

    #[test]
    fn degenerate_slash_env_defaults_to_first_server() {
        // GIVEN a BOOTSTRAP_URL that normalizes to empty (just slashes)
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("//");
        // THEN it is treated as empty rather than prepended as a bogus server
        assert_eq!(options.len(), BOOTSTRAP_SERVERS.len());
        assert_eq!(default, BOOTSTRAP_SERVERS[0]);
    }

    #[test]
    fn prepended_env_is_stored_normalized() {
        // GIVEN an unlisted BOOTSTRAP_URL with a trailing slash
        // WHEN the dropdown is computed
        let (options, default) = compute_base_url("https://x.example/rdap/");
        // THEN the stored option/default have the trailing slash stripped
        assert_eq!(options[0], "https://x.example/rdap");
        assert_eq!(default, "https://x.example/rdap");
    }

    #[test]
    fn bootstrap_servers_meta_is_json_of_hardcoded_redirectors() {
        // GIVEN the hardcoded bootstrap redirectors
        // WHEN serialized for the rdap-bootstrap-servers meta tag
        let json = serde_json::to_string(BOOTSTRAP_SERVERS).unwrap();
        // THEN it round-trips back to exactly the const list (the client
        // matches the selected base against these exact strings)
        let parsed: Vec<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, BOOTSTRAP_SERVERS.to_vec());
    }

    #[test]
    fn bootstrap_servers_json_is_html_safe_in_attribute() {
        // The JSON contains double quotes; askama escapes them to &quot; in
        // the meta content attribute and the browser decodes them back, so
        // the serialized form must be valid JSON on its own.
        let json = serde_json::to_string(BOOTSTRAP_SERVERS).unwrap();
        assert!(json.starts_with('[') && json.ends_with(']'));
        assert!(serde_json::from_str::<Vec<String>>(&json).is_ok());
    }

    #[test]
    fn default_is_always_an_option() {
        // The default must be selectable in every branch.
        for env in [
            "",
            "   ",
            "//",
            "https://rdap.org",
            "https://new.example/rdap/",
        ] {
            let (options, default) = compute_base_url(env);
            assert!(
                options.contains(&default),
                "default {default} not in options for {env:?}"
            );
        }
    }

    #[test]
    fn iana_options_drop_bootstrap_duplicates_and_label_by_tag() {
        // GIVEN a bootstrap set and an IANA set that overlaps on one URL
        let bootstrap = vec!["https://bootstrap.rcode3.com/rdap".to_string()];
        let servers = vec![
            IanaServer {
                tag: "rcode3".to_string(),
                url: "https://bootstrap.rcode3.com/rdap/".to_string(),
                key: "https://bootstrap.rcode3.com/rdap".to_string(),
            },
            IanaServer {
                tag: "ARIN".to_string(),
                url: "https://rdap.arin.net/registry/".to_string(),
                key: "https://rdap.arin.net/registry".to_string(),
            },
        ];
        // WHEN the display options are built
        let opts = iana_display_options(&servers, &bootstrap);
        // THEN the bootstrap duplicate is dropped and the survivor is
        // labelled by tag with the URL as its value
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].label, "ARIN");
        assert_eq!(opts[0].value, "https://rdap.arin.net/registry/");
    }

    #[test]
    fn iana_options_empty_when_all_duplicated() {
        // GIVEN an IANA set fully covered by the bootstrap set
        let bootstrap = vec!["https://a.example/rdap/".to_string()];
        let servers = vec![IanaServer {
            tag: "A".to_string(),
            url: "https://a.example/rdap".to_string(),
            key: "https://a.example/rdap".to_string(),
        }];
        // WHEN built
        // THEN nothing remains (trailing-slash-insensitive dedup)
        assert!(iana_display_options(&servers, &bootstrap).is_empty());
    }
}
