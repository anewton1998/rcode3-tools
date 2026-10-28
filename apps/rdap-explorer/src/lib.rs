use askama::Template;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Html,
    routing::{get, post},
};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use ui_components::{ProgressBar, Select, TextInput, Theme, ThemeAppSelect};

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
    exts_list: String,
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
fn normalize_bootstrap(url: &str) -> String {
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

#[derive(Template)]
#[template(path = "status.html")]
struct StatusMessage {
    text: String,
}

fn render_error(_: askama::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn render_explorer(
    State(base): State<String>,
) -> Result<(HeaderMap, Html<String>), StatusCode> {
    let home_url = std::env::var("HOME_URL").unwrap_or_else(|_| "/".to_string());

    let search_input = TextInput::new("query")
        .placeholder("example.com or 192.0.2.1")
        .x_model("query")
        .enter_activates("#lookup-btn");

    let query_type_select = Select::new("query_type")
        .x_model("queryType")
        .groups_expr("queryTypeGroups");

    // Base-URL dropdown: the bootstrap servers plus a "Custom" entry that
    // reveals the text box. Disabled (with a note) for the Explicit URL type,
    // which ignores any base URL.
    let (base_options, base_default) =
        compute_base_url(&std::env::var("BOOTSTRAP_URL").unwrap_or_default());
    let mut base_url_select = Select::new("base_url")
        .x_model("baseUrlChoice")
        .x_bind_disabled("baseSelectDisabled")
        .selected(&base_default);
    for opt in &base_options {
        base_url_select = base_url_select.option(opt, opt);
    }
    let base_url_select = base_url_select.option("custom", "Custom");

    let base_url_input = TextInput::new("base_url_custom")
        .x_model("baseUrlCustom")
        .x_bind_disabled("isUrlType")
        .placeholder("https://my-rdap.example.com/base");

    let page = Explorer {
        search_input_html: search_input.render().map_err(render_error)?,
        query_type_select_html: query_type_select.render().map_err(render_error)?,
        base_url_select_html: base_url_select.render().map_err(render_error)?,
        base_url_input_html: base_url_input.render().map_err(render_error)?,
        progress_bar_html: ProgressBar.render().map_err(render_error)?,
        theme_app_html: ThemeAppSelect::new().render().map_err(render_error)?,
        theme: Theme::from_env().class_name(),
        base,
        home_url,
        bootstrap_url: base_default,
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
        .with_state(url_base);

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
}
