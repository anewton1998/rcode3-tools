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
    record_type_select_html: String,
    doh_server_select_html: String,
    doh_server_input_html: String,
    progress_bar_html: String,
    theme_app_html: String,
    theme: &'static str,
    base: String,
    home_url: String,
    doh_url: String,
}

/// The DNS-over-HTTPS servers offered in the dropdown, in display order.
const DOH_SERVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://dns.google/dns-query",
];

/// Trims whitespace and trailing slashes so endpoint URLs compare equal
/// regardless of a trailing slash.
fn normalize_doh(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

/// Builds the DoH-server dropdown options and the default selection from the
/// configured `DOH_URL` value.
///
/// The env value is normalized (trimmed, trailing slashes stripped) before it
/// is compared or stored, so a value like `"/"` collapses to empty and a
/// trailing slash never leaks into the option/default that reaches the client.
///
/// - Env set (non-empty after normalization) → the env value is the default;
///   if it isn't already one of the listed servers it is prepended so it is
///   selectable.
/// - Empty (or degenerate) env → the default is the first server in the list.
fn compute_doh_url(env_doh: &str) -> (Vec<String>, String) {
    debug_assert!(
        !DOH_SERVERS.is_empty(),
        "DOH_SERVERS must contain at least one server"
    );
    let mut options: Vec<String> = DOH_SERVERS.iter().map(|s| s.to_string()).collect();
    let env = normalize_doh(env_doh);
    // `custom` is the dropdown's sentinel for the free-text box; a configured
    // value of `custom` would collide with it, so treat it as unset.
    if env.is_empty() || env.eq_ignore_ascii_case("custom") {
        let default = options[0].clone();
        return (options, default);
    }
    if !options.iter().any(|s| normalize_doh(s) == env) {
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
        .placeholder("example.com")
        .x_model("query")
        .enter_activates("#lookup-btn");

    let record_type_select = Select::new("record_type")
        .x_model("recordType")
        .groups_expr("recordTypeGroups");

    // DoH-server dropdown: the listed providers plus a "Custom" entry that
    // reveals the text box for an arbitrary endpoint.
    let (server_options, server_default) =
        compute_doh_url(&std::env::var("DOH_URL").unwrap_or_default());
    let mut doh_server_select = Select::new("doh_server")
        .x_model("serverChoice")
        .selected(&server_default);
    for opt in &server_options {
        doh_server_select = doh_server_select.option(opt, opt);
    }
    let doh_server_select = doh_server_select.option("custom", "Custom");

    let doh_server_input = TextInput::new("doh_server_custom")
        .x_model("serverCustom")
        .placeholder("https://doh.example.com/dns-query");

    let page = Explorer {
        search_input_html: search_input.render().map_err(render_error)?,
        record_type_select_html: record_type_select.render().map_err(render_error)?,
        doh_server_select_html: doh_server_select.render().map_err(render_error)?,
        doh_server_input_html: doh_server_input.render().map_err(render_error)?,
        progress_bar_html: ProgressBar.render().map_err(render_error)?,
        theme_app_html: ThemeAppSelect::new().render().map_err(render_error)?,
        theme: Theme::from_env().class_name(),
        base,
        home_url,
        doh_url: server_default,
    };
    // The page embeds runtime config (DoH default) and the inline app JS, so
    // it must never be cached — a stale copy would ship old logic and a stale
    // server default.
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
    fn normalize_doh_trims_slash_and_space() {
        assert_eq!(
            normalize_doh("  https://dns.example.com/dns-query//  "),
            "https://dns.example.com/dns-query"
        );
        assert_eq!(normalize_doh("https://dns.example"), "https://dns.example");
    }

    #[test]
    fn empty_env_defaults_to_first_server() {
        // GIVEN no configured DOH_URL
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("");
        // THEN the options are the servers as-is and the first is the default
        assert_eq!(
            options,
            DOH_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(default, DOH_SERVERS[0]);
    }

    #[test]
    fn env_already_in_list_becomes_default() {
        // GIVEN a configured DOH_URL that is already a listed server
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("https://dns.google/dns-query");
        // THEN nothing is prepended and the configured server is the default
        assert_eq!(options.len(), DOH_SERVERS.len());
        assert_eq!(default, "https://dns.google/dns-query");
    }

    #[test]
    fn env_not_in_list_is_prepended_and_default() {
        // GIVEN a configured DOH_URL not present in the list
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("https://custom.example/dns-query");
        // THEN it is prepended and becomes the default
        assert_eq!(options[0], "https://custom.example/dns-query");
        assert_eq!(options.len(), DOH_SERVERS.len() + 1);
        assert_eq!(default, "https://custom.example/dns-query");
    }

    #[test]
    fn env_match_ignores_trailing_slash() {
        // GIVEN a configured DOH_URL that matches a listed server only after
        // trailing-slash normalization
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("https://dns.google/dns-query/");
        // THEN it is treated as already present (not prepended) and the
        // normalized configured server is the default
        assert_eq!(options.len(), DOH_SERVERS.len());
        assert_eq!(default, "https://dns.google/dns-query");
    }

    #[test]
    fn whitespace_padded_env_in_list_is_not_prepended() {
        // GIVEN a listed server wrapped in whitespace
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("  https://dns.google/dns-query  ");
        // THEN it is recognized as present (not prepended) and is the default
        assert_eq!(options.len(), DOH_SERVERS.len());
        assert_eq!(default, "https://dns.google/dns-query");
    }

    #[test]
    fn whitespace_only_env_defaults_to_first_server() {
        // GIVEN a whitespace-only DOH_URL
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("   ");
        // THEN it collapses to empty and the first server is the default
        assert_eq!(options.len(), DOH_SERVERS.len());
        assert_eq!(default, DOH_SERVERS[0]);
    }

    #[test]
    fn custom_sentinel_env_is_treated_as_unset() {
        // GIVEN a DOH_URL that collides with the dropdown's "custom" sentinel
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("custom");
        // THEN it is not prepended (no duplicate `custom` option) and the
        // first listed server is the default
        assert_eq!(options.len(), DOH_SERVERS.len());
        assert_eq!(default, DOH_SERVERS[0]);
    }

    #[test]
    fn degenerate_slash_env_defaults_to_first_server() {
        // GIVEN a DOH_URL that normalizes to empty (just slashes)
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("//");
        // THEN it is treated as empty rather than prepended as a bogus server
        assert_eq!(options.len(), DOH_SERVERS.len());
        assert_eq!(default, DOH_SERVERS[0]);
    }

    #[test]
    fn prepended_env_is_stored_normalized() {
        // GIVEN an unlisted DOH_URL with a trailing slash
        // WHEN the dropdown is computed
        let (options, default) = compute_doh_url("https://x.example/dns-query/");
        // THEN the stored option/default have the trailing slash stripped
        assert_eq!(options[0], "https://x.example/dns-query");
        assert_eq!(default, "https://x.example/dns-query");
    }

    #[test]
    fn default_is_always_an_option() {
        // The default must be selectable in every branch.
        for env in [
            "",
            "   ",
            "//",
            "https://dns.google/dns-query",
            "https://new.example/dns-query/",
        ] {
            let (options, default) = compute_doh_url(env);
            assert!(
                options.contains(&default),
                "default {default} not in options for {env:?}"
            );
        }
    }
}
