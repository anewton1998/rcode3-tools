use askama::Template;
use axum::{
    Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::Html,
    routing::{get, post},
};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use ui_components::{ProgressBar, Select, TextInput, Theme};

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Dashboard {
    search_input_html: String,
    query_type_select_html: String,
    progress_bar_html: String,
    theme: &'static str,
    base: String,
    home_url: String,
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusMessage {
    text: String,
}

fn render_error(_: askama::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn render_dashboard(State(base): State<String>) -> Result<Html<String>, StatusCode> {
    let home_url = std::env::var("HOME_URL").unwrap_or_else(|_| "/".to_string());

    let search_input = TextInput::new("query")
        .placeholder("example.com or 192.0.2.1")
        .x_model("query")
        .enter_activates("#lookup-btn");

    let query_type_select = Select::new("query_type")
        .x_model("queryType")
        .groups_expr("queryTypeGroups");

    let page = Dashboard {
        search_input_html: search_input.render().map_err(render_error)?,
        query_type_select_html: query_type_select.render().map_err(render_error)?,
        progress_bar_html: ProgressBar.render().map_err(render_error)?,
        theme: Theme::from_env().class_name(),
        base,
        home_url,
    };
    Ok(Html(page.render().map_err(render_error)?))
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
        .route("/", get(render_dashboard))
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
