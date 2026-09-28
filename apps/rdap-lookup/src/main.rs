use askama::Template;
use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::Html,
    routing::{get, post},
};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use ui_components::{Button, Theme, TextInput};

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Dashboard {
    button_html: String,
    search_input_html: String,
    theme: &'static str,
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusMessage {
    text: String,
}

fn render_error(_: askama::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn render_dashboard() -> Result<Html<String>, StatusCode> {
    // Instantiate shared button with HTMX attributes directly
    let button = Button::new("Save Settings")
        .hx_post("/api/settings")
        .hx_target("#status-message");

    let search_input = TextInput::new("query")
        .placeholder("example.com or 192.0.2.1")
        .x_model("query")
        .enter_activates("#lookup-btn");

    let page = Dashboard {
        button_html: button.render().map_err(render_error)?,
        search_input_html: search_input.render().map_err(render_error)?,
        theme: Theme::from_env().class_name(),
    };
    Ok(Html(page.render().map_err(render_error)?))
}

async fn save_settings() -> Result<Html<String>, StatusCode> {
    // HTMX fragment response: swapped into #status-message by the client.
    let fragment = StatusMessage {
        text: "Settings saved".to_string(),
    };
    Ok(Html(fragment.render().map_err(render_error)?))
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = match std::env::var("PORT") {
        Ok(value) => value.parse().expect("PORT must be a valid port number"),
        Err(_) => 3000,
    };
    let cors_origin = std::env::var("CORS_ORIGIN").unwrap_or_else(|_| "*".to_string());
    let cors_methods = std::env::var("CORS_METHODS").unwrap_or_else(|_| "*".to_string());
    let cors_headers = std::env::var("CORS_HEADERS").unwrap_or_else(|_| "*".to_string());

    let base_css = ui_components::global_css();

    let app = Router::new()
        .route("/", get(render_dashboard))
        .route("/api/settings", post(save_settings))
        .route(
            "/base.css",
            get(move || async move {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    base_css,
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
        );

    let listener = tokio::net::TcpListener::bind((host.as_str(), port))
        .await
        .unwrap();
    tracing::info!(%host, port, "listening");
    axum::serve(listener, app).await.unwrap();
}
