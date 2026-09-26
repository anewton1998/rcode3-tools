use askama::Template;
use axum::{
    http::{header, StatusCode},
    response::Html,
    routing::{get, post},
    Router,
};
use tower_http::services::ServeDir;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use ui_components::Button;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Dashboard {
    button_html: String,
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

    let page = Dashboard {
        button_html: button.render().map_err(render_error)?,
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
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = match std::env::var("PORT") {
        Ok(value) => value.parse().expect("PORT must be a valid port number"),
        Err(_) => 3000,
    };

    let base_css = ui_components::global_base_css().expect("base css compiles at startup");

    let app = Router::new()
        .route("/", get(render_dashboard))
        .route("/api/settings", post(save_settings))
        .route(
            "/base.css",
            get(move || async move {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    base_css.clone(),
                )
            }),
        )
        .nest_service(
            "/static",
            ServeDir::new(format!("{}/static", env!("CARGO_MANIFEST_DIR"))),
        )
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
