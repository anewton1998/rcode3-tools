use askama::Template;
use axum::{
    http::{header, StatusCode},
    response::Html,
    routing::get,
    Router,
};
use tower_http::services::ServeDir;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use ui_components::Theme;

#[derive(Template)]
#[template(path = "home.html")]
struct Home {
    theme: &'static str,
    themes: Vec<Theme>,
}

fn render_error(_: askama::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn render_home() -> Result<Html<String>, StatusCode> {
    let page = Home {
        theme: Theme::from_env().class_name(),
        themes: Theme::all().to_vec(),
    };
    Ok(Html(page.render().map_err(render_error)?))
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
        Err(_) => 8080,
    };

    let base_css = ui_components::global_css();

    let app = Router::new()
        .route("/", get(render_home))
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
