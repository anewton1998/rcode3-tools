use askama::Template;
use axum::{
    http::{header, StatusCode},
    response::Html,
    routing::{get, post},
    Router,
};
use tower_http::services::ServeDir;
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
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
