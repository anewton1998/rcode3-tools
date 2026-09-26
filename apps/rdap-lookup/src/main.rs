use askama::Template;
use axum::{response::Html, routing::get, Router};
use ui_components::Button;

async fn render_dashboard() -> Result<Html<String>, axum::http::StatusCode> {
    // Instantiate shared button with HTMX attributes directly
    let button = Button::new("Save Settings")
        .hx_post("/api/settings")
        .hx_target("#status-message");

    Ok(Html(
        button
            .render()
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?,
    ))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(render_dashboard));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
