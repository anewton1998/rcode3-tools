use axum::{routing::get, Router};
use ui_components::Button;

async fn render_dashboard() -> Button<'static> {
    // Instantiate shared button with HTMX attributes directly
    Button::new("Save Settings")
        .hx_post("/api/settings")
        .hx_target("#status-message")
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(render_dashboard));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
