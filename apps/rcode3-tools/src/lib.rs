use askama::Template;
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::Html,
    routing::get,
};
use tower_http::services::ServeDir;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;
use ui_components::Theme;

#[derive(Template)]
#[template(path = "home.html")]
struct Home {
    theme: &'static str,
    themes: Vec<Theme>,
    base: String,
}

fn render_error(_: askama::Error) -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn render_home(State(base): State<String>) -> Result<Html<String>, StatusCode> {
    let page = Home {
        theme: Theme::from_env().class_name(),
        themes: Theme::all().to_vec(),
        base,
    };
    Ok(Html(page.render().map_err(render_error)?))
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

    let app = Router::new()
        .route("/", get(render_home))
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
