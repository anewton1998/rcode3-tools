#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = match std::env::var("PORT") {
        Ok(value) => value.parse().expect("PORT must be a valid port number"),
        Err(_) => 3000,
    };
    let base = std::env::var("BASE_PATH").unwrap_or_else(|_| "/".to_string());

    let app = rdap_lookup::router(&base);

    let listener = tokio::net::TcpListener::bind((host.as_str(), port))
        .await
        .unwrap();
    tracing::info!(%host, port, %base, "listening");
    axum::serve(listener, app).await.unwrap();
}
