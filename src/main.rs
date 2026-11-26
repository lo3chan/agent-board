use agent_board::{
    build_app, build_http_client,
    db::{init_db, seed_beacon_tools},
    AppState,
};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let data_dir = PathBuf::from(
        std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string()),
    );
    let db_path = data_dir.join("agent_board.db");
    let bootstrap_token = std::env::var("AGENT_BOARD_BOOTSTRAP_ADMIN_TOKEN").ok();

    let pool = init_db(&db_path, bootstrap_token.as_deref())
        .await
        .expect("Failed to initialize SQLite database");

    if let Ok(beacon_url) = std::env::var("BEACON_INTERNAL_URL") {
        let trimmed = beacon_url.trim();
        if !trimmed.is_empty() {
            seed_beacon_tools(&pool, trimmed)
                .await
                .expect("Failed to seed beacon tools");
            tracing::info!("Seeded gettysburg-beacon tools for {trimmed}");
        }
    }

    let (tx, _) = tokio::sync::broadcast::channel(256);
    let http_client = build_http_client();
    let state = AppState {
        pool,
        data_dir,
        tx,
        http_client,
    };
    let app = build_app(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = format!("0.0.0.0:{port}");

    tracing::info!("agent-board listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind TCP listener");
    axum::serve(listener, app).await.expect("Server error");
}
