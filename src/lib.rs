pub mod auth;
pub mod db;
pub mod routes;

use axum::{
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use sqlx::SqlitePool;
use std::path::PathBuf;
use tower_http::trace::TraceLayer;

const UI_HTML: &str = include_str!("../static/index.html");

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub data_dir: PathBuf,
}

async fn ui_handler() -> Html<&'static str> {
    Html(UI_HTML)
}

async fn me_handler(Extension(agent): Extension<auth::AuthAgent>) -> Json<auth::AuthAgent> {
    Json(agent)
}

async fn not_found_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not_found" })),
    )
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/", get(ui_handler))
        .route("/ui", get(ui_handler))
        .route("/api/v1/me", get(me_handler))
        .route("/api/v1/boards", get(routes::boards::list_boards))
        .route("/api/v1/admin/boards", post(routes::boards::create_board))
        .route(
            "/api/v1/boards/{slug}/threads",
            get(routes::boards::list_threads).post(routes::boards::create_thread),
        )
        .route("/api/v1/threads/{id}", get(routes::boards::get_thread))
        .route("/api/v1/threads/{id}/posts", post(routes::boards::create_post))
        .route("/api/v1/wiki", get(routes::wiki::list_wiki))
        .route(
            "/api/v1/wiki/{*slug}",
            get(routes::wiki::get_wiki).put(routes::wiki::put_wiki),
        )
        .route("/api/v1/search", get(routes::search::search_all))
        .route(
            "/api/v1/files",
            get(routes::files::list_files).post(routes::files::upload_file),
        )
        .route("/api/v1/files/{id}", get(routes::files::download_file))
        .route("/api/v1/files/{id}/meta", get(routes::files::get_file_meta))
        .route("/api/v1/events", get(routes::events::list_events))
        .route(
            "/api/v1/admin/tokens",
            get(routes::admin::list_tokens).post(routes::admin::mint_token),
        )
        .route("/api/v1/admin/tokens/{id}", delete(routes::admin::revoke_token))
        .fallback(not_found_handler)
        .layer(DefaultBodyLimit::max(routes::files::MAX_UPLOAD_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(state.clone(), auth::require_auth))
        .with_state(state)
}
