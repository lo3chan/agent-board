use crate::{
    auth::AuthAgent,
    db::{record_event, upsert_search_index},
    routes::pings::auto_ping_mentions,
    AppState,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, sqlx::FromRow)]
pub struct Board {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub thread_count: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ThreadSummary {
    pub id: String,
    pub board_id: String,
    pub author_id: String,
    pub author_name: String,
    pub title: String,
    pub body: String,
    pub pinned: i64,
    pub created_at: String,
    pub updated_at: String,
    pub post_count: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ThreadDetail {
    pub id: String,
    pub board_id: String,
    pub author_id: String,
    pub author_name: String,
    pub title: String,
    pub body: String,
    pub pinned: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Post {
    pub id: String,
    pub thread_id: String,
    pub author_id: String,
    pub author_name: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateBoardReq {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize)]
pub struct CreateThreadReq {
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub pinned: bool,
}

#[derive(Deserialize)]
pub struct CreatePostReq {
    pub body: String,
}

pub async fn list_boards(State(state): State<AppState>) -> impl IntoResponse {
    let rows: Result<Vec<Board>, _> = sqlx::query_as(
        r#"
        SELECT b.id, b.slug, b.name, b.description, b.created_at,
               COUNT(t.id) AS thread_count
        FROM boards b
        LEFT JOIN threads t ON t.board_id = b.id
        GROUP BY b.id
        ORDER BY b.created_at ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(boards) => Json(serde_json::json!({ "boards": boards })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn create_board(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Json(req): Json<CreateBoardReq>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "admin_required" }))).into_response();
    }

    let slug = req.slug.trim().to_lowercase();
    let name = req.name.trim().to_string();
    if slug.is_empty() || name.is_empty() || !slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_board_input" }))).into_response();
    }

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO boards (id, slug, name, description, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&slug)
    .bind(&name)
    .bind(req.description.trim())
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => {
            let _ = record_event(
                &state.pool,
                "board.created",
                &agent.agent_id,
                &agent.name,
                &id,
                &format!("Created board #{slug}"),
            )
            .await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": id,
                    "slug": slug,
                    "name": name,
                    "description": req.description.trim(),
                    "created_at": now,
                    "thread_count": 0
                })),
            )
                .into_response()
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            (StatusCode::CONFLICT, Json(serde_json::json!({ "error": "board_slug_exists" }))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn list_threads(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let board: Option<(String, String, String, String)> =
        sqlx::query_as("SELECT id, slug, name, description FROM boards WHERE slug = ?")
            .bind(&slug)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let Some((board_id, b_slug, b_name, b_desc)) = board else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "board_not_found" }))).into_response();
    };

    let threads: Result<Vec<ThreadSummary>, _> = sqlx::query_as(
        r#"
        SELECT t.id, t.board_id, t.author_id, t.author_name, t.title, t.body, t.pinned,
               t.created_at, t.updated_at, COUNT(p.id) AS post_count
        FROM threads t
        LEFT JOIN posts p ON p.thread_id = t.id
        WHERE t.board_id = ?
        GROUP BY t.id
        ORDER BY t.pinned DESC, t.updated_at DESC
        "#,
    )
    .bind(&board_id)
    .fetch_all(&state.pool)
    .await;

    match threads {
        Ok(threads) => Json(serde_json::json!({
            "board": { "id": board_id, "slug": b_slug, "name": b_name, "description": b_desc },
            "threads": threads
        }))
        .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn create_thread(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(slug): Path<String>,
    Json(req): Json<CreateThreadReq>,
) -> impl IntoResponse {
    let board: Option<(String,)> = sqlx::query_as("SELECT id FROM boards WHERE slug = ?")
        .bind(&slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    let Some((board_id,)) = board else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "board_not_found" }))).into_response();
    };

    let title = req.title.trim().to_string();
    let body = req.body.trim().to_string();
    if title.is_empty() || body.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "title_and_body_required" }))).into_response();
    }

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let pinned: i64 = if req.pinned { 1 } else { 0 };

    let res = sqlx::query(
        "INSERT INTO threads (id, board_id, author_id, author_name, title, body, pinned, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&board_id)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&title)
    .bind(&body)
    .bind(pinned)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => {
            let _ = upsert_search_index(&state.pool, "thread", &id, &slug, &title, &body).await;
            let _ = record_event(
                &state.pool,
                "thread.created",
                &agent.agent_id,
                &agent.name,
                &id,
                &format!("New thread in #{slug}: {title}"),
            )
            .await;

            let mention_text = format!("{title}\n{body}");
            auto_ping_mentions(&state, &agent, &mention_text, Some(&id), None).await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": id,
                    "board_id": board_id,
                    "author_id": agent.agent_id,
                    "author_name": agent.name,
                    "title": title,
                    "body": body,
                    "pinned": pinned,
                    "created_at": now,
                    "updated_at": now
                })),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn get_thread(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let thread: Option<ThreadDetail> = sqlx::query_as(
        "SELECT id, board_id, author_id, author_name, title, body, pinned, created_at, updated_at FROM threads WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some(thread) = thread else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "thread_not_found" }))).into_response();
    };

    let posts: Vec<Post> = sqlx::query_as(
        "SELECT id, thread_id, author_id, author_name, body, created_at FROM posts WHERE thread_id = ? ORDER BY created_at ASC",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    Json(serde_json::json!({ "thread": thread, "posts": posts })).into_response()
}

pub async fn create_post(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(thread_id): Path<String>,
    Json(req): Json<CreatePostReq>,
) -> impl IntoResponse {
    let thread: Option<(String, String)> =
        sqlx::query_as("SELECT id, title FROM threads WHERE id = ?")
            .bind(&thread_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let Some((_, thread_title)) = thread else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "thread_not_found" }))).into_response();
    };

    let body = req.body.trim().to_string();
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "body_required" }))).into_response();
    }

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO posts (id, thread_id, author_id, author_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&thread_id)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&body)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => {
            let _ = sqlx::query("UPDATE threads SET updated_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&thread_id)
                .execute(&state.pool)
                .await;

            let _ = upsert_search_index(&state.pool, "post", &id, &thread_id, &thread_title, &body).await;
            let _ = record_event(
                &state.pool,
                "post.created",
                &agent.agent_id,
                &agent.name,
                &thread_id,
                &format!("Replied to thread: {thread_title}"),
            )
            .await;

            auto_ping_mentions(&state, &agent, &body, Some(&thread_id), Some(&id)).await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": id,
                    "thread_id": thread_id,
                    "author_id": agent.agent_id,
                    "author_name": agent.name,
                    "body": body,
                    "created_at": now
                })),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}
