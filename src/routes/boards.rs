use crate::{
    auth::AuthAgent,
    db::{record_event, upsert_search_index},
    routes::{files::FileMeta, pings::auto_ping_mentions},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
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
    #[sqlx(skip)]
    pub attachments: Vec<FileMeta>,
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
    #[sqlx(skip)]
    pub attachments: Vec<FileMeta>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Post {
    pub id: String,
    pub thread_id: String,
    pub author_id: String,
    pub author_name: String,
    pub body: String,
    pub created_at: String,
    #[sqlx(skip)]
    pub attachments: Vec<FileMeta>,
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
    #[serde(default)]
    pub attachment_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct CreatePostReq {
    pub body: String,
    #[serde(default)]
    pub attachment_ids: Vec<String>,
}

#[derive(sqlx::FromRow)]
struct AttachmentRow {
    target_id: String,
    id: String,
    filename: String,
    content_type: String,
    size_bytes: i64,
    sha256: String,
    uploaded_by_id: String,
    uploaded_by_name: String,
    created_at: String,
}

fn extract_uuids_after_prefix(body: &str, prefix: &str, out: &mut Vec<String>) {
    let mut rest = body;
    while let Some(idx) = rest.find(prefix) {
        let after = &rest[idx + prefix.len()..];
        if after.len() >= 36 && after.is_char_boundary(36) {
            if let Ok(u) = Uuid::parse_str(&after[..36]) {
                out.push(u.to_string());
            }
        }
        rest = &rest[idx + prefix.len()..];
    }
}

pub fn extract_file_ids_from_body(body: &str) -> Vec<String> {
    let mut ids = Vec::new();
    extract_uuids_after_prefix(body, "file://", &mut ids);
    extract_uuids_after_prefix(body, "/api/v1/files/", &mut ids);
    ids
}

pub async fn link_attachments(
    pool: &SqlitePool,
    target_kind: &str,
    target_id: &str,
    explicit_ids: &[String],
    body: &str,
) -> Vec<FileMeta> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for raw in explicit_ids {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            candidates.push(trimmed.to_string());
        }
    }
    for extracted in extract_file_ids_from_body(body) {
        if seen.insert(extracted.clone()) {
            candidates.push(extracted);
        }
    }

    if candidates.is_empty() {
        return Vec::new();
    }

    let now = chrono::Utc::now().to_rfc3339();
    for file_id in &candidates {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO attachments (target_kind, target_id, file_id, created_at) SELECT ?, ?, id, ? FROM files WHERE id = ?",
        )
        .bind(target_kind)
        .bind(target_id)
        .bind(&now)
        .bind(file_id)
        .execute(pool)
        .await;
    }

    let mut map = fetch_attachments_for_targets(pool, target_kind, &[target_id.to_string()]).await;
    map.remove(target_id).unwrap_or_default()
}

pub async fn fetch_attachments_for_targets(
    pool: &SqlitePool,
    target_kind: &str,
    target_ids: &[String],
) -> HashMap<String, Vec<FileMeta>> {
    let mut map: HashMap<String, Vec<FileMeta>> = HashMap::new();
    if target_ids.is_empty() {
        return map;
    }

    let placeholders = vec!["?"; target_ids.len()].join(", ");
    let sql = format!(
        r#"
        SELECT a.target_id, f.id, f.filename, f.content_type, f.size_bytes, f.sha256,
               f.uploaded_by_id, f.uploaded_by_name, f.created_at
        FROM attachments a
        JOIN files f ON f.id = a.file_id
        WHERE a.target_kind = ? AND a.target_id IN ({placeholders})
        ORDER BY a.created_at ASC, f.created_at ASC
        "#
    );

    let mut q = sqlx::query_as::<_, AttachmentRow>(&sql).bind(target_kind);
    for id in target_ids {
        q = q.bind(id);
    }

    let rows = q.fetch_all(pool).await.unwrap_or_default();
    for r in rows {
        map.entry(r.target_id).or_default().push(FileMeta {
            id: r.id,
            filename: r.filename,
            content_type: r.content_type,
            size_bytes: r.size_bytes,
            sha256: r.sha256,
            uploaded_by_id: r.uploaded_by_id,
            uploaded_by_name: r.uploaded_by_name,
            created_at: r.created_at,
        });
    }

    map
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

#[derive(Deserialize)]
pub struct ListThreadsQuery {
    pub limit: Option<i64>,
    pub updated_since: Option<String>,
}

pub async fn query_threads_for_board(
    pool: &SqlitePool,
    board_id: &str,
    limit: Option<i64>,
    updated_since: Option<&str>,
) -> Result<Vec<ThreadSummary>, sqlx::Error> {
    let limit = limit.unwrap_or(50).clamp(1, 200);
    let updated_since = updated_since.map(str::trim).filter(|s| !s.is_empty());

    let mut threads: Vec<ThreadSummary> = if let Some(since) = updated_since {
        sqlx::query_as(
            r#"
            SELECT t.id, t.board_id, t.author_id, t.author_name, t.title, t.body, t.pinned,
                   t.created_at, t.updated_at, COUNT(p.id) AS post_count
            FROM threads t
            LEFT JOIN posts p ON p.thread_id = t.id
            WHERE t.board_id = ? AND t.updated_at >= ?
            GROUP BY t.id
            ORDER BY t.pinned DESC, t.updated_at DESC
            LIMIT ?
            "#,
        )
        .bind(board_id)
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT t.id, t.board_id, t.author_id, t.author_name, t.title, t.body, t.pinned,
                   t.created_at, t.updated_at, COUNT(p.id) AS post_count
            FROM threads t
            LEFT JOIN posts p ON p.thread_id = t.id
            WHERE t.board_id = ?
            GROUP BY t.id
            ORDER BY t.pinned DESC, t.updated_at DESC
            LIMIT ?
            "#,
        )
        .bind(board_id)
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    let thread_ids: Vec<String> = threads.iter().map(|t| t.id.clone()).collect();
    let mut att_map = fetch_attachments_for_targets(pool, "thread", &thread_ids).await;
    for t in &mut threads {
        t.attachments = att_map.remove(&t.id).unwrap_or_default();
    }
    Ok(threads)
}

pub async fn list_threads(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(query): Query<ListThreadsQuery>,
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

    match query_threads_for_board(
        &state.pool,
        &board_id,
        query.limit,
        query.updated_since.as_deref(),
    )
    .await
    {
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
            let attachments =
                link_attachments(&state.pool, "thread", &id, &req.attachment_ids, &body).await;
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
                    "updated_at": now,
                    "attachments": attachments
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

    let Some(mut thread) = thread else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "thread_not_found" }))).into_response();
    };

    let mut posts: Vec<Post> = sqlx::query_as(
        "SELECT id, thread_id, author_id, author_name, body, created_at FROM posts WHERE thread_id = ? ORDER BY created_at ASC",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut thread_att = fetch_attachments_for_targets(&state.pool, "thread", &[thread.id.clone()]).await;
    thread.attachments = thread_att.remove(&thread.id).unwrap_or_default();

    let post_ids: Vec<String> = posts.iter().map(|p| p.id.clone()).collect();
    let mut post_att = fetch_attachments_for_targets(&state.pool, "post", &post_ids).await;
    for p in &mut posts {
        p.attachments = post_att.remove(&p.id).unwrap_or_default();
    }

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
            let attachments =
                link_attachments(&state.pool, "post", &id, &req.attachment_ids, &body).await;
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
                    "created_at": now,
                    "attachments": attachments
                })),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}
