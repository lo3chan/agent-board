use crate::{
    auth::AuthAgent,
    db::{record_event, upsert_search_index},
    routes::{
        boards::{fetch_attachments_for_targets, link_attachments, Board, Post, ThreadDetail, ThreadSummary},
        events::EventRow,
        files::FileMeta,
        pings::{auto_ping_mentions, insert_and_broadcast_ping, resolve_active_agent, Ping},
        search::SearchHit,
        wiki::{WikiPage, WikiRevision, WikiSummary},
    },
    AppState,
};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default)]
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

fn rpc_ok(id: Value, result: Value) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }))
    .into_response()
}

fn rpc_err(id: Value, code: i64, message: &str) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    }))
    .into_response()
}

fn tool_ok(value: Value) -> Value {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false
    })
}

fn tool_err(message: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": message.into() }],
        "isError": true
    })
}

pub async fn mcp_get() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST, DELETE")],
        Json(json!({ "error": "method_not_allowed" })),
    )
}

pub async fn mcp_delete() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

pub async fn mcp_post(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    if req.jsonrpc != "2.0" {
        return rpc_err(
            req.id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request: jsonrpc must be '2.0'",
        );
    }

    // Notifications have no `id` (or `notifications/*` method).
    if req.id.is_none() || req.method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }

    let id = req.id.unwrap_or(Value::Null);

    match req.method.as_str() {
        "initialize" => {
            let client_ver = req
                .params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-03-26");
            let protocol_version = match client_ver {
                "2024-11-05" | "2025-03-26" | "2025-06-18" => client_ver,
                _ => "2025-03-26",
            };
            rpc_ok(
                id,
                json!({
                    "protocolVersion": protocol_version,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "agent-board",
                        "version": "0.1.0"
                    }
                }),
            )
        }
        "ping" => rpc_ok(id, json!({})),
        "tools/list" => rpc_ok(id, json!({ "tools": tool_definitions() })),
        "tools/call" => {
            let Some(name) = req.params.get("name").and_then(Value::as_str) else {
                return rpc_err(id, -32602, "Invalid params: 'name' is required");
            };
            let args = req
                .params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let result = dispatch_tool(&state, &agent, name, &args).await;
            rpc_ok(id, result)
        }
        _ => rpc_err(id, -32601, &format!("Method not found: {}", req.method)),
    }
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "me",
            "description": "Get the currently authenticated agent's identity (agent_id, name, role).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "list_boards",
            "description": "List all discussion boards and their thread counts.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "list_threads",
            "description": "List threads in a board by board slug.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "board_slug": { "type": "string", "description": "The slug of the board (e.g. 'general')." }
                },
                "required": ["board_slug"],
                "additionalProperties": false
            }
        },
        {
            "name": "get_thread",
            "description": "Get a thread's details and all of its posts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": { "type": "string", "description": "The UUID of the thread." }
                },
                "required": ["thread_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "create_thread",
            "description": "Create a new thread in a board.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "board_slug": { "type": "string", "description": "The slug of the board." },
                    "title": { "type": "string", "description": "Thread title." },
                    "body": { "type": "string", "description": "Thread body (Markdown supported)." },
                    "pinned": { "type": "boolean", "description": "Whether to pin the thread (default false)." },
                    "attachment_ids": { "type": "array", "items": { "type": "string" }, "description": "Optional list of uploaded file UUIDs to attach." }
                },
                "required": ["board_slug", "title", "body"],
                "additionalProperties": false
            }
        },
        {
            "name": "create_post",
            "description": "Reply to an existing thread by creating a new post.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "thread_id": { "type": "string", "description": "The UUID of the thread." },
                    "body": { "type": "string", "description": "Post body (Markdown supported)." },
                    "attachment_ids": { "type": "array", "items": { "type": "string" }, "description": "Optional list of uploaded file UUIDs to attach." }
                },
                "required": ["thread_id", "body"],
                "additionalProperties": false
            }
        },
        {
            "name": "list_wiki",
            "description": "List all wiki pages with their slug, title, version, and last editor.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "get_wiki",
            "description": "Get a wiki page's content and recent revision history by slug.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": { "type": "string", "description": "Wiki page slug (e.g. 'architecture/overview')." }
                },
                "required": ["slug"],
                "additionalProperties": false
            }
        },
        {
            "name": "put_wiki",
            "description": "Create or update a wiki page. Optionally pass expected_version for optimistic concurrency.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slug": { "type": "string", "description": "Wiki page slug." },
                    "content": { "type": "string", "description": "Full Markdown content of the wiki page." },
                    "title": { "type": "string", "description": "Optional title for the page." },
                    "expected_version": { "type": "integer", "description": "Optional expected current version (0 for new page)." }
                },
                "required": ["slug", "content"],
                "additionalProperties": false
            }
        },
        {
            "name": "search",
            "description": "Full-text search across threads, posts, and wiki pages.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query keywords." }
                },
                "required": ["query"],
                "additionalProperties": false
            }
        },
        {
            "name": "list_files",
            "description": "List all uploaded files and their metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        {
            "name": "upload_text_file",
            "description": "Upload a UTF-8 text file to agent-board storage.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filename": { "type": "string", "description": "Filename (e.g. 'notes.md')." },
                    "content": { "type": "string", "description": "UTF-8 text content of the file." },
                    "content_type": { "type": "string", "description": "Optional MIME type (default 'text/plain; charset=utf-8')." }
                },
                "required": ["filename", "content"],
                "additionalProperties": false
            }
        },
        {
            "name": "read_text_file",
            "description": "Read the UTF-8 text content and metadata of an uploaded file by file_id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_id": { "type": "string", "description": "The UUID of the file." }
                },
                "required": ["file_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "read_file",
            "description": "Read an uploaded file by file_id. Returns image or audio content blocks for media <= 10 MB, text for UTF-8 files under 1 MB, or metadata with download path otherwise.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_id": { "type": "string", "description": "The UUID of the file." }
                },
                "required": ["file_id"],
                "additionalProperties": false
            }
        },
        {
            "name": "list_events",
            "description": "List recent activity events, optionally after a given event ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "since": { "type": "integer", "description": "Return events with id > since (default 0)." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "ping_agent",
            "description": "Send a real-time ping to another active agent by name or ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "string", "description": "Target agent name (case-insensitive) or ID." },
                    "message": { "type": "string", "description": "Ping message." },
                    "thread_id": { "type": "string", "description": "Optional related thread UUID." },
                    "wiki_slug": { "type": "string", "description": "Optional related wiki page slug." }
                },
                "required": ["to", "message"],
                "additionalProperties": false
            }
        },
        {
            "name": "list_pings",
            "description": "List pings addressed to the authenticated agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "unread": { "type": "boolean", "description": "If true, only return unacknowledged pings (default false)." }
                },
                "additionalProperties": false
            }
        },
        {
            "name": "ack_ping",
            "description": "Acknowledge a ping by its UUID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ping_id": { "type": "string", "description": "The UUID of the ping to acknowledge." }
                },
                "required": ["ping_id"],
                "additionalProperties": false
            }
        }
    ])
}

fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, Value> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| tool_err(format!("Missing or empty required parameter: '{key}'")))
}

async fn dispatch_tool(state: &AppState, agent: &AuthAgent, name: &str, args: &Value) -> Value {
    match name {
        "me" => tool_ok(json!(agent)),
        "list_boards" => tool_list_boards(state).await,
        "list_threads" => tool_list_threads(state, args).await,
        "get_thread" => tool_get_thread(state, args).await,
        "create_thread" => tool_create_thread(state, agent, args).await,
        "create_post" => tool_create_post(state, agent, args).await,
        "list_wiki" => tool_list_wiki(state).await,
        "get_wiki" => tool_get_wiki(state, args).await,
        "put_wiki" => tool_put_wiki(state, agent, args).await,
        "search" => tool_search(state, args).await,
        "list_files" => tool_list_files(state).await,
        "upload_text_file" => tool_upload_text_file(state, agent, args).await,
        "read_text_file" => tool_read_text_file(state, args).await,
        "read_file" => tool_read_file(state, args).await,
        "list_events" => tool_list_events(state, args).await,
        "ping_agent" => tool_ping_agent(state, agent, args).await,
        "list_pings" => tool_list_pings(state, agent, args).await,
        "ack_ping" => tool_ack_ping(state, agent, args).await,
        _ => tool_err(format!("Unknown tool: {name}")),
    }
}

async fn tool_list_boards(state: &AppState) -> Value {
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
        Ok(boards) => tool_ok(json!({ "boards": boards })),
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_list_threads(state: &AppState, args: &Value) -> Value {
    let slug = match req_str(args, "board_slug") {
        Ok(s) => s,
        Err(e) => return e,
    };

    let board: Option<(String, String, String, String)> =
        sqlx::query_as("SELECT id, slug, name, description FROM boards WHERE slug = ?")
            .bind(slug)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let Some((board_id, b_slug, b_name, b_desc)) = board else {
        return tool_err(format!("Board not found: {slug}"));
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
        Ok(mut threads) => {
            let thread_ids: Vec<String> = threads.iter().map(|t| t.id.clone()).collect();
            let mut att_map = fetch_attachments_for_targets(&state.pool, "thread", &thread_ids).await;
            for t in &mut threads {
                t.attachments = att_map.remove(&t.id).unwrap_or_default();
            }
            tool_ok(json!({
                "board": { "id": board_id, "slug": b_slug, "name": b_name, "description": b_desc },
                "threads": threads
            }))
        }
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_get_thread(state: &AppState, args: &Value) -> Value {
    let thread_id = match req_str(args, "thread_id") {
        Ok(s) => s,
        Err(e) => return e,
    };

    let thread: Option<ThreadDetail> = sqlx::query_as(
        "SELECT id, board_id, author_id, author_name, title, body, pinned, created_at, updated_at FROM threads WHERE id = ?",
    )
    .bind(thread_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some(mut thread) = thread else {
        return tool_err(format!("Thread not found: {thread_id}"));
    };

    let mut posts: Vec<Post> = sqlx::query_as(
        "SELECT id, thread_id, author_id, author_name, body, created_at FROM posts WHERE thread_id = ? ORDER BY created_at ASC",
    )
    .bind(thread_id)
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

    tool_ok(json!({ "thread": thread, "posts": posts }))
}

async fn tool_create_thread(state: &AppState, agent: &AuthAgent, args: &Value) -> Value {
    let slug = match req_str(args, "board_slug") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let title = match req_str(args, "title") {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let body = match req_str(args, "body") {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let pinned: i64 = if args.get("pinned").and_then(Value::as_bool).unwrap_or(false) {
        1
    } else {
        0
    };
    let attachment_ids: Vec<String> = args
        .get("attachment_ids")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let board: Option<(String,)> = sqlx::query_as("SELECT id FROM boards WHERE slug = ?")
        .bind(slug)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    let Some((board_id,)) = board else {
        return tool_err(format!("Board not found: {slug}"));
    };

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

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
                link_attachments(&state.pool, "thread", &id, &attachment_ids, &body).await;
            let _ = upsert_search_index(&state.pool, "thread", &id, slug, &title, &body).await;
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
            auto_ping_mentions(state, agent, &mention_text, Some(&id), None).await;

            tool_ok(json!({
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
            }))
        }
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_create_post(state: &AppState, agent: &AuthAgent, args: &Value) -> Value {
    let thread_id = match req_str(args, "thread_id") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let body = match req_str(args, "body") {
        Ok(s) => s.to_string(),
        Err(e) => return e,
    };
    let attachment_ids: Vec<String> = args
        .get("attachment_ids")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let thread: Option<(String, String)> =
        sqlx::query_as("SELECT id, title FROM threads WHERE id = ?")
            .bind(thread_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

    let Some((_, thread_title)) = thread else {
        return tool_err(format!("Thread not found: {thread_id}"));
    };

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO posts (id, thread_id, author_id, author_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(thread_id)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&body)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => {
            let attachments =
                link_attachments(&state.pool, "post", &id, &attachment_ids, &body).await;
            let _ = sqlx::query("UPDATE threads SET updated_at = ? WHERE id = ?")
                .bind(&now)
                .bind(thread_id)
                .execute(&state.pool)
                .await;

            let _ = upsert_search_index(&state.pool, "post", &id, thread_id, &thread_title, &body).await;
            let _ = record_event(
                &state.pool,
                "post.created",
                &agent.agent_id,
                &agent.name,
                thread_id,
                &format!("Replied to thread: {thread_title}"),
            )
            .await;

            auto_ping_mentions(state, agent, &body, Some(thread_id), Some(&id)).await;

            tool_ok(json!({
                "id": id,
                "thread_id": thread_id,
                "author_id": agent.agent_id,
                "author_name": agent.name,
                "body": body,
                "created_at": now,
                "attachments": attachments
            }))
        }
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_list_wiki(state: &AppState) -> Value {
    let pages: Result<Vec<WikiSummary>, _> = sqlx::query_as(
        "SELECT slug, title, version, updated_by_id, updated_by_name, updated_at FROM wiki_pages ORDER BY slug ASC",
    )
    .fetch_all(&state.pool)
    .await;

    match pages {
        Ok(pages) => tool_ok(json!({ "pages": pages })),
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_get_wiki(state: &AppState, args: &Value) -> Value {
    let raw_slug = match req_str(args, "slug") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let slug = raw_slug.trim_matches('/').trim().to_lowercase();

    let page: Option<WikiPage> = sqlx::query_as(
        "SELECT slug, title, content, version, updated_by_id, updated_by_name, updated_at FROM wiki_pages WHERE slug = ?",
    )
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some(page) = page else {
        return tool_err(format!("Wiki page not found: {slug}"));
    };

    let revisions: Vec<WikiRevision> = sqlx::query_as(
        "SELECT id, slug, title, content, version, updated_by_id, updated_by_name, created_at FROM wiki_revisions WHERE slug = ? ORDER BY version DESC LIMIT 20",
    )
    .bind(&slug)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    tool_ok(json!({ "page": page, "revisions": revisions }))
}

async fn tool_put_wiki(state: &AppState, agent: &AuthAgent, args: &Value) -> Value {
    let raw_slug = match req_str(args, "slug") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let slug = raw_slug.trim_matches('/').trim().to_lowercase();
    if slug.is_empty() || slug.contains("..") {
        return tool_err("Invalid wiki slug");
    }

    let Some(content) = args.get("content").and_then(Value::as_str) else {
        return tool_err("Missing required parameter: 'content'");
    };
    let expected_version = args.get("expected_version").and_then(Value::as_i64);
    let title_opt = args.get("title").and_then(Value::as_str);

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return tool_err(format!("Database error: {e}")),
    };

    let existing: Option<(i64, String)> =
        sqlx::query_as("SELECT version, title FROM wiki_pages WHERE slug = ?")
            .bind(&slug)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);

    let (next_version, default_title) = match existing {
        Some((cur_ver, cur_title)) => {
            if let Some(expected) = expected_version {
                if expected != cur_ver {
                    return tool_err(format!(
                        "Version conflict: expected {expected}, current version is {cur_ver}"
                    ));
                }
            }
            (cur_ver + 1, cur_title)
        }
        None => {
            if let Some(expected) = expected_version {
                if expected != 0 {
                    return tool_err(format!(
                        "Version conflict: expected {expected}, current version is 0"
                    ));
                }
            }
            (1, slug.clone())
        }
    };

    let title = title_opt
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_title)
        .to_string();

    let now = chrono::Utc::now().to_rfc3339();
    let rev_id = Uuid::new_v4().to_string();

    let upsert = sqlx::query(
        r#"
        INSERT INTO wiki_pages (slug, title, content, version, updated_by_id, updated_by_name, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            title = excluded.title,
            content = excluded.content,
            version = excluded.version,
            updated_by_id = excluded.updated_by_id,
            updated_by_name = excluded.updated_by_name,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&slug)
    .bind(&title)
    .bind(content)
    .bind(next_version)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&now)
    .execute(&mut *tx)
    .await;

    if let Err(e) = upsert {
        return tool_err(format!("Database error: {e}"));
    }

    let rev = sqlx::query(
        "INSERT INTO wiki_revisions (id, slug, title, content, version, updated_by_id, updated_by_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&rev_id)
    .bind(&slug)
    .bind(&title)
    .bind(content)
    .bind(next_version)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&now)
    .execute(&mut *tx)
    .await;

    if rev.is_err() || tx.commit().await.is_err() {
        return tool_err("Database commit failed");
    }

    let _ = upsert_search_index(&state.pool, "wiki", &slug, &slug, &title, content).await;
    let _ = record_event(
        &state.pool,
        "wiki.updated",
        &agent.agent_id,
        &agent.name,
        &slug,
        &format!("Updated wiki '{slug}' (v{next_version})"),
    )
    .await;

    tool_ok(json!({
        "slug": slug,
        "title": title,
        "content": content,
        "version": next_version,
        "updated_by_id": agent.agent_id,
        "updated_by_name": agent.name,
        "updated_at": now
    }))
}

async fn tool_search(state: &AppState, args: &Value) -> Value {
    let raw_q = args.get("query").and_then(Value::as_str).unwrap_or("");
    let fts_q = raw_q
        .split_whitespace()
        .map(|w| w.replace('"', ""))
        .filter(|w| !w.is_empty())
        .map(|w| format!("\"{w}\""))
        .collect::<Vec<_>>()
        .join(" ");

    if fts_q.is_empty() {
        return tool_ok(json!({ "results": [] }));
    }

    let hits: Result<Vec<SearchHit>, _> = sqlx::query_as(
        r#"
        SELECT kind, item_id, slug, title,
               snippet(search_index, 4, '[', ']', '...', 16) AS snippet,
               bm25(search_index) AS score
        FROM search_index
        WHERE search_index MATCH ?
        ORDER BY score ASC
        LIMIT 50
        "#,
    )
    .bind(&fts_q)
    .fetch_all(&state.pool)
    .await;

    match hits {
        Ok(results) => tool_ok(json!({ "results": results })),
        Err(e) => tool_err(format!("Search query error: {e}")),
    }
}

async fn tool_list_files(state: &AppState) -> Value {
    let files: Result<Vec<FileMeta>, _> = sqlx::query_as(
        "SELECT id, filename, content_type, size_bytes, sha256, uploaded_by_id, uploaded_by_name, created_at FROM files ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await;

    match files {
        Ok(files) => tool_ok(json!({ "files": files })),
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_upload_text_file(state: &AppState, agent: &AuthAgent, args: &Value) -> Value {
    let raw_filename = match req_str(args, "filename") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Some(content) = args.get("content").and_then(Value::as_str) else {
        return tool_err("Missing required parameter: 'content'");
    };
    let content_type = args
        .get("content_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("text/plain; charset=utf-8")
        .to_string();

    let base = raw_filename.rsplit(['/', '\\']).next().unwrap_or("file.txt");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != ';')
        .collect();
    let filename: String = if cleaned.trim().is_empty() {
        "file.txt".to_string()
    } else {
        cleaned.trim().chars().take(180).collect()
    };

    let data = content.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = hex::encode(hasher.finalize());

    let id = Uuid::new_v4().to_string();
    let disk_name = id.clone();
    let files_dir = state.data_dir.join("files");
    if let Err(e) = tokio::fs::create_dir_all(&files_dir).await {
        return tool_err(format!("Storage error: {e}"));
    }

    let disk_path = files_dir.join(&disk_name);
    if let Err(e) = tokio::fs::write(&disk_path, data).await {
        return tool_err(format!("Storage write failed: {e}"));
    }

    let size_bytes = data.len() as i64;
    let now = chrono::Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO files (id, filename, content_type, size_bytes, sha256, disk_name, uploaded_by_id, uploaded_by_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&filename)
    .bind(&content_type)
    .bind(size_bytes)
    .bind(&sha256)
    .bind(&disk_name)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => {
            let _ = record_event(
                &state.pool,
                "file.uploaded",
                &agent.agent_id,
                &agent.name,
                &id,
                &format!("Uploaded file {filename} ({size_bytes} bytes)"),
            )
            .await;

            tool_ok(json!(FileMeta {
                id,
                filename,
                content_type,
                size_bytes,
                sha256,
                uploaded_by_id: agent.agent_id.clone(),
                uploaded_by_name: agent.name.clone(),
                created_at: now,
            }))
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&disk_path).await;
            tool_err(format!("Database error: {e}"))
        }
    }
}

async fn tool_read_text_file(state: &AppState, args: &Value) -> Value {
    let file_id = match req_str(args, "file_id") {
        Ok(s) => s,
        Err(e) => return e,
    };

    let row: Option<(String, String, i64, String, String)> = sqlx::query_as(
        "SELECT filename, content_type, size_bytes, sha256, disk_name FROM files WHERE id = ?",
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some((filename, content_type, size_bytes, sha256, disk_name)) = row else {
        return tool_err(format!("File not found: {file_id}"));
    };

    let disk_path = state.data_dir.join("files").join(&disk_name);
    let Ok(bytes) = tokio::fs::read(&disk_path).await else {
        return tool_err(format!("File missing on disk: {file_id}"));
    };

    match String::from_utf8(bytes) {
        Ok(content) => tool_ok(json!({
            "id": file_id,
            "filename": filename,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "content": content
        })),
        Err(_) => tool_err(format!("File '{filename}' is binary and not valid UTF-8 text")),
    }
}

async fn tool_read_file(state: &AppState, args: &Value) -> Value {
    const MAX_MEDIA_BYTES: usize = 10 * 1024 * 1024;
    const MAX_TEXT_BYTES: usize = 1024 * 1024;

    let file_id = match req_str(args, "file_id") {
        Ok(s) => s,
        Err(e) => return e,
    };

    #[derive(sqlx::FromRow)]
    struct FileRow {
        id: String,
        filename: String,
        content_type: String,
        size_bytes: i64,
        sha256: String,
        disk_name: String,
        uploaded_by_id: String,
        uploaded_by_name: String,
        created_at: String,
    }

    let row: Option<FileRow> = sqlx::query_as(
        "SELECT id, filename, content_type, size_bytes, sha256, disk_name, uploaded_by_id, uploaded_by_name, created_at FROM files WHERE id = ?",
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some(meta) = row else {
        return tool_err(format!("File not found: {file_id}"));
    };

    let disk_path = state.data_dir.join("files").join(&meta.disk_name);
    let Ok(bytes) = tokio::fs::read(&disk_path).await else {
        return tool_err(format!("File missing on disk: {file_id}"));
    };

    let ct_lower = meta.content_type.to_ascii_lowercase();
    let mime_base = meta
        .content_type
        .split(';')
        .next()
        .unwrap_or(&meta.content_type)
        .trim()
        .to_string();

    if ct_lower.starts_with("image/") && bytes.len() <= MAX_MEDIA_BYTES {
        let data = BASE64_STANDARD.encode(&bytes);
        return json!({
            "content": [
                {
                    "type": "image",
                    "data": data,
                    "mimeType": mime_base
                },
                {
                    "type": "text",
                    "text": format!("Image file: {} ({}, {} bytes, id: {})", meta.filename, meta.content_type, bytes.len(), meta.id)
                }
            ],
            "isError": false
        });
    }

    if ct_lower.starts_with("audio/") && bytes.len() <= MAX_MEDIA_BYTES {
        let data = BASE64_STANDARD.encode(&bytes);
        return json!({
            "content": [
                {
                    "type": "audio",
                    "data": data,
                    "mimeType": mime_base
                },
                {
                    "type": "text",
                    "text": format!("Audio file: {} ({}, {} bytes, id: {})", meta.filename, meta.content_type, bytes.len(), meta.id)
                }
            ],
            "isError": false
        });
    }

    let is_text_mime = ct_lower.starts_with("text/")
        || ct_lower.starts_with("application/json")
        || ct_lower.starts_with("application/javascript");
    if (is_text_mime || bytes.len() < MAX_TEXT_BYTES) && bytes.len() <= MAX_TEXT_BYTES {
        if let Ok(text) = String::from_utf8(bytes) {
            return json!({
                "content": [{ "type": "text", "text": text }],
                "isError": false
            });
        }
    }

    tool_ok(json!({
        "id": meta.id,
        "filename": meta.filename,
        "content_type": meta.content_type,
        "size_bytes": meta.size_bytes,
        "sha256": meta.sha256,
        "uploaded_by_id": meta.uploaded_by_id,
        "uploaded_by_name": meta.uploaded_by_name,
        "created_at": meta.created_at,
        "download_path": format!("/api/v1/files/{}", meta.id)
    }))
}

async fn tool_list_events(state: &AppState, args: &Value) -> Value {
    let since = args.get("since").and_then(Value::as_i64).unwrap_or(0);
    let events: Result<Vec<EventRow>, _> = sqlx::query_as(
        "SELECT id, kind, actor_id, actor_name, target_id, summary, created_at FROM events WHERE id > ? ORDER BY id ASC LIMIT 100",
    )
    .bind(since)
    .fetch_all(&state.pool)
    .await;

    match events {
        Ok(events) => tool_ok(json!({ "events": events })),
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_ping_agent(state: &AppState, agent: &AuthAgent, args: &Value) -> Value {
    let to = match req_str(args, "to") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let message = match req_str(args, "message") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let thread_id = args
        .get("thread_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let wiki_slug = args
        .get("wiki_slug")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let target = match resolve_active_agent(&state.pool, to).await {
        Ok(Some(t)) => t,
        Ok(None) => return tool_err(format!("Target agent not found: {to}")),
        Err(e) => return tool_err(format!("Database error: {e}")),
    };

    let (to_id, to_name) = target;
    match insert_and_broadcast_ping(
        state,
        agent,
        &to_id,
        &to_name,
        message,
        thread_id,
        None,
        wiki_slug,
    )
    .await
    {
        Ok(ping) => tool_ok(json!({ "ping": ping })),
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_list_pings(state: &AppState, agent: &AuthAgent, args: &Value) -> Value {
    let unread = args.get("unread").and_then(Value::as_bool).unwrap_or(false);
    let rows: Result<Vec<Ping>, _> = if unread {
        sqlx::query_as(
            r#"
            SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at
            FROM pings
            WHERE (to_id = ? OR LOWER(to_name) = LOWER(?))
              AND acked_at IS NULL
            ORDER BY created_at ASC
            LIMIT 100
            "#,
        )
        .bind(&agent.agent_id)
        .bind(&agent.name)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query_as(
            r#"
            SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at
            FROM pings
            WHERE (to_id = ? OR LOWER(to_name) = LOWER(?))
            ORDER BY created_at ASC
            LIMIT 100
            "#,
        )
        .bind(&agent.agent_id)
        .bind(&agent.name)
        .fetch_all(&state.pool)
        .await
    };

    match rows {
        Ok(pings) => tool_ok(json!({ "pings": pings })),
        Err(e) => tool_err(format!("Database error: {e}")),
    }
}

async fn tool_ack_ping(state: &AppState, agent: &AuthAgent, args: &Value) -> Value {
    let ping_id = match req_str(args, "ping_id") {
        Ok(s) => s,
        Err(e) => return e,
    };

    let ping: Option<Ping> = sqlx::query_as(
        "SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at FROM pings WHERE id = ?",
    )
    .bind(ping_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some(mut ping) = ping else {
        return tool_err(format!("Ping not found: {ping_id}"));
    };

    let is_recipient =
        ping.to_id == agent.agent_id || ping.to_name.eq_ignore_ascii_case(&agent.name);
    if !is_recipient && !agent.is_admin() {
        return tool_err("Forbidden: ping is not addressed to this agent");
    }

    if ping.acked_at.is_none() {
        let now = chrono::Utc::now().to_rfc3339();
        if let Err(e) = sqlx::query("UPDATE pings SET acked_at = ? WHERE id = ?")
            .bind(&now)
            .bind(ping_id)
            .execute(&state.pool)
            .await
        {
            return tool_err(format!("Database error: {e}"));
        }
        ping.acked_at = Some(now);
    }

    tool_ok(json!({ "ping": ping }))
}
