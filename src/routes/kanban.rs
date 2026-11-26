use crate::{
    auth::AuthAgent,
    db::{record_event, upsert_search_index},
    routes::{
        boards::{fetch_attachments_for_targets, link_attachments},
        files::FileMeta,
        pings::{extract_mentions, insert_and_broadcast_ping, resolve_active_agent},
    },
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistItem {
    pub text: String,
    #[serde(default)]
    pub done: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct KanbanColumn {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub position: i64,
    pub created_at: String,
}

#[derive(sqlx::FromRow)]
struct KanbanTicketRow {
    id: String,
    column_slug: String,
    position: i64,
    title: String,
    description: String,
    priority: String,
    labels_json: String,
    assignee_name: Option<String>,
    due_at: Option<String>,
    checklist_json: String,
    thread_id: Option<String>,
    wiki_slug: Option<String>,
    attachment_ids_json: String,
    comment_count: i64,
    created_by_id: String,
    created_by_name: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KanbanTicket {
    pub id: String,
    pub column_slug: String,
    pub position: i64,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub labels: Vec<String>,
    pub assignee_name: Option<String>,
    pub due_at: Option<String>,
    pub checklist: Vec<ChecklistItem>,
    pub thread_id: Option<String>,
    pub wiki_slug: Option<String>,
    pub attachment_ids: Vec<String>,
    pub comment_count: i64,
    pub created_by_id: String,
    pub created_by_name: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<KanbanTicketRow> for KanbanTicket {
    fn from(r: KanbanTicketRow) -> Self {
        Self {
            id: r.id,
            column_slug: r.column_slug,
            position: r.position,
            title: r.title,
            description: r.description,
            priority: r.priority,
            labels: serde_json::from_str(&r.labels_json).unwrap_or_default(),
            assignee_name: r.assignee_name,
            due_at: r.due_at,
            checklist: serde_json::from_str(&r.checklist_json).unwrap_or_default(),
            thread_id: r.thread_id,
            wiki_slug: r.wiki_slug,
            attachment_ids: serde_json::from_str(&r.attachment_ids_json).unwrap_or_default(),
            comment_count: r.comment_count,
            created_by_id: r.created_by_id,
            created_by_name: r.created_by_name,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct KanbanComment {
    pub id: String,
    pub ticket_id: String,
    pub author_id: String,
    pub author_name: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct KanbanFilterQuery {
    pub column: Option<String>,
    pub assignee: Option<String>,
    pub label: Option<String>,
    pub priority: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateColumnReq {
    pub slug: String,
    pub title: String,
    pub position: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTicketReq {
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub column_slug: Option<String>,
    pub position: Option<i64>,
    pub priority: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub assignee_name: Option<String>,
    pub due_at: Option<String>,
    #[serde(default)]
    pub checklist: Vec<ChecklistItem>,
    pub thread_id: Option<String>,
    pub wiki_slug: Option<String>,
    #[serde(default)]
    pub attachment_ids: Vec<String>,
}

fn deserialize_double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(Option::<String>::deserialize(deserializer)?))
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateTicketReq {
    pub title: Option<String>,
    pub description: Option<String>,
    pub column_slug: Option<String>,
    pub position: Option<i64>,
    pub priority: Option<String>,
    pub labels: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub assignee_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub due_at: Option<Option<String>>,
    pub checklist: Option<Vec<ChecklistItem>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub thread_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub wiki_slug: Option<Option<String>>,
    pub attachment_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct CreateCommentReq {
    pub body: String,
}

pub fn normalize_priority(raw: Option<&str>) -> Result<String, &'static str> {
    let val = raw.unwrap_or("medium").trim().to_lowercase();
    match val.as_str() {
        "low" | "medium" | "high" | "urgent" => Ok(val),
        _ => Err("invalid_priority"),
    }
}

fn clean_opt_str(opt: Option<String>) -> Option<String> {
    opt.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn clean_labels(labels: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for l in labels {
        let trimmed = l.trim().to_string();
        if !trimmed.is_empty() && seen.insert(trimmed.to_lowercase()) {
            out.push(trimmed);
        }
    }
    out
}

async fn column_exists(pool: &sqlx::SqlitePool, slug: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT slug FROM kanban_columns WHERE slug = ?")
        .bind(slug)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

async fn fetch_ticket_by_id(
    pool: &sqlx::SqlitePool,
    id: &str,
) -> Result<Option<KanbanTicket>, sqlx::Error> {
    let row: Option<KanbanTicketRow> = sqlx::query_as(
        r#"
        SELECT t.id, t.column_slug, t.position, t.title, t.description, t.priority,
               t.labels_json, t.assignee_name, t.due_at, t.checklist_json,
               t.thread_id, t.wiki_slug, t.attachment_ids_json,
               COUNT(c.id) AS comment_count,
               t.created_by_id, t.created_by_name, t.created_at, t.updated_at
        FROM kanban_tickets t
        LEFT JOIN kanban_comments c ON c.ticket_id = t.id
        WHERE t.id = ?
        GROUP BY t.id
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(KanbanTicket::from))
}

async fn ping_ticket_targets(
    state: &AppState,
    actor: &AuthAgent,
    assignee: Option<&str>,
    mention_text: &str,
    message: &str,
    thread_id: Option<&str>,
    wiki_slug: Option<&str>,
) {
    let mut seen_ids = HashSet::new();
    let mut targets: Vec<String> = Vec::new();

    if let Some(a) = assignee {
        let trimmed = a.trim();
        if !trimmed.is_empty() {
            targets.push(trimmed.to_string());
        }
    }
    for m in extract_mentions(mention_text) {
        targets.push(m);
    }

    for name in targets {
        if let Ok(Some((to_id, to_name))) = resolve_active_agent(&state.pool, &name).await {
            if to_id == actor.agent_id || !seen_ids.insert(to_id.clone()) {
                continue;
            }
            let _ = insert_and_broadcast_ping(
                state,
                actor,
                &to_id,
                &to_name,
                message,
                thread_id.map(str::to_string),
                None,
                wiki_slug.map(str::to_string),
            )
            .await;
        }
    }
}

pub async fn query_board(
    pool: &sqlx::SqlitePool,
    filter: &KanbanFilterQuery,
) -> Result<(Vec<KanbanColumn>, Vec<KanbanTicket>), sqlx::Error> {
    let columns: Vec<KanbanColumn> = sqlx::query_as(
        "SELECT id, slug, title, position, created_at FROM kanban_columns ORDER BY position ASC, created_at ASC",
    )
    .fetch_all(pool)
    .await?;

    let rows: Vec<KanbanTicketRow> = sqlx::query_as(
        r#"
        SELECT t.id, t.column_slug, t.position, t.title, t.description, t.priority,
               t.labels_json, t.assignee_name, t.due_at, t.checklist_json,
               t.thread_id, t.wiki_slug, t.attachment_ids_json,
               COUNT(c.id) AS comment_count,
               t.created_by_id, t.created_by_name, t.created_at, t.updated_at
        FROM kanban_tickets t
        LEFT JOIN kanban_comments c ON c.ticket_id = t.id
        GROUP BY t.id
        ORDER BY t.position ASC, t.updated_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let col_f = filter.column.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let ass_f = filter.assignee.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let lbl_f = filter.label.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let pri_f = filter.priority.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let tickets: Vec<KanbanTicket> = rows
        .into_iter()
        .map(KanbanTicket::from)
        .filter(|t| {
            if let Some(c) = col_f {
                if !t.column_slug.eq_ignore_ascii_case(c) {
                    return false;
                }
            }
            if let Some(a) = ass_f {
                match t.assignee_name.as_deref() {
                    Some(name) if name.eq_ignore_ascii_case(a) => {}
                    _ => return false,
                }
            }
            if let Some(p) = pri_f {
                if !t.priority.eq_ignore_ascii_case(p) {
                    return false;
                }
            }
            if let Some(l) = lbl_f {
                if !t.labels.iter().any(|item| item.eq_ignore_ascii_case(l)) {
                    return false;
                }
            }
            true
        })
        .collect();

    Ok((columns, tickets))
}

pub async fn get_board(
    State(state): State<AppState>,
    Query(filter): Query<KanbanFilterQuery>,
) -> impl IntoResponse {
    match query_board(&state.pool, &filter).await {
        Ok((columns, tickets)) => {
            Json(json!({ "columns": columns, "tickets": tickets })).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db_error" })),
        )
            .into_response(),
    }
}

pub async fn create_column(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Json(req): Json<CreateColumnReq>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "admin_required" })),
        )
            .into_response();
    }

    let slug = req.slug.trim().to_lowercase();
    let title = req.title.trim().to_string();
    if slug.is_empty()
        || title.is_empty()
        || !slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_column_input" })),
        )
            .into_response();
    }

    let position = match req.position {
        Some(p) => p,
        None => {
            let max_pos: Option<(Option<i64>,)> =
                sqlx::query_as("SELECT MAX(position) FROM kanban_columns")
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);
            max_pos.and_then(|(m,)| m).map(|m| m + 1).unwrap_or(0)
        }
    };

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO kanban_columns (id, slug, title, position, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&slug)
    .bind(&title)
    .bind(position)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => (
            StatusCode::CREATED,
            Json(json!({
                "column": KanbanColumn { id, slug, title, position, created_at: now }
            })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "column_already_exists" })),
        )
            .into_response(),
    }
}

pub async fn delete_column(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "admin_required" })),
        )
            .into_response();
    }

    if !column_exists(&state.pool, &slug).await.unwrap_or(false) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "column_not_found" })),
        )
            .into_response();
    }

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM kanban_tickets WHERE column_slug = ?")
            .bind(&slug)
            .fetch_one(&state.pool)
            .await
            .unwrap_or((0,));
    if count.0 > 0 {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "column_not_empty" })),
        )
            .into_response();
    }

    match sqlx::query("DELETE FROM kanban_columns WHERE slug = ?")
        .bind(&slug)
        .execute(&state.pool)
        .await
    {
        Ok(_) => Json(json!({ "deleted": slug })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db_error" })),
        )
            .into_response(),
    }
}

pub async fn create_ticket_inner(
    state: &AppState,
    agent: &AuthAgent,
    req: CreateTicketReq,
) -> Result<KanbanTicket, (StatusCode, &'static str)> {
    let title = req.title.trim().to_string();
    if title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title_required"));
    }

    let column_slug = req
        .column_slug
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("todo")
        .to_lowercase();

    if !column_exists(&state.pool, &column_slug)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
    {
        return Err((StatusCode::BAD_REQUEST, "invalid_column"));
    }

    let priority =
        normalize_priority(req.priority.as_deref()).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let position = req.position.unwrap_or(0);
    let description = req.description;
    let labels = clean_labels(req.labels);
    let assignee_name = clean_opt_str(req.assignee_name);
    let due_at = clean_opt_str(req.due_at);
    let thread_id = clean_opt_str(req.thread_id);
    let wiki_slug = clean_opt_str(req.wiki_slug);
    let checklist = req.checklist;
    let attachment_ids = req.attachment_ids;

    let labels_json = serde_json::to_string(&labels).unwrap_or_else(|_| "[]".into());
    let checklist_json = serde_json::to_string(&checklist).unwrap_or_else(|_| "[]".into());
    let attachment_ids_json =
        serde_json::to_string(&attachment_ids).unwrap_or_else(|_| "[]".into());

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO kanban_tickets (
            id, column_slug, position, title, description, priority,
            labels_json, assignee_name, due_at, checklist_json,
            thread_id, wiki_slug, attachment_ids_json,
            created_by_id, created_by_name, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&column_slug)
    .bind(position)
    .bind(&title)
    .bind(&description)
    .bind(&priority)
    .bind(&labels_json)
    .bind(&assignee_name)
    .bind(&due_at)
    .bind(&checklist_json)
    .bind(&thread_id)
    .bind(&wiki_slug)
    .bind(&attachment_ids_json)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;

    let _ = link_attachments(&state.pool, "ticket", &id, &attachment_ids, &description).await;
    let _ = upsert_search_index(&state.pool, "ticket", &id, &column_slug, &title, &description).await;
    let _ = record_event(
        &state.pool,
        "ticket.created",
        &agent.agent_id,
        &agent.name,
        &id,
        &format!("Created ticket [{column_slug}]: {title}"),
    )
    .await;

    let ping_msg = format!("Ticket assigned/mentioned [{column_slug}]: {title}");
    ping_ticket_targets(
        state,
        agent,
        assignee_name.as_deref(),
        &description,
        &ping_msg,
        thread_id.as_deref(),
        wiki_slug.as_deref(),
    )
    .await;

    let ticket = fetch_ticket_by_id(&state.pool, &id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;

    Ok(ticket)
}

pub async fn create_ticket(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Json(req): Json<CreateTicketReq>,
) -> impl IntoResponse {
    match create_ticket_inner(&state, &agent, req).await {
        Ok(ticket) => (StatusCode::CREATED, Json(json!({ "ticket": ticket }))).into_response(),
        Err((code, err)) => (code, Json(json!({ "error": err }))).into_response(),
    }
}

pub async fn get_ticket_inner(
    pool: &sqlx::SqlitePool,
    id: &str,
) -> Result<(KanbanTicket, Vec<KanbanComment>, Vec<FileMeta>), (StatusCode, &'static str)> {
    let ticket = fetch_ticket_by_id(pool, id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
        .ok_or((StatusCode::NOT_FOUND, "ticket_not_found"))?;

    let comments: Vec<KanbanComment> = sqlx::query_as(
        "SELECT id, ticket_id, author_id, author_name, body, created_at FROM kanban_comments WHERE ticket_id = ? ORDER BY created_at ASC",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut att_map = fetch_attachments_for_targets(pool, "ticket", &[id.to_string()]).await;
    let attachments = att_map.remove(id).unwrap_or_default();

    Ok((ticket, comments, attachments))
}

pub async fn get_ticket(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match get_ticket_inner(&state.pool, &id).await {
        Ok((ticket, comments, attachments)) => Json(json!({
            "ticket": ticket,
            "comments": comments,
            "attachments": attachments
        }))
        .into_response(),
        Err((code, err)) => (code, Json(json!({ "error": err }))).into_response(),
    }
}

pub async fn update_ticket_inner(
    state: &AppState,
    agent: &AuthAgent,
    id: &str,
    req: UpdateTicketReq,
) -> Result<KanbanTicket, (StatusCode, &'static str)> {
    let existing = fetch_ticket_by_id(&state.pool, id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
        .ok_or((StatusCode::NOT_FOUND, "ticket_not_found"))?;

    let title = match req.title {
        Some(t) => {
            let trimmed = t.trim().to_string();
            if trimmed.is_empty() {
                return Err((StatusCode::BAD_REQUEST, "title_required"));
            }
            trimmed
        }
        None => existing.title.clone(),
    };

    let description = req.description.unwrap_or_else(|| existing.description.clone());

    let column_slug = match req.column_slug {
        Some(c) => {
            let slug = c.trim().to_lowercase();
            if !column_exists(&state.pool, &slug)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
            {
                return Err((StatusCode::BAD_REQUEST, "invalid_column"));
            }
            slug
        }
        None => existing.column_slug.clone(),
    };

    let moved = column_slug != existing.column_slug;
    let position = req.position.unwrap_or(existing.position);

    let priority = match req.priority {
        Some(p) => normalize_priority(Some(&p)).map_err(|e| (StatusCode::BAD_REQUEST, e))?,
        None => existing.priority.clone(),
    };

    let labels = req.labels.map(clean_labels).unwrap_or_else(|| existing.labels.clone());
    let assignee_name = match req.assignee_name {
        Some(opt) => clean_opt_str(opt),
        None => existing.assignee_name.clone(),
    };
    let due_at = match req.due_at {
        Some(opt) => clean_opt_str(opt),
        None => existing.due_at.clone(),
    };
    let checklist = req.checklist.unwrap_or_else(|| existing.checklist.clone());
    let thread_id = match req.thread_id {
        Some(opt) => clean_opt_str(opt),
        None => existing.thread_id.clone(),
    };
    let wiki_slug = match req.wiki_slug {
        Some(opt) => clean_opt_str(opt),
        None => existing.wiki_slug.clone(),
    };
    let attachment_ids = req
        .attachment_ids
        .unwrap_or_else(|| existing.attachment_ids.clone());

    let labels_json = serde_json::to_string(&labels).unwrap_or_else(|_| "[]".into());
    let checklist_json = serde_json::to_string(&checklist).unwrap_or_else(|_| "[]".into());
    let attachment_ids_json =
        serde_json::to_string(&attachment_ids).unwrap_or_else(|_| "[]".into());
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE kanban_tickets
        SET column_slug = ?, position = ?, title = ?, description = ?, priority = ?,
            labels_json = ?, assignee_name = ?, due_at = ?, checklist_json = ?,
            thread_id = ?, wiki_slug = ?, attachment_ids_json = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&column_slug)
    .bind(position)
    .bind(&title)
    .bind(&description)
    .bind(&priority)
    .bind(&labels_json)
    .bind(&assignee_name)
    .bind(&due_at)
    .bind(&checklist_json)
    .bind(&thread_id)
    .bind(&wiki_slug)
    .bind(&attachment_ids_json)
    .bind(&now)
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;

    let _ = link_attachments(&state.pool, "ticket", id, &attachment_ids, &description).await;
    let _ = upsert_search_index(&state.pool, "ticket", id, &column_slug, &title, &description).await;

    let (ev_kind, ev_summary) = if moved {
        (
            "ticket.moved",
            format!(
                "Moved ticket {} -> {}: {}",
                existing.column_slug, column_slug, title
            ),
        )
    } else {
        ("ticket.updated", format!("Updated ticket: {title}"))
    };
    let _ = record_event(
        &state.pool,
        ev_kind,
        &agent.agent_id,
        &agent.name,
        id,
        &ev_summary,
    )
    .await;

    let assignee_changed = match (&existing.assignee_name, &assignee_name) {
        (Some(old), Some(new)) => !old.eq_ignore_ascii_case(new),
        (None, Some(_)) => true,
        _ => false,
    };
    if assignee_changed {
        if let Some(ref new_assignee) = assignee_name {
            let msg = format!("Assigned ticket [{column_slug}]: {title}");
            ping_ticket_targets(
                state,
                agent,
                Some(new_assignee),
                "",
                &msg,
                thread_id.as_deref(),
                wiki_slug.as_deref(),
            )
            .await;
        }
    }

    fetch_ticket_by_id(&state.pool, id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "db_error"))
}

pub async fn update_ticket(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(id): Path<String>,
    Json(req): Json<UpdateTicketReq>,
) -> impl IntoResponse {
    match update_ticket_inner(&state, &agent, &id, req).await {
        Ok(ticket) => Json(json!({ "ticket": ticket })).into_response(),
        Err((code, err)) => (code, Json(json!({ "error": err }))).into_response(),
    }
}

pub async fn delete_ticket_inner(
    state: &AppState,
    agent: &AuthAgent,
    id: &str,
) -> Result<(), (StatusCode, &'static str)> {
    let existing = fetch_ticket_by_id(&state.pool, id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
        .ok_or((StatusCode::NOT_FOUND, "ticket_not_found"))?;

    if existing.created_by_id != agent.agent_id && !agent.is_admin() {
        return Err((StatusCode::FORBIDDEN, "forbidden"));
    }

    sqlx::query("DELETE FROM kanban_tickets WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;

    let _ = sqlx::query("DELETE FROM search_index WHERE kind = 'ticket' AND item_id = ?")
        .bind(id)
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM attachments WHERE target_kind = 'ticket' AND target_id = ?")
        .bind(id)
        .execute(&state.pool)
        .await;

    let _ = record_event(
        &state.pool,
        "ticket.deleted",
        &agent.agent_id,
        &agent.name,
        id,
        &format!("Deleted ticket: {}", existing.title),
    )
    .await;

    Ok(())
}

pub async fn delete_ticket(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match delete_ticket_inner(&state, &agent, &id).await {
        Ok(()) => Json(json!({ "deleted": id })).into_response(),
        Err((code, err)) => (code, Json(json!({ "error": err }))).into_response(),
    }
}

pub async fn add_comment_inner(
    state: &AppState,
    agent: &AuthAgent,
    ticket_id: &str,
    raw_body: &str,
) -> Result<KanbanComment, (StatusCode, &'static str)> {
    let ticket = fetch_ticket_by_id(&state.pool, ticket_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?
        .ok_or((StatusCode::NOT_FOUND, "ticket_not_found"))?;

    let body = raw_body.trim().to_string();
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "body_required"));
    }

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO kanban_comments (id, ticket_id, author_id, author_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(ticket_id)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&body)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error"))?;

    let _ = sqlx::query("UPDATE kanban_tickets SET updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(ticket_id)
        .execute(&state.pool)
        .await;

    let _ = record_event(
        &state.pool,
        "ticket.commented",
        &agent.agent_id,
        &agent.name,
        ticket_id,
        &format!("Commented on ticket: {}", ticket.title),
    )
    .await;

    let snippet: String = body.chars().take(120).collect();
    let ping_msg = format!("New comment on ticket '{}': {}", ticket.title, snippet);
    ping_ticket_targets(
        state,
        agent,
        ticket.assignee_name.as_deref(),
        &body,
        &ping_msg,
        ticket.thread_id.as_deref(),
        ticket.wiki_slug.as_deref(),
    )
    .await;

    Ok(KanbanComment {
        id,
        ticket_id: ticket_id.to_string(),
        author_id: agent.agent_id.clone(),
        author_name: agent.name.clone(),
        body,
        created_at: now,
    })
}

pub async fn add_comment(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(ticket_id): Path<String>,
    Json(req): Json<CreateCommentReq>,
) -> impl IntoResponse {
    match add_comment_inner(&state, &agent, &ticket_id, &req.body).await {
        Ok(comment) => (StatusCode::CREATED, Json(json!({ "comment": comment }))).into_response(),
        Err((code, err)) => (code, Json(json!({ "error": err }))).into_response(),
    }
}
