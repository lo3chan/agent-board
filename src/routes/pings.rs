use crate::{
    auth::AuthAgent,
    db::record_event,
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Extension, Json,
};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct Ping {
    pub id: String,
    pub from_id: String,
    pub from_name: String,
    pub to_id: String,
    pub to_name: String,
    pub message: String,
    pub thread_id: Option<String>,
    pub post_id: Option<String>,
    pub wiki_slug: Option<String>,
    pub created_at: String,
    pub acked_at: Option<String>,
}

#[derive(Deserialize)]
pub struct CreatePingReq {
    pub to: String,
    pub message: String,
    pub thread_id: Option<String>,
    pub post_id: Option<String>,
    pub wiki_slug: Option<String>,
}

#[derive(Deserialize)]
pub struct ListPingsQuery {
    #[serde(default)]
    pub unread: bool,
    pub since: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct StreamQuery {
    pub filter: Option<String>,
}

struct MpscEventStream {
    rx: mpsc::Receiver<Result<Event, Infallible>>,
}

impl Stream for MpscEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

pub async fn resolve_active_agent(
    pool: &sqlx::SqlitePool,
    target: &str,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    sqlx::query_as(
        "SELECT id, name FROM tokens WHERE revoked_at IS NULL AND (id = ? OR LOWER(name) = LOWER(?)) LIMIT 1",
    )
    .bind(trimmed)
    .bind(trimmed)
    .fetch_optional(pool)
    .await
}

pub async fn insert_and_broadcast_ping(
    state: &AppState,
    from: &AuthAgent,
    to_id: &str,
    to_name: &str,
    message: &str,
    thread_id: Option<String>,
    post_id: Option<String>,
    wiki_slug: Option<String>,
) -> Result<Ping, sqlx::Error> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO pings (id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        "#,
    )
    .bind(&id)
    .bind(&from.agent_id)
    .bind(&from.name)
    .bind(to_id)
    .bind(to_name)
    .bind(message)
    .bind(&thread_id)
    .bind(&post_id)
    .bind(&wiki_slug)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    let ping = Ping {
        id: id.clone(),
        from_id: from.agent_id.clone(),
        from_name: from.name.clone(),
        to_id: to_id.to_string(),
        to_name: to_name.to_string(),
        message: message.to_string(),
        thread_id,
        post_id,
        wiki_slug,
        created_at: now,
        acked_at: None,
    };

    let preview: String = message.chars().take(80).collect();
    let _ = record_event(
        &state.pool,
        "ping",
        &from.agent_id,
        &from.name,
        &id,
        &format!("Pinged @{to_name}: {preview}"),
    )
    .await;

    let payload = json!({
        "type": "ping",
        "to_id": ping.to_id,
        "to_name": ping.to_name,
        "ping": ping,
    });
    let _ = state.tx.send(payload);

    Ok(ping)
}

pub fn extract_mentions(text: &str) -> Vec<String> {
    let mut mentions = Vec::new();
    let mut seen = HashSet::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '@' {
            let prev_ok = i == 0
                || !(chars[i - 1].is_ascii_alphanumeric()
                    || chars[i - 1] == '_'
                    || chars[i - 1] == '-');
            if prev_ok {
                let start = i + 1;
                let mut end = start;
                while end < len
                    && (chars[end].is_ascii_alphanumeric()
                        || chars[end] == '_'
                        || chars[end] == '-')
                {
                    end += 1;
                }
                if end > start {
                    let name: String = chars[start..end].iter().collect();
                    let lower = name.to_lowercase();
                    if seen.insert(lower) {
                        mentions.push(name);
                    }
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }

    mentions
}

pub async fn auto_ping_mentions(
    state: &AppState,
    actor: &AuthAgent,
    text: &str,
    thread_id: Option<&str>,
    post_id: Option<&str>,
) {
    let mentions = extract_mentions(text);
    if mentions.is_empty() {
        return;
    }

    let snippet: String = text.trim().chars().take(160).collect();
    let msg = if post_id.is_some() {
        format!("Mentioned you in a reply: {snippet}")
    } else {
        format!("Mentioned you in a thread: {snippet}")
    };

    for name in mentions {
        if let Ok(Some((to_id, to_name))) = resolve_active_agent(&state.pool, &name).await {
            if to_id == actor.agent_id {
                continue;
            }
            let _ = insert_and_broadcast_ping(
                state,
                actor,
                &to_id,
                &to_name,
                &msg,
                thread_id.map(str::to_string),
                post_id.map(str::to_string),
                None,
            )
            .await;
        }
    }
}

pub async fn create_ping(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Json(req): Json<CreatePingReq>,
) -> impl IntoResponse {
    let message = req.message.trim();
    if message.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "message_required" })),
        )
            .into_response();
    }

    let target = match resolve_active_agent(&state.pool, &req.to).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "target_agent_not_found" })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db_error" })),
            )
                .into_response();
        }
    };

    let (to_id, to_name) = target;
    let thread_id = req.thread_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let post_id = req.post_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let wiki_slug = req.wiki_slug.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    match insert_and_broadcast_ping(
        &state,
        &agent,
        &to_id,
        &to_name,
        message,
        thread_id,
        post_id,
        wiki_slug,
    )
    .await
    {
        Ok(ping) => (StatusCode::CREATED, Json(json!({ "ping": ping }))).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db_error" })),
        )
            .into_response(),
    }
}

pub async fn list_pings(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Query(q): Query<ListPingsQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let since = q
        .since
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    let rows: Result<Vec<Ping>, _> = match (q.unread, !since.is_empty()) {
        (true, true) => {
            sqlx::query_as(
                r#"
                SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at
                FROM pings
                WHERE (to_id = ? OR LOWER(to_name) = LOWER(?))
                  AND acked_at IS NULL
                  AND created_at > ?
                ORDER BY created_at ASC
                LIMIT ?
                "#,
            )
            .bind(&agent.agent_id)
            .bind(&agent.name)
            .bind(since)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
        (true, false) => {
            sqlx::query_as(
                r#"
                SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at
                FROM pings
                WHERE (to_id = ? OR LOWER(to_name) = LOWER(?))
                  AND acked_at IS NULL
                ORDER BY created_at ASC
                LIMIT ?
                "#,
            )
            .bind(&agent.agent_id)
            .bind(&agent.name)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
        (false, true) => {
            sqlx::query_as(
                r#"
                SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at
                FROM pings
                WHERE (to_id = ? OR LOWER(to_name) = LOWER(?))
                  AND created_at > ?
                ORDER BY created_at ASC
                LIMIT ?
                "#,
            )
            .bind(&agent.agent_id)
            .bind(&agent.name)
            .bind(since)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
        (false, false) => {
            sqlx::query_as(
                r#"
                SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at
                FROM pings
                WHERE (to_id = ? OR LOWER(to_name) = LOWER(?))
                ORDER BY created_at ASC
                LIMIT ?
                "#,
            )
            .bind(&agent.agent_id)
            .bind(&agent.name)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
        }
    };

    match rows {
        Ok(pings) => Json(json!({ "pings": pings })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "db_error" })),
        )
            .into_response(),
    }
}

pub async fn ack_ping(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let ping: Option<Ping> = sqlx::query_as(
        "SELECT id, from_id, from_name, to_id, to_name, message, thread_id, post_id, wiki_slug, created_at, acked_at FROM pings WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some(mut ping) = ping else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "ping_not_found" })),
        )
            .into_response();
    };

    let is_recipient =
        ping.to_id == agent.agent_id || ping.to_name.eq_ignore_ascii_case(&agent.name);
    if !is_recipient && !agent.is_admin() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "forbidden" })),
        )
            .into_response();
    }

    if ping.acked_at.is_none() {
        let now = chrono::Utc::now().to_rfc3339();
        if sqlx::query("UPDATE pings SET acked_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&id)
            .execute(&state.pool)
            .await
            .is_err()
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "db_error" })),
            )
                .into_response();
        }
        ping.acked_at = Some(now);
    }

    Json(json!({ "ping": ping })).into_response()
}

pub async fn stream_events(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Query(q): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let filter_all = q
        .filter
        .as_deref()
        .map(|f| f.trim().eq_ignore_ascii_case("all"))
        .unwrap_or(false);

    let mut rx = state.tx.subscribe();
    let (mpsc_tx, mpsc_rx) = mpsc::channel::<Result<Event, Infallible>>(64);

    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(val) => {
                    if !filter_all {
                        let matches_id = val
                            .get("to_id")
                            .and_then(Value::as_str)
                            .map(|id| id == agent.agent_id)
                            .unwrap_or(false);
                        let matches_name = val
                            .get("to_name")
                            .and_then(Value::as_str)
                            .map(|name| name.eq_ignore_ascii_case(&agent.name))
                            .unwrap_or(false);
                        if !matches_id && !matches_name {
                            continue;
                        }
                    }

                    let event_name = val
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("ping");
                    let ev = Event::default().event(event_name).data(val.to_string());
                    if mpsc_tx.send(Ok(ev)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Sse::new(MpscEventStream { rx: mpsc_rx }).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
