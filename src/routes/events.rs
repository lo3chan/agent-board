use crate::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Deserialize)]
pub struct EventsQuery {
    pub since: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct EventRow {
    pub id: i64,
    pub kind: String,
    pub actor_id: String,
    pub actor_name: String,
    pub target_id: String,
    pub summary: String,
    pub created_at: String,
}

pub async fn fetch_events(
    pool: &SqlitePool,
    since: i64,
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    let limit = limit.clamp(1, 500);
    if since > 0 {
        sqlx::query_as(
            "SELECT id, kind, actor_id, actor_name, target_id, summary, created_at FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
        )
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as(
            "SELECT id, kind, actor_id, actor_name, target_id, summary, created_at FROM events ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

pub async fn list_events(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> impl IntoResponse {
    let since = q.since.unwrap_or(0);
    let limit = q.limit.unwrap_or(100);
    match fetch_events(&state.pool, since, limit).await {
        Ok(events) => Json(serde_json::json!({ "events": events })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}
