use crate::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct EventsQuery {
    pub since: Option<i64>,
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

pub async fn list_events(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> impl IntoResponse {
    let since = q.since.unwrap_or(0);
    let events: Result<Vec<EventRow>, _> = sqlx::query_as(
        "SELECT id, kind, actor_id, actor_name, target_id, summary, created_at FROM events WHERE id > ? ORDER BY id ASC LIMIT 100",
    )
    .bind(since)
    .fetch_all(&state.pool)
    .await;

    match events {
        Ok(events) => Json(serde_json::json!({ "events": events })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}
