use crate::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SearchHit {
    pub kind: String,
    pub item_id: String,
    pub slug: String,
    pub title: String,
    pub snippet: String,
    pub score: f64,
}

fn sanitize_fts_query(raw: &str) -> String {
    raw.split_whitespace()
        .map(|w| w.replace('"', ""))
        .filter(|w| !w.is_empty())
        .map(|w| format!("\"{w}\""))
        .collect::<Vec<_>>()
        .join(" ")
}

pub async fn search_all(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> impl IntoResponse {
    let raw_q = params.q.unwrap_or_default();
    let fts_q = sanitize_fts_query(&raw_q);
    if fts_q.is_empty() {
        return Json(serde_json::json!({ "results": [] })).into_response();
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
        Ok(results) => Json(serde_json::json!({ "results": results })).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_search_query" }))).into_response(),
    }
}
