use crate::{
    auth::AuthAgent,
    db::{record_event, upsert_search_index},
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
pub struct WikiSummary {
    pub slug: String,
    pub title: String,
    pub version: i64,
    pub updated_by_id: String,
    pub updated_by_name: String,
    pub updated_at: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct WikiPage {
    pub slug: String,
    pub title: String,
    pub content: String,
    pub version: i64,
    pub updated_by_id: String,
    pub updated_by_name: String,
    pub updated_at: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct WikiRevision {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub content: String,
    pub version: i64,
    pub updated_by_id: String,
    pub updated_by_name: String,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct PutWikiReq {
    pub title: Option<String>,
    pub content: String,
    pub expected_version: Option<i64>,
}

fn normalize_slug(raw: &str) -> String {
    raw.trim_matches('/').trim().to_lowercase()
}

pub async fn list_wiki(State(state): State<AppState>) -> impl IntoResponse {
    let pages: Result<Vec<WikiSummary>, _> = sqlx::query_as(
        "SELECT slug, title, version, updated_by_id, updated_by_name, updated_at FROM wiki_pages ORDER BY slug ASC",
    )
    .fetch_all(&state.pool)
    .await;

    match pages {
        Ok(pages) => Json(serde_json::json!({ "pages": pages })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn get_wiki(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let slug = normalize_slug(&slug);
    let page: Option<WikiPage> = sqlx::query_as(
        "SELECT slug, title, content, version, updated_by_id, updated_by_name, updated_at FROM wiki_pages WHERE slug = ?",
    )
    .bind(&slug)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some(page) = page else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "wiki_not_found" }))).into_response();
    };

    let revisions: Vec<WikiRevision> = sqlx::query_as(
        "SELECT id, slug, title, content, version, updated_by_id, updated_by_name, created_at FROM wiki_revisions WHERE slug = ? ORDER BY version DESC LIMIT 20",
    )
    .bind(&slug)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    Json(serde_json::json!({ "page": page, "revisions": revisions })).into_response()
}

pub async fn put_wiki(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(slug): Path<String>,
    Json(req): Json<PutWikiReq>,
) -> impl IntoResponse {
    let slug = normalize_slug(&slug);
    if slug.is_empty() || slug.contains("..") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_slug" }))).into_response();
    }

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    };

    let existing: Option<(i64, String)> =
        sqlx::query_as("SELECT version, title FROM wiki_pages WHERE slug = ?")
            .bind(&slug)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);

    let (next_version, default_title) = match existing {
        Some((cur_ver, cur_title)) => {
            if let Some(expected) = req.expected_version {
                if expected != cur_ver {
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "error": "version_conflict",
                            "current_version": cur_ver
                        })),
                    )
                        .into_response();
                }
            }
            (cur_ver + 1, cur_title)
        }
        None => {
            if let Some(expected) = req.expected_version {
                if expected != 0 {
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "error": "version_conflict",
                            "current_version": 0
                        })),
                    )
                        .into_response();
                }
            }
            (1, slug.clone())
        }
    };

    let title = req
        .title
        .as_deref()
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
    .bind(&req.content)
    .bind(next_version)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&now)
    .execute(&mut *tx)
    .await;

    if upsert.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response();
    }

    let rev = sqlx::query(
        "INSERT INTO wiki_revisions (id, slug, title, content, version, updated_by_id, updated_by_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&rev_id)
    .bind(&slug)
    .bind(&title)
    .bind(&req.content)
    .bind(next_version)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&now)
    .execute(&mut *tx)
    .await;

    if rev.is_err() || tx.commit().await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response();
    }

    let _ = upsert_search_index(&state.pool, "wiki", &slug, &slug, &title, &req.content).await;
    let _ = record_event(
        &state.pool,
        "wiki.updated",
        &agent.agent_id,
        &agent.name,
        &slug,
        &format!("Updated wiki '{slug}' (v{next_version})"),
    )
    .await;

    Json(serde_json::json!({
        "slug": slug,
        "title": title,
        "content": req.content,
        "version": next_version,
        "updated_by_id": agent.agent_id,
        "updated_by_name": agent.name,
        "updated_at": now
    }))
    .into_response()
}
