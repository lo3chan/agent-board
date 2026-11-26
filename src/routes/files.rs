use crate::{auth::AuthAgent, db::record_event, AppState};
use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024; // 50 MB

#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct FileMeta {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub uploaded_by_id: String,
    pub uploaded_by_name: String,
    pub created_at: String,
}

fn sanitize_filename(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("file");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != ';')
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.chars().take(180).collect()
    }
}

pub async fn list_files(State(state): State<AppState>) -> impl IntoResponse {
    let files: Result<Vec<FileMeta>, _> = sqlx::query_as(
        "SELECT id, filename, content_type, size_bytes, sha256, uploaded_by_id, uploaded_by_name, created_at FROM files ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await;

    match files {
        Ok(files) => Json(serde_json::json!({ "files": files })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn upload_file(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut uploaded: Option<(String, String, Vec<u8>)> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name != "file" && uploaded.is_some() {
            continue;
        }
        let filename = sanitize_filename(field.file_name().unwrap_or("upload.bin"));
        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();

        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(_) => {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_multipart_payload" }))).into_response();
            }
        };

        if bytes.len() > MAX_UPLOAD_BYTES {
            return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({ "error": "file_too_large" }))).into_response();
        }

        uploaded = Some((filename, content_type, bytes.to_vec()));
        if field_name == "file" {
            break;
        }
    }

    let Some((filename, content_type, data)) = uploaded else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "missing_file_field" }))).into_response();
    };

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let sha256 = hex::encode(hasher.finalize());

    let id = Uuid::new_v4().to_string();
    let disk_name = id.clone();
    let files_dir = state.data_dir.join("files");
    if tokio::fs::create_dir_all(&files_dir).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "storage_error" }))).into_response();
    }

    let disk_path = files_dir.join(&disk_name);
    if tokio::fs::write(&disk_path, &data).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "storage_write_failed" }))).into_response();
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

            (
                StatusCode::CREATED,
                Json(FileMeta {
                    id,
                    filename,
                    content_type,
                    size_bytes,
                    sha256,
                    uploaded_by_id: agent.agent_id,
                    uploaded_by_name: agent.name,
                    created_at: now,
                }),
            )
                .into_response()
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(&disk_path).await;
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response()
        }
    }
}

pub async fn get_file_meta(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let meta: Option<FileMeta> = sqlx::query_as(
        "SELECT id, filename, content_type, size_bytes, sha256, uploaded_by_id, uploaded_by_name, created_at FROM files WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    match meta {
        Some(m) => Json(m).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "file_not_found" }))).into_response(),
    }
}

pub async fn download_file(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT filename, content_type, disk_name FROM files WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let Some((filename, content_type, disk_name)) = row else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "file_not_found" }))).into_response();
    };

    let disk_path = state.data_dir.join("files").join(&disk_name);
    let Ok(bytes) = tokio::fs::read(&disk_path).await else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "file_missing_on_disk" }))).into_response();
    };

    let safe_name = sanitize_filename(&filename);
    let disp = format!("attachment; filename=\"{safe_name}\"");
    let mut resp = (StatusCode::OK, Body::from(bytes)).into_response();
    let headers = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&content_type) {
        headers.insert(header::CONTENT_TYPE, v);
    } else {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    }
    if let Ok(v) = HeaderValue::from_str(&disp) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    } else {
        headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    }
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    resp
}
