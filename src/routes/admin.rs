use crate::{
    auth::{generate_token, hash_token, AuthAgent},
    db::record_event,
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

#[derive(Deserialize)]
pub struct MintTokenReq {
    pub name: String,
    pub role: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub role: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

pub async fn mint_token(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Json(req): Json<MintTokenReq>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "admin_required" }))).into_response();
    }

    let name = req.name.trim().to_string();
    let role = req.role.trim().to_lowercase();
    if name.is_empty() || (role != "admin" && role != "agent") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid_name_or_role" }))).into_response();
    }

    let plaintext = generate_token(&role);
    let token_hash = hash_token(&plaintext);
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO tokens (id, name, role, token_hash, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&role)
    .bind(&token_hash)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => {
            let _ = record_event(
                &state.pool,
                "token.minted",
                &agent.agent_id,
                &agent.name,
                &id,
                &format!("Minted {role} token for {name}"),
            )
            .await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "id": id,
                    "name": name,
                    "role": role,
                    "token": plaintext,
                    "created_at": now
                })),
            )
                .into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn list_tokens(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "admin_required" }))).into_response();
    }

    let tokens: Result<Vec<TokenInfo>, _> = sqlx::query_as(
        "SELECT id, name, role, created_at, revoked_at FROM tokens ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await;

    match tokens {
        Ok(tokens) => Json(serde_json::json!({ "tokens": tokens })).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}

pub async fn revoke_token(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "admin_required" }))).into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();
    let res = sqlx::query("UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(&now)
        .bind(&id)
        .execute(&state.pool)
        .await;

    match res {
        Ok(r) if r.rows_affected() > 0 => {
            let _ = record_event(
                &state.pool,
                "token.revoked",
                &agent.agent_id,
                &agent.name,
                &id,
                &format!("Revoked token {id}"),
            )
            .await;
            Json(serde_json::json!({ "revoked": true, "id": id, "revoked_at": now })).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "token_not_found_or_already_revoked" }))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "db_error" }))).into_response(),
    }
}
