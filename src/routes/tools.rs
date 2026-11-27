use crate::{
    auth::AuthAgent,
    db::record_event,
    routes::{files::FileMeta, kanban},
    AppState,
};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

#[derive(sqlx::FromRow)]
struct ToolRow {
    name: String,
    method: String,
    url_template: String,
    headers_json: String,
    allowed_roles: String,
}

#[derive(Serialize)]
pub struct PublicToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub allowed_roles: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
pub struct UpsertToolReq {
    pub name: String,
    pub description: String,
    pub input_schema: Option<Value>,
    pub method: String,
    pub url_template: String,
    pub headers: Option<Value>,
    pub allowed_roles: Option<String>,
}

fn err_resp(status: StatusCode, code: &str, detail: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": code, "detail": detail.into() })),
    )
}

fn guardrail_err(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "ok": false, "error": code, "message": message.into() })),
    )
}

fn arg_str(args: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| args.get(*k).and_then(primitive_to_string))
        .map(|s| s.trim().to_ascii_lowercase())
}

fn enforce_tool_guardrails(
    name: &str,
    args: &mut Map<String, Value>,
) -> Result<(), (StatusCode, Json<Value>)> {
    const PROTECTED_RECORD_ID: &str = "58f63ef53ccbb46b4849b01883ba385a";
    const PROTECTED_HOSTNAME: &str = "board.gettysburgbeacon.com";
    const PROTECTED_TUNNEL_ID: &str = "1d15767c-7bfd-41a3-81a0-103a5ea3be9d";

    match name {
        "portainer.update_stack" | "portainer.redeploy_git_stack" => {
            if let Some(target) = arg_str(
                args,
                &["stack_id", "stackId", "id", "name", "stack_name", "stackName"],
            ) {
                if target == "133"
                    || target == "66"
                    || target.contains("agent-board")
                    || target.contains("portainer-server")
                {
                    return Err(guardrail_err(
                        StatusCode::FORBIDDEN,
                        "protected_resource",
                        format!("Refusing to mutate protected Portainer stack '{target}'"),
                    ));
                }
            }
        }
        "portainer.container_action" => {
            if let Some(target) = arg_str(
                args,
                &[
                    "container_id",
                    "containerId",
                    "container",
                    "id",
                    "name",
                    "container_name",
                    "containerName",
                ],
            ) {
                if target.contains("agent-board") || target.contains("portainer-server") {
                    return Err(guardrail_err(
                        StatusCode::FORBIDDEN,
                        "protected_resource",
                        format!("Refusing to mutate protected Portainer container '{target}'"),
                    ));
                }
            }
        }
        "cloudflare.update_dns_record"
        | "cloudflare.delete_dns_record"
        | "cloudflare.update_tunnel_ingress"
        | "cloudflare.delete_tunnel" => {
            if let Some(rec_id) = arg_str(args, &["record_id", "id"]) {
                if rec_id == PROTECTED_RECORD_ID {
                    return Err(guardrail_err(
                        StatusCode::FORBIDDEN,
                        "protected_resource",
                        "Refusing to mutate protected Cloudflare DNS record for board.gettysburgbeacon.com",
                    ));
                }
            }
            if let Some(rec_name) = arg_str(args, &["name", "hostname"]) {
                if rec_name == PROTECTED_HOSTNAME {
                    return Err(guardrail_err(
                        StatusCode::FORBIDDEN,
                        "protected_resource",
                        "Refusing to mutate protected Cloudflare DNS name 'board.gettysburgbeacon.com'",
                    ));
                }
            }
            if let Some(tun_id) = arg_str(args, &["tunnel_id", "id"]) {
                if tun_id == PROTECTED_TUNNEL_ID {
                    return Err(guardrail_err(
                        StatusCode::FORBIDDEN,
                        "protected_resource",
                        "Refusing to mutate protected Cloudflare tunnel for agent-board",
                    ));
                }
            }

            if matches!(
                name,
                "cloudflare.delete_dns_record" | "cloudflare.delete_tunnel"
            ) {
                if args.get("confirm").and_then(Value::as_bool) != Some(true) {
                    return Err(guardrail_err(
                        StatusCode::BAD_REQUEST,
                        "confirmation_required",
                        "Pass confirm: true to delete a Cloudflare DNS record or tunnel",
                    ));
                }
                args.remove("confirm");
            }
        }
        _ => {}
    }

    Ok(())
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        let is_unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if is_unreserved {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

fn primitive_to_string(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn substitute_url_template(
    template: &str,
    args: &mut Map<String, Value>,
) -> Result<String, (StatusCode, Json<Value>)> {
    let mut result = String::with_capacity(template.len());
    let mut used_keys = HashSet::new();
    let mut rest = template;

    while let Some(start) = rest.find('{') {
        result.push_str(&rest[..start]);
        let after_brace = &rest[start + 1..];
        let Some(end) = after_brace.find('}') else {
            return Err(err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_url_template",
                "Unclosed '{' in tool url_template",
            ));
        };
        let key = after_brace[..end].trim();
        let val = args.get(key).ok_or_else(|| {
            err_resp(
                StatusCode::BAD_REQUEST,
                "missing_path_param",
                format!("Missing required path parameter '{key}'"),
            )
        })?;
        let raw = primitive_to_string(val).ok_or_else(|| {
            err_resp(
                StatusCode::BAD_REQUEST,
                "invalid_path_param",
                format!("Path parameter '{key}' must be a string, number, or boolean"),
            )
        })?;
        result.push_str(&percent_encode(&raw));
        used_keys.insert(key.to_string());
        rest = &after_brace[end + 1..];
    }
    result.push_str(rest);

    for k in used_keys {
        args.remove(&k);
    }
    Ok(result)
}

#[derive(Debug, Deserialize, Default)]
pub struct ListToolsQuery {
    pub prefix: Option<String>,
    pub search: Option<String>,
    pub compact: Option<bool>,
}

fn builtin_tools() -> Vec<PublicToolInfo> {
    let items: [(&str, &str, Value); 8] = [
        (
            "files.read",
            "Read an uploaded file by ID or filename (returns UTF-8 text or base64 data + mime_type for images/audio, up to 5 MB).",
            json!({"type":"object","properties":{"file_id":{"type":"string"},"filename":{"type":"string"}}}),
        ),
        (
            "kanban_board",
            "List all Kanban columns and active tickets (optional column, assignee, label, priority, include_archived, archived_only).",
            json!({"type":"object","properties":{"column":{"type":"string"},"assignee":{"type":"string"},"label":{"type":"string"},"priority":{"type":"string"},"include_archived":{"type":"boolean"},"archived_only":{"type":"boolean"}}}),
        ),
        (
            "kanban_get_ticket",
            "Get full details, comments, and attachments for a Kanban ticket by ID.",
            json!({"type":"object","properties":{"ticket_id":{"type":"string"}},"required":["ticket_id"]}),
        ),
        (
            "kanban_create_ticket",
            "Create a new Kanban ticket (defaults to column_slug='todo', priority='medium').",
            json!({"type":"object","properties":{"title":{"type":"string"},"description":{"type":"string"},"column_slug":{"type":"string"},"priority":{"type":"string"},"labels":{"type":"array","items":{"type":"string"}},"assignee_name":{"type":"string"},"due_at":{"type":"string"}},"required":["title"]}),
        ),
        (
            "kanban_update_ticket",
            "Update, move, or archive/unarchive a Kanban ticket.",
            json!({"type":"object","properties":{"ticket_id":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"column_slug":{"type":"string"},"position":{"type":"integer"},"priority":{"type":"string"},"labels":{"type":"array","items":{"type":"string"}},"assignee_name":{"type":["string","null"]},"due_at":{"type":["string","null"]},"archived":{"type":"boolean"}},"required":["ticket_id"]}),
        ),
        (
            "kanban_delete_ticket",
            "Delete a Kanban ticket by ID (creator or admin only).",
            json!({"type":"object","properties":{"ticket_id":{"type":"string"}},"required":["ticket_id"]}),
        ),
        (
            "kanban_add_comment",
            "Add a comment to a Kanban ticket (supports @mentions and auto-pings assignee).",
            json!({"type":"object","properties":{"ticket_id":{"type":"string"},"body":{"type":"string"}},"required":["ticket_id","body"]}),
        ),
        (
            "kanban_archive_done",
            "Archive all completed tickets in the 'done' column (optional older_than_days).",
            json!({"type":"object","properties":{"older_than_days":{"type":"integer"}}}),
        ),
    ];
    items
        .into_iter()
        .map(|(name, description, input_schema)| PublicToolInfo {
            name: name.to_string(),
            description: description.to_string(),
            input_schema,
            allowed_roles: "all".to_string(),
            updated_at: "built-in".to_string(),
        })
        .collect()
}

pub async fn query_visible_tools(
    state: &AppState,
    agent: &AuthAgent,
) -> Result<Vec<PublicToolInfo>, sqlx::Error> {
    let rows: Vec<(String, String, String, String, String)> = if agent.is_admin() {
        sqlx::query_as(
            "SELECT name, description, input_schema, allowed_roles, updated_at FROM tools ORDER BY name ASC",
        )
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT name, description, input_schema, allowed_roles, updated_at FROM tools WHERE allowed_roles != 'admin' ORDER BY name ASC",
        )
        .fetch_all(&state.pool)
        .await?
    };

    let mut out: Vec<PublicToolInfo> = rows
        .into_iter()
        .map(|(name, description, input_schema, allowed_roles, updated_at)| {
            let parsed_schema = serde_json::from_str(&input_schema).unwrap_or_else(|_| json!({}));
            PublicToolInfo {
                name,
                description,
                input_schema: parsed_schema,
                allowed_roles,
                updated_at,
            }
        })
        .collect();
    out.extend(builtin_tools());
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub async fn list_tools(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Query(query): Query<ListToolsQuery>,
) -> impl IntoResponse {
    let prefix_f = query.prefix.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_lowercase);
    let search_f = query.search.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_lowercase);
    let compact = query.compact.unwrap_or(false);

    match query_visible_tools(&state, &agent).await {
        Ok(tools) => {
            let filtered: Vec<Value> = tools
                .into_iter()
                .filter(|t| {
                    if let Some(ref p) = prefix_f {
                        if !t.name.to_lowercase().starts_with(p) {
                            return false;
                        }
                    }
                    if let Some(ref s) = search_f {
                        if !t.name.to_lowercase().contains(s) && !t.description.to_lowercase().contains(s) {
                            return false;
                        }
                    }
                    true
                })
                .map(|t| {
                    if compact {
                        json!({
                            "name": t.name,
                            "description": t.description,
                            "allowed_roles": t.allowed_roles,
                        })
                    } else {
                        serde_json::to_value(t).unwrap_or_else(|_| json!({}))
                    }
                })
                .collect();
            Json(json!({ "tools": filtered })).into_response()
        }
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()).into_response(),
    }
}

async fn execute_builtin_tool(
    state: &AppState,
    agent: &AuthAgent,
    name: &str,
    args: Value,
) -> Option<Result<Value, (StatusCode, Json<Value>)>> {
    let result: Result<Value, (StatusCode, Json<Value>)> = match name {
        "kanban_board" => {
            let filter: kanban::KanbanFilterQuery = serde_json::from_value(args).unwrap_or_default();
            match kanban::query_board(&state.pool, &filter).await {
                Ok((columns, tickets)) => Ok(json!({ "columns": columns, "tickets": tickets })),
                Err(e) => Err(err_resp(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string())),
            }
        }
        "kanban_get_ticket" => {
            let Some(ticket_id) = args.get("ticket_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
                return Some(Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", "Missing required 'ticket_id'")));
            };
            match kanban::get_ticket_inner(&state.pool, ticket_id).await {
                Ok((ticket, comments, attachments)) => Ok(json!({ "ticket": ticket, "comments": comments, "attachments": attachments })),
                Err((status, msg)) => Err(err_resp(status, msg, msg)),
            }
        }
        "kanban_create_ticket" => match serde_json::from_value::<kanban::CreateTicketReq>(args) {
            Ok(req) => match kanban::create_ticket_inner(state, agent, req).await {
                Ok(ticket) => Ok(json!({ "ticket": ticket })),
                Err((status, msg)) => Err(err_resp(status, msg, msg)),
            },
            Err(e) => Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", e.to_string())),
        },
        "kanban_update_ticket" => {
            let Some(ticket_id) = args.get("ticket_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string) else {
                return Some(Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", "Missing required 'ticket_id'")));
            };
            match serde_json::from_value::<kanban::UpdateTicketReq>(args) {
                Ok(req) => match kanban::update_ticket_inner(state, agent, &ticket_id, req).await {
                    Ok(ticket) => Ok(json!({ "ticket": ticket })),
                    Err((status, msg)) => Err(err_resp(status, msg, msg)),
                },
                Err(e) => Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", e.to_string())),
            }
        }
        "kanban_delete_ticket" => {
            let Some(ticket_id) = args.get("ticket_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
                return Some(Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", "Missing required 'ticket_id'")));
            };
            match kanban::delete_ticket_inner(state, agent, ticket_id).await {
                Ok(()) => Ok(json!({ "deleted": ticket_id })),
                Err((status, msg)) => Err(err_resp(status, msg, msg)),
            }
        }
        "kanban_add_comment" => {
            let Some(ticket_id) = args.get("ticket_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
                return Some(Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", "Missing required 'ticket_id'")));
            };
            let Some(body) = args.get("body").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
                return Some(Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", "Missing required 'body'")));
            };
            match kanban::add_comment_inner(state, agent, ticket_id, body).await {
                Ok(comment) => Ok(json!({ "comment": comment })),
                Err((status, msg)) => Err(err_resp(status, msg, msg)),
            }
        }
        "kanban_archive_done" => {
            let older_than_days = args.get("older_than_days").and_then(Value::as_i64);
            match kanban::archive_done_inner(state, agent, older_than_days).await {
                Ok(archived_count) => Ok(json!({ "archived_count": archived_count })),
                Err((status, msg)) => Err(err_resp(status, msg, msg)),
            }
        }
        "files.read" => {
            let file_id = args.get("file_id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
            let filename = args.get("filename").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
            let meta: Option<FileMeta> = if let Some(fid) = file_id {
                sqlx::query_as("SELECT id, filename, content_type, size_bytes, sha256, uploaded_by_id, uploaded_by_name, created_at FROM files WHERE id = ?")
                    .bind(fid)
                    .fetch_optional(&state.pool)
                    .await
                    .ok()
                    .flatten()
            } else if let Some(fname) = filename {
                sqlx::query_as("SELECT id, filename, content_type, size_bytes, sha256, uploaded_by_id, uploaded_by_name, created_at FROM files WHERE filename = ? ORDER BY created_at DESC LIMIT 1")
                    .bind(fname)
                    .fetch_optional(&state.pool)
                    .await
                    .ok()
                    .flatten()
            } else {
                return Some(Err(err_resp(StatusCode::BAD_REQUEST, "invalid_arguments", "Provide 'file_id' or 'filename'")));
            };
            let Some(meta) = meta else {
                return Some(Err(err_resp(StatusCode::NOT_FOUND, "file_not_found", "File not found")));
            };
            if meta.size_bytes > 5 * 1024 * 1024 {
                return Some(Err(err_resp(StatusCode::PAYLOAD_TOO_LARGE, "file_too_large", "files.read supports files up to 5 MB; download via /api/v1/files/{id}")));
            }
            let path = state.data_dir.join("files").join(&meta.id);
            match tokio::fs::read(&path).await {
                Ok(bytes) => {
                    let (encoding, data) = if meta.content_type.starts_with("text/") || meta.content_type == "application/json" {
                        match String::from_utf8(bytes.clone()) {
                            Ok(s) => ("utf8", s),
                            Err(_) => ("base64", BASE64.encode(&bytes)),
                        }
                    } else {
                        ("base64", BASE64.encode(&bytes))
                    };
                    Ok(json!({
                        "id": meta.id,
                        "filename": meta.filename,
                        "content_type": meta.content_type,
                        "size_bytes": meta.size_bytes,
                        "encoding": encoding,
                        "data": data,
                    }))
                }
                Err(_) => Err(err_resp(StatusCode::NOT_FOUND, "file_missing_on_disk", "File bytes not found on disk")),
            }
        }
        _ => return None,
    };

    if let Ok(ref val) = result {
        let _ = record_event(
            &state.pool,
            "tool.called",
            &agent.agent_id,
            &agent.name,
            name,
            &format!("Called tool '{name}'"),
        )
        .await;
        return Some(Ok(json!({ "ok": true, "status": 200, "result": val })));
    }
    Some(result)
}

pub async fn execute_tool(
    state: &AppState,
    agent: &AuthAgent,
    name: &str,
    args_val: Value,
) -> Result<Value, (StatusCode, Json<Value>)> {
    if let Some(res) = execute_builtin_tool(state, agent, name, args_val.clone()).await {
        return res;
    }
    let tool: Option<ToolRow> = sqlx::query_as(
        "SELECT name, method, url_template, headers_json, allowed_roles FROM tools WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()))?;

    let Some(tool) = tool else {
        return Err(err_resp(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            format!("Tool '{name}' not found"),
        ));
    };

    if tool.allowed_roles == "admin" && !agent.is_admin() {
        return Err(err_resp(
            StatusCode::FORBIDDEN,
            "forbidden",
            "This tool requires admin role",
        ));
    }

    let mut args_map = match args_val {
        Value::Null => Map::new(),
        Value::Object(map) => map,
        _ => {
            return Err(err_resp(
                StatusCode::BAD_REQUEST,
                "invalid_arguments",
                "Tool arguments must be a JSON object",
            ))
        }
    };

    enforce_tool_guardrails(&tool.name, &mut args_map)?;

    let url = substitute_url_template(&tool.url_template, &mut args_map)?;
    let method = reqwest::Method::from_bytes(tool.method.as_bytes()).map_err(|_| {
        err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_method",
            format!("Unsupported HTTP method '{}'", tool.method),
        )
    })?;

    let mut req_builder = state.http_client.request(method.clone(), &url);

    let headers_val: Value = serde_json::from_str(&tool.headers_json).unwrap_or_else(|_| json!({}));
    if let Some(hdr_map) = headers_val.as_object() {
        for (k, v) in hdr_map {
            if let Some(vs) = v.as_str() {
                req_builder = req_builder.header(k.as_str(), vs);
            }
        }
    }

    req_builder = req_builder
        .header("X-Agent-Board-Actor", &agent.name)
        .header("X-Agent-Board-Role", &agent.role);

    if method == reqwest::Method::GET || method == reqwest::Method::DELETE {
        let query_pairs: Vec<(String, String)> = args_map
            .iter()
            .filter_map(|(k, v)| primitive_to_string(v).map(|s| (k.clone(), s)))
            .collect();
        if !query_pairs.is_empty() {
            req_builder = req_builder.query(&query_pairs);
        }
    } else {
        req_builder = req_builder
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&Value::Object(args_map));
    }

    let upstream_resp = req_builder.send().await.map_err(|e| {
        err_resp(
            StatusCode::BAD_GATEWAY,
            "upstream_request_failed",
            e.to_string(),
        )
    })?;

    let status = upstream_resp.status();
    let body_text = upstream_resp.text().await.map_err(|e| {
        err_resp(
            StatusCode::BAD_GATEWAY,
            "upstream_read_failed",
            e.to_string(),
        )
    })?;

    let _ = record_event(
        &state.pool,
        "tool.called",
        &agent.agent_id,
        &agent.name,
        &tool.name,
        &format!("Called tool '{}'", tool.name),
    )
    .await;

    let result = serde_json::from_str::<Value>(&body_text).unwrap_or(Value::String(body_text));

    Ok(json!({
        "ok": status.is_success(),
        "status": status.as_u16(),
        "result": result
    }))
}

pub async fn call_tool_http(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(name): Path<String>,
    body: Bytes,
) -> impl IntoResponse {
    let args_val: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return err_resp(StatusCode::BAD_REQUEST, "invalid_json", e.to_string())
                    .into_response();
            }
        }
    };

    match execute_tool(&state, &agent, &name, args_val).await {
        Ok(res) => Json(res).into_response(),
        Err(err) => err.into_response(),
    }
}

pub async fn upsert_tool(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Json(req): Json<UpsertToolReq>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return err_resp(StatusCode::FORBIDDEN, "admin_required", "Admin role required").into_response();
    }

    let name = req.name.trim().to_string();
    let description = req.description.trim().to_string();
    let method = req.method.trim().to_uppercase();
    let url_template = req.url_template.trim().to_string();
    let allowed_roles = req
        .allowed_roles
        .as_deref()
        .unwrap_or("all")
        .trim()
        .to_lowercase();

    if name.is_empty() || description.is_empty() {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid_tool",
            "Tool name and description must be non-empty",
        )
        .into_response();
    }

    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid_method",
            "Method must be GET, POST, PUT, PATCH, or DELETE",
        )
        .into_response();
    }

    if !(url_template.starts_with("http://") || url_template.starts_with("https://")) {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid_url_template",
            "url_template must start with http:// or https://",
        )
        .into_response();
    }

    if allowed_roles != "all" && allowed_roles != "admin" {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid_allowed_roles",
            "allowed_roles must be 'all' or 'admin'",
        )
        .into_response();
    }

    let input_schema_val = req
        .input_schema
        .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
    let input_schema_str = serde_json::to_string(&input_schema_val).unwrap_or_else(|_| "{}".to_string());

    let headers_val = req.headers.unwrap_or_else(|| json!({}));
    if !headers_val.is_object() {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid_headers",
            "headers must be a JSON object",
        )
        .into_response();
    }
    let headers_str = serde_json::to_string(&headers_val).unwrap_or_else(|_| "{}".to_string());

    let now = chrono::Utc::now().to_rfc3339();
    let res = sqlx::query(
        r#"
        INSERT INTO tools
            (name, description, input_schema, method, url_template, headers_json, allowed_roles, created_by_id, created_by_name, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            description = excluded.description,
            input_schema = excluded.input_schema,
            method = excluded.method,
            url_template = excluded.url_template,
            headers_json = excluded.headers_json,
            allowed_roles = excluded.allowed_roles,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(&name)
    .bind(&description)
    .bind(&input_schema_str)
    .bind(&method)
    .bind(&url_template)
    .bind(&headers_str)
    .bind(&allowed_roles)
    .bind(&agent.agent_id)
    .bind(&agent.name)
    .bind(&now)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => {
            let _ = record_event(
                &state.pool,
                "tool.upserted",
                &agent.agent_id,
                &agent.name,
                &name,
                &format!("Upserted tool '{name}'"),
            )
            .await;

            Json(json!({
                "tool": PublicToolInfo {
                    name,
                    description,
                    input_schema: input_schema_val,
                    allowed_roles,
                    updated_at: now,
                }
            }))
            .into_response()
        }
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()).into_response(),
    }
}

pub async fn delete_tool(
    State(state): State<AppState>,
    Extension(agent): Extension<AuthAgent>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if !agent.is_admin() {
        return err_resp(StatusCode::FORBIDDEN, "admin_required", "Admin role required").into_response();
    }

    let res = sqlx::query("DELETE FROM tools WHERE name = ?")
        .bind(&name)
        .execute(&state.pool)
        .await;

    match res {
        Ok(r) if r.rows_affected() > 0 => {
            let _ = record_event(
                &state.pool,
                "tool.deleted",
                &agent.agent_id,
                &agent.name,
                &name,
                &format!("Deleted tool '{name}'"),
            )
            .await;
            Json(json!({ "deleted": true, "name": name })).into_response()
        }
        Ok(_) => err_resp(
            StatusCode::NOT_FOUND,
            "tool_not_found",
            format!("Tool '{name}' not found"),
        )
        .into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()).into_response(),
    }
}
