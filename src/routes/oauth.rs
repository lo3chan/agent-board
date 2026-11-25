use crate::{
    auth::{generate_prefixed_token, hash_token, public_base_url},
    AppState,
};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ACCESS_TOKEN_TTL_SECS: i64 = 3600;
const AUTH_CODE_TTL_SECS: i64 = 300;

pub async fn protected_resource_metadata() -> impl IntoResponse {
    let base = public_base_url();
    Json(serde_json::json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp"]
    }))
}

pub async fn authorization_server_metadata() -> impl IntoResponse {
    let base = public_base_url();
    Json(serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"]
    }))
}

#[derive(Deserialize)]
pub struct RegisterClientReq {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
}

fn is_valid_redirect_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    trimmed.starts_with("https://")
        || trimmed.starts_with("http://localhost")
        || trimmed.starts_with("http://127.0.0.1")
        || trimmed.starts_with("http://[::1]")
}

fn is_known_unregistered_redirect_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    trimmed.starts_with("https://gemini.google.com/")
        || trimmed.starts_with("https://developers.google.com/")
        || trimmed.starts_with("https://claude.ai/")
        || trimmed.starts_with("http://localhost")
        || trimmed.starts_with("http://127.0.0.1")
}

pub async fn register_client(
    State(state): State<AppState>,
    Json(req): Json<RegisterClientReq>,
) -> impl IntoResponse {
    if req.redirect_uris.is_empty() || !req.redirect_uris.iter().all(|u| is_valid_redirect_uri(u)) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris must be a non-empty list of valid https or localhost URIs"
            })),
        )
            .into_response();
    }

    let client_id = generate_prefixed_token("ab_cli_");
    let client_name = req
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("MCP Client")
        .to_string();
    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string(), "refresh_token".to_string()]);
    let response_types = req
        .response_types
        .unwrap_or_else(|| vec!["code".to_string()]);
    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("none")
        .to_string();

    let now = chrono::Utc::now().to_rfc3339();
    let redirect_uris_json = serde_json::to_string(&req.redirect_uris).unwrap_or_default();
    let grant_types_json = serde_json::to_string(&grant_types).unwrap_or_default();
    let response_types_json = serde_json::to_string(&response_types).unwrap_or_default();

    let res = sqlx::query(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&client_id)
    .bind(&client_name)
    .bind(&redirect_uris_json)
    .bind(&grant_types_json)
    .bind(&response_types_json)
    .bind(&token_endpoint_auth_method)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match res {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "client_id": client_id,
                "client_name": client_name,
                "redirect_uris": req.redirect_uris,
                "grant_types": grant_types,
                "response_types": response_types,
                "token_endpoint_auth_method": token_endpoint_auth_method
            })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "db_error" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize, Default)]
pub struct AuthorizeParams {
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

async fn validate_authorize_client(
    state: &AppState,
    params: &AuthorizeParams,
) -> Result<String, (StatusCode, &'static str, &'static str)> {
    if params.response_type != "code" {
        return Err((
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be 'code'",
        ));
    }
    if params.code_challenge_method != "S256" || params.code_challenge.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be 'S256' with a non-empty code_challenge",
        ));
    }
    if params.client_id.trim().is_empty() || !is_valid_redirect_uri(&params.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id and valid redirect_uri are required",
        ));
    }

    let row: Option<(String, String)> =
        sqlx::query_as("SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?")
            .bind(params.client_id.trim())
            .fetch_optional(&state.pool)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "server_error", "db_error"))?;

    if let Some((client_name, redirect_uris_json)) = row {
        let uris: Vec<String> = serde_json::from_str(&redirect_uris_json).unwrap_or_default();
        if !uris.iter().any(|u| u == &params.redirect_uri) {
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "redirect_uri does not match registered client redirect_uris",
            ));
        }
        Ok(client_name)
    } else if is_known_unregistered_redirect_uri(&params.redirect_uri) {
        Ok(params.client_id.clone())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Unknown client_id or unregistered redirect_uri",
        ))
    }
}

fn render_authorize_html(
    client_name: &str,
    params: &AuthorizeParams,
    error_msg: Option<&str>,
) -> String {
    let err_block = match error_msg {
        Some(msg) => format!(r#"<div class="err">{}</div>"#, html_escape(msg)),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize MCP Access — agent-board</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin: 0; font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 16px; box-sizing: border-box; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 28px; width: 100%; max-width: 420px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}
  h1 {{ font-size: 1.2rem; margin: 0 0 8px; }}
  p {{ color: #8b949e; font-size: 0.9rem; margin: 0 0 18px; line-height: 1.45; }}
  .client {{ color: #e6edf3; font-weight: 600; }}
  input[type="password"] {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 6px; border: 1px solid #30363d; background: #0d1117; color: #e6edf3; font-family: monospace; font-size: 0.9rem; margin-bottom: 12px; }}
  button {{ width: 100%; padding: 10px; border: 0; border-radius: 6px; background: #238636; color: #fff; font-weight: 600; cursor: pointer; font-size: 0.95rem; }}
  button:hover {{ background: #2ea043; }}
  .err {{ color: #f85149; font-size: 0.85rem; margin-top: 12px; }}
</style>
</head>
<body>
<div class="card">
  <h1>Authorize MCP Access</h1>
  <p><span class="client">{client_name}</span> is requesting access to <strong>agent-board</strong> via MCP. Paste your Bearer token to authorize this connection.</p>
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="response_type" value="{response_type}">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="scope" value="{scope}">
    <input name="token" type="password" placeholder="ab_agt_... or ab_adm_..." autocomplete="off" required autofocus>
    <button type="submit">Authorize</button>
  </form>
  {err_block}
</div>
</body>
</html>"#,
        client_name = html_escape(client_name),
        response_type = html_escape(&params.response_type),
        client_id = html_escape(&params.client_id),
        redirect_uri = html_escape(&params.redirect_uri),
        code_challenge = html_escape(&params.code_challenge),
        code_challenge_method = html_escape(&params.code_challenge_method),
        state = html_escape(params.state.as_deref().unwrap_or("")),
        scope = html_escape(params.scope.as_deref().unwrap_or("mcp")),
        err_block = err_block,
    )
}

pub async fn authorize_get(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    match validate_authorize_client(&state, &params).await {
        Ok(client_name) => Html(render_authorize_html(&client_name, &params, None)).into_response(),
        Err((status, err, desc)) => (
            status,
            Json(serde_json::json!({ "error": err, "error_description": desc })),
        )
            .into_response(),
    }
}

pub async fn authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false);

    let params: AuthorizeParams = if is_json {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_request" })),
                )
                    .into_response()
            }
        }
    } else {
        match serde_urlencoded::from_bytes(&body) {
            Ok(p) => p,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_request" })),
                )
                    .into_response()
            }
        }
    };

    let client_name = match validate_authorize_client(&state, &params).await {
        Ok(name) => name,
        Err((status, err, desc)) => {
            return (
                status,
                Json(serde_json::json!({ "error": err, "error_description": desc })),
            )
                .into_response()
        }
    };

    let raw_token = params.token.as_deref().map(str::trim).unwrap_or("");
    if raw_token.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Html(render_authorize_html(
                &client_name,
                &params,
                Some("Bearer token is required."),
            )),
        )
            .into_response();
    }

    let token_hash = hash_token(raw_token);
    let token_row: Option<(String,)> = match sqlx::query_as(
        "SELECT id FROM tokens WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "server_error" })),
            )
                .into_response()
        }
    };

    let Some((token_id,)) = token_row else {
        return (
            StatusCode::UNAUTHORIZED,
            Html(render_authorize_html(
                &client_name,
                &params,
                Some("Invalid or revoked token."),
            )),
        )
            .into_response();
    };

    let code = generate_prefixed_token("ab_code_");
    let code_hash = hash_token(&code);
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(AUTH_CODE_TTL_SECS)).to_rfc3339();

    let insert = sqlx::query(
        "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, token_id, expires_at, used_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(&code_hash)
    .bind(params.client_id.trim())
    .bind(params.redirect_uri.trim())
    .bind(params.code_challenge.trim())
    .bind(&token_id)
    .bind(&expires_at)
    .execute(&state.pool)
    .await;

    if insert.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    }

    #[derive(Serialize)]
    struct RedirectQuery<'a> {
        code: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<&'a str>,
    }

    let state_param = params.state.as_deref().filter(|s| !s.is_empty());
    let qs = serde_urlencoded::to_string(RedirectQuery {
        code: &code,
        state: state_param,
    })
    .unwrap_or_default();
    let sep = if params.redirect_uri.contains('?') { '&' } else { '?' };
    let location = format!("{}{}{}", params.redirect_uri.trim(), sep, qs);

    Redirect::to(&location).into_response()
}

#[derive(Deserialize)]
pub struct TokenReq {
    #[serde(default)]
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    if code_verifier.is_empty() {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hasher.finalize());
    computed == code_challenge
}

fn oauth_token_response(access_token: &str, refresh_token: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECS,
            "refresh_token": refresh_token,
            "scope": "mcp"
        })),
    )
        .into_response()
}

fn oauth_error(status: StatusCode, err: &str, desc: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": err,
            "error_description": desc
        })),
    )
        .into_response()
}

pub async fn token_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false);

    let req: TokenReq = if is_json {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "Malformed JSON body"),
        }
    } else {
        match serde_urlencoded::from_bytes(&body) {
            Ok(r) => r,
            Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "Malformed form body"),
        }
    };

    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&state, &req).await,
        "refresh_token" => handle_refresh_token(&state, &req).await,
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Supported grant_types: authorization_code, refresh_token",
        ),
    }
}

async fn handle_authorization_code(state: &AppState, req: &TokenReq) -> Response {
    let code = req.code.as_deref().map(str::trim).unwrap_or("");
    let redirect_uri = req.redirect_uri.as_deref().map(str::trim).unwrap_or("");
    let client_id = req.client_id.as_deref().map(str::trim).unwrap_or("");
    let code_verifier = req.code_verifier.as_deref().unwrap_or("");

    if code.is_empty() || redirect_uri.is_empty() || client_id.is_empty() || code_verifier.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code, redirect_uri, client_id, and code_verifier are required",
        );
    }

    let code_hash = hash_token(code);
    let row: Option<(String, String, String, String, String, Option<String>)> = match sqlx::query_as(
        "SELECT client_id, redirect_uri, code_challenge, token_id, expires_at, used_at FROM oauth_codes WHERE code_hash = ?",
    )
    .bind(&code_hash)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "db_error"),
    };

    let Some((row_client_id, row_redirect_uri, code_challenge, token_id, expires_at, used_at)) = row else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid authorization code");
    };

    if used_at.is_some() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Authorization code already used");
    }

    let not_expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|dt| dt > chrono::Utc::now())
        .unwrap_or(false);
    if !not_expired {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Authorization code expired");
    }

    if row_client_id != client_id || row_redirect_uri != redirect_uri {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "client_id or redirect_uri mismatch");
    }

    if !verify_pkce_s256(code_verifier, &code_challenge) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
    }

    let now = chrono::Utc::now();
    let now_str = now.to_rfc3339();
    let mark_used = sqlx::query("UPDATE oauth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL")
        .bind(&now_str)
        .bind(&code_hash)
        .execute(&state.pool)
        .await;
    match mark_used {
        Ok(r) if r.rows_affected() == 1 => {}
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Authorization code already used"),
    }

    let token_active: Option<(String,)> =
        sqlx::query_as("SELECT id FROM tokens WHERE id = ? AND revoked_at IS NULL")
            .bind(&token_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
    if token_active.is_none() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Underlying token was revoked");
    }

    let access_token = generate_prefixed_token("ab_oat_");
    let refresh_token = generate_prefixed_token("ab_ort_");
    let oauth_id = uuid::Uuid::new_v4().to_string();
    let expires_at = (now + chrono::Duration::seconds(ACCESS_TOKEN_TTL_SECS)).to_rfc3339();

    let insert = sqlx::query(
        r#"
        INSERT INTO oauth_tokens (id, token_id, client_id, access_token_hash, refresh_token_hash, expires_at, revoked_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
        "#,
    )
    .bind(&oauth_id)
    .bind(&token_id)
    .bind(client_id)
    .bind(hash_token(&access_token))
    .bind(hash_token(&refresh_token))
    .bind(&expires_at)
    .bind(&now_str)
    .execute(&state.pool)
    .await;

    match insert {
        Ok(_) => oauth_token_response(&access_token, &refresh_token),
        Err(_) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "db_error"),
    }
}

async fn handle_refresh_token(state: &AppState, req: &TokenReq) -> Response {
    let refresh_token = req.refresh_token.as_deref().map(str::trim).unwrap_or("");
    if refresh_token.is_empty() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "refresh_token is required");
    }

    let refresh_hash = hash_token(refresh_token);
    let row: Option<(String, String)> = match sqlx::query_as(
        r#"
        SELECT o.id, o.client_id
        FROM oauth_tokens o
        JOIN tokens t ON t.id = o.token_id
        WHERE o.refresh_token_hash = ? AND o.revoked_at IS NULL AND t.revoked_at IS NULL
        "#,
    )
    .bind(&refresh_hash)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "db_error"),
    };

    let Some((oauth_id, row_client_id)) = row else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid or revoked refresh_token");
    };

    if let Some(cid) = req.client_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if cid != row_client_id {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "client_id mismatch");
        }
    }

    let new_access = generate_prefixed_token("ab_oat_");
    let new_refresh = generate_prefixed_token("ab_ort_");
    let new_expires = (chrono::Utc::now() + chrono::Duration::seconds(ACCESS_TOKEN_TTL_SECS)).to_rfc3339();

    let updated = sqlx::query(
        "UPDATE oauth_tokens SET access_token_hash = ?, refresh_token_hash = ?, expires_at = ? WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(hash_token(&new_access))
    .bind(hash_token(&new_refresh))
    .bind(&new_expires)
    .bind(&oauth_id)
    .execute(&state.pool)
    .await;

    match updated {
        Ok(r) if r.rows_affected() == 1 => oauth_token_response(&new_access, &new_refresh),
        _ => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "db_error"),
    }
}
