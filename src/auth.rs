use crate::AppState;
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Json,
};
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize)]
pub struct AuthAgent {
    pub agent_id: String,
    pub name: String,
    pub role: String,
}

impl AuthAgent {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_token(role: &str) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::rng();
    let suffix: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    let prefix = if role == "admin" { "ab_adm_" } else { "ab_agt_" };
    format!("{prefix}{suffix}")
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::trim).filter(|s| !s.is_empty())
}

fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false)
}

const TOKEN_GATE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authentication Required</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 28px; width: 100%; max-width: 400px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
  h1 { font-size: 1.2rem; margin: 0 0 8px; }
  p { color: #8b949e; font-size: 0.9rem; margin: 0 0 18px; }
  input { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 6px; border: 1px solid #30363d; background: #0d1117; color: #e6edf3; font-family: monospace; font-size: 0.9rem; margin-bottom: 12px; }
  button { width: 100%; padding: 10px; border: 0; border-radius: 6px; background: #238636; color: #fff; font-weight: 600; cursor: pointer; }
  button:hover { background: #2ea043; }
  .err { color: #f85149; font-size: 0.85rem; margin-top: 10px; display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>Token Required</h1>
  <p>Enter your Bearer token to unlock.</p>
  <form id="f">
    <input id="t" type="password" placeholder="ab_adm_... or ab_agt_..." autocomplete="off" required>
    <button type="submit">Unlock</button>
  </form>
  <div id="err" class="err">Invalid or revoked token.</div>
</div>
<script>
(function() {
  const KEY = 'agent_board_token';
  async function loadWithToken(token) {
    try {
      const res = await fetch('/ui', { headers: { 'Authorization': 'Bearer ' + token } });
      if (!res.ok) return false;
      const html = await res.text();
      localStorage.setItem(KEY, token);
      document.open();
      document.write(html);
      document.close();
      return true;
    } catch (_) {
      return false;
    }
  }
  const saved = localStorage.getItem(KEY);
  if (saved) {
    loadWithToken(saved).then(ok => {
      if (!ok) localStorage.removeItem(KEY);
    });
  }
  document.getElementById('f').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = document.getElementById('err');
    err.style.display = 'none';
    const token = document.getElementById('t').value.trim();
    if (!token) return;
    const ok = await loadWithToken(token);
    if (!ok) err.style.display = 'block';
  });
})();
</script>
</body>
</html>
"#;

fn unauthorized_response(is_root_get: bool, headers: &HeaderMap) -> Response {
    if is_root_get && wants_html(headers) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Html(TOKEN_GATE_HTML),
        )
            .into_response();
    }

    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let is_root_get = req.method() == axum::http::Method::GET && req.uri().path() == "/";

    let Some(token) = extract_bearer_token(req.headers()) else {
        return unauthorized_response(is_root_get, req.headers());
    };

    let token_hash = hash_token(token);
    let row: Option<(String, String, String)> = match sqlx::query_as(
        "SELECT id, name, role FROM tokens WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "internal_error" })),
            )
                .into_response()
        }
    };

    let Some((agent_id, name, role)) = row else {
        return unauthorized_response(is_root_get, req.headers());
    };

    req.extensions_mut().insert(AuthAgent {
        agent_id,
        name,
        role,
    });

    next.run(req).await
}
