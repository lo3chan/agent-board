use agent_board::{build_app, build_http_client, db::init_db, AppState};
use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

const BOOTSTRAP_ADMIN: &str = "ab_adm_0123456789abcdef0123456789abcdef";

async fn setup_app() -> (Router, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let pool = init_db(&db_path, Some(BOOTSTRAP_ADMIN)).await.unwrap();
    let (tx, _) = tokio::sync::broadcast::channel(256);
    let state = AppState {
        pool,
        data_dir: dir.path().to_path_buf(),
        tx,
        http_client: build_http_client(),
    };
    (build_app(state), dir)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn all_routes_require_auth_401() {
    let (app, _dir) = setup_app().await;

    let routes = vec![
        (Method::GET, "/"),
        (Method::GET, "/ui"),
        (Method::GET, "/health"),
        (Method::GET, "/healthz"),
        (Method::GET, "/nonexistent"),
        (Method::GET, "/api/v1/me"),
        (Method::GET, "/api/v1/boards"),
        (Method::POST, "/api/v1/admin/boards"),
        (Method::GET, "/api/v1/wiki"),
        (Method::GET, "/api/v1/wiki/test"),
        (Method::PUT, "/api/v1/wiki/test"),
        (Method::GET, "/api/v1/search?q=test"),
        (Method::GET, "/api/v1/files"),
        (Method::POST, "/api/v1/files"),
        (Method::GET, "/api/v1/events"),
        (Method::GET, "/api/v1/pings"),
        (Method::POST, "/api/v1/pings"),
        (Method::GET, "/api/v1/stream"),
        (Method::GET, "/api/v1/admin/tokens"),
        (Method::POST, "/api/v1/admin/tokens"),
    ];

    for (method, path) in routes {
        let req = Request::builder()
            .method(method.clone())
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Expected 401 for {method} {path}"
        );
    }

    // Root GET with Accept: text/html must return 401 with minimal token-gate HTML
    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header(header::ACCEPT, "text/html,application/xhtml+xml")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let html = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(html.contains("Token Required"));
    assert!(html.contains("localStorage"));
    assert!(!html.contains("Antigravity"));
}

#[tokio::test]
async fn auth_and_admin_token_minting_and_revocation() {
    let (app, _dir) = setup_app().await;

    // Bootstrap admin /me
    let req = Request::builder()
        .uri("/api/v1/me")
        .header(header::AUTHORIZATION, format!("Bearer {BOOTSTRAP_ADMIN}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let me = body_json(resp).await;
    assert_eq!(me["name"], "Antigravity");
    assert_eq!(me["role"], "admin");

    // Mint agent token
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/admin/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {BOOTSTRAP_ADMIN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"name": "worker-1", "role": "agent"}).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let minted = body_json(resp).await;
    let agent_token = minted["token"].as_str().unwrap().to_string();
    let agent_token_id = minted["id"].as_str().unwrap().to_string();
    assert!(agent_token.starts_with("ab_agt_"));
    assert_eq!(agent_token.len(), 39);

    // Agent cannot access admin endpoints (403)
    let req = Request::builder()
        .uri("/api/v1/admin/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {agent_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Admin lists tokens without exposing hashes
    let req = Request::builder()
        .uri("/api/v1/admin/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {BOOTSTRAP_ADMIN}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list_text = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(!list_text.contains("token_hash"));
    assert!(!list_text.contains(&agent_token));

    // Revoke agent token
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/v1/admin/tokens/{agent_token_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {BOOTSTRAP_ADMIN}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Revoked token now gets 401
    let req = Request::builder()
        .uri("/api/v1/me")
        .header(header::AUTHORIZATION, format!("Bearer {agent_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forum_wiki_search_files_and_events_flow() {
    let (app, dir) = setup_app().await;
    let auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    // 1. Create board
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/boards")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"slug": "ops", "name": "Operations", "description": "Infra ops"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 2. Create thread + reply
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/boards/ops/threads")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"title": "Deploy Jelly", "body": "Checking cloudflared tunnel status"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let thread = body_json(resp).await;
    let tid = thread["id"].as_str().unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/threads/{tid}/posts"))
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"body": "Tunnel is healthy and serving HTTPS"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 3. Wiki create + optimistic concurrency conflict
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/wiki/infra/jelly")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"title": "Jelly Host", "content": "ZFS pool /firma", "expected_version": 0}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let w1 = body_json(resp).await;
    assert_eq!(w1["version"], 1);

    // Stale expected_version -> 409 Conflict
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/wiki/infra/jelly")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"content": "Overwrite", "expected_version": 0}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // 4. FTS5 Search across threads, posts, wiki
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/search?q=cloudflared")
                .header(header::AUTHORIZATION, &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sres = body_json(resp).await;
    assert!(!sres["results"].as_array().unwrap().is_empty());

    // 5. File upload & download headers
    let boundary = "----agentboardboundary";
    let multipart_body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../evil.txt\"\r\nContent-Type: text/plain\r\n\r\nhello world\r\n--{boundary}--\r\n"
    );
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/files")
                .header(header::AUTHORIZATION, &auth)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let fmeta = body_json(resp).await;
    let fid = fmeta["id"].as_str().unwrap();
    assert_eq!(fmeta["filename"], "evil.txt");
    assert!(dir.path().join("files").join(fid).exists());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/files/{fid}"))
                .header(header::AUTHORIZATION, &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("attachment;"));

    // 6. Events feed
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?since=0")
                .header(header::AUTHORIZATION, &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let evs = body_json(resp).await;
    assert!(evs["events"].as_array().unwrap().len() >= 5);
}

#[tokio::test]
async fn oauth_discovery_dcr_pkce_and_mcp_flow() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    let (app, _dir) = setup_app().await;

    // 1. OAuth Discovery endpoints (public)
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let j = body_json(resp).await;
        assert_eq!(j["resource"], "https://board.gettysburgbeacon.com/mcp");
        assert_eq!(j["authorization_servers"][0], "https://board.gettysburgbeacon.com");
    }

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let meta = body_json(resp).await;
    assert_eq!(meta["issuer"], "https://board.gettysburgbeacon.com");
    assert_eq!(
        meta["authorization_endpoint"],
        "https://board.gettysburgbeacon.com/oauth/authorize"
    );
    assert_eq!(
        meta["token_endpoint"],
        "https://board.gettysburgbeacon.com/oauth/token"
    );
    assert_eq!(
        meta["registration_endpoint"],
        "https://board.gettysburgbeacon.com/oauth/register"
    );
    assert_eq!(meta["code_challenge_methods_supported"][0], "S256");

    // 2. Unauthenticated /mcp returns 401 with WWW-Authenticate resource_metadata
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www_auth = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        www_auth,
        r#"Bearer resource_metadata="https://board.gettysburgbeacon.com/.well-known/oauth-protected-resource""#
    );

    // 3. Mint an agent token & create a board for MCP tool tests
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tokens")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "Gemini", "role": "agent"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let minted = body_json(resp).await;
    let gemini_token = minted["token"].as_str().unwrap().to_string();
    let gemini_token_id = minted["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/boards")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"slug": "general", "name": "General"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Dynamic Client Registration (RFC 7591)
    let redirect_uri = "https://gemini.google.com/oauth/callback";
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "client_name": "Gemini Custom App",
                        "redirect_uris": [redirect_uri],
                        "grant_types": ["authorization_code", "refresh_token"],
                        "response_types": ["code"],
                        "token_endpoint_auth_method": "none"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let reg = body_json(resp).await;
    let client_id = reg["client_id"].as_str().unwrap().to_string();
    assert!(client_id.starts_with("ab_cli_"));

    // 5. PKCE S256 + GET /oauth/authorize
    let code_verifier = "test_pkce_verifier_0123456789abcdefghijklmnopqrstuvwxyz";
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    let state_val = "xyz123state";

    let auth_qs = serde_urlencoded::to_string(&[
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state_val),
    ])
    .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/oauth/authorize?{auth_qs}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let auth_html =
        String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(auth_html.contains("Authorize MCP Access"));
    assert!(auth_html.contains("Gemini Custom App"));

    // 6. POST /oauth/authorize with invalid token -> 401
    let bad_form = serde_urlencoded::to_string(&[
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state_val),
        ("token", "ab_agt_invalidtoken"),
    ])
    .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(bad_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 7. POST /oauth/authorize with valid Gemini token -> 302 redirect with code & state
    let good_form = serde_urlencoded::to_string(&[
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", state_val),
        ("token", gemini_token.as_str()),
    ])
    .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(good_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(redirect_uri));
    let query_part = location.split('?').nth(1).unwrap();
    let pairs: Vec<(String, String)> = serde_urlencoded::from_str(query_part).unwrap();
    let auth_code = pairs
        .iter()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.clone())
        .unwrap();
    let returned_state = pairs
        .iter()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(returned_state, state_val);

    // 8. POST /oauth/token with wrong code_verifier -> 400
    let bad_token_form = serde_urlencoded::to_string(&[
        ("grant_type", "authorization_code"),
        ("code", auth_code.as_str()),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id.as_str()),
        ("code_verifier", "wrong_verifier"),
    ])
    .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(bad_token_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 9. POST /oauth/token with valid code_verifier -> 200 with ab_oat_ & ab_ort_
    let good_token_form = serde_urlencoded::to_string(&[
        ("grant_type", "authorization_code"),
        ("code", auth_code.as_str()),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id.as_str()),
        ("code_verifier", code_verifier),
    ])
    .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(good_token_form.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tok_resp = body_json(resp).await;
    let access_token = tok_resp["access_token"].as_str().unwrap().to_string();
    let refresh_token = tok_resp["refresh_token"].as_str().unwrap().to_string();
    assert!(access_token.starts_with("ab_oat_"));
    assert!(refresh_token.starts_with("ab_ort_"));
    assert_eq!(tok_resp["token_type"], "Bearer");

    // Reusing authorization code must fail
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(good_token_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 10. Refresh token grant
    let refresh_form = serde_urlencoded::to_string(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("client_id", client_id.as_str()),
    ])
    .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(refresh_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let refreshed = body_json(resp).await;
    let oauth_bearer = format!("Bearer {}", refreshed["access_token"].as_str().unwrap());

    // 11. MCP Streamable HTTP: initialize, notifications/initialized, ping, tools/list, tools/call
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": { "protocolVersion": "2025-03-26" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let init_resp = body_json(resp).await;
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "agent-board");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list_resp = body_json(resp).await;
    let tools = list_resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 27);

    // Call `me` tool -> resolves to Gemini identity
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": { "name": "me", "arguments": {} }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let me_resp = body_json(resp).await;
    assert_eq!(me_resp["result"]["isError"], false);
    let me_text = me_resp["result"]["content"][0]["text"].as_str().unwrap();
    let me_parsed: Value = serde_json::from_str(me_text).unwrap();
    assert_eq!(me_parsed["name"], "Gemini");

    // Call `create_thread`, `put_wiki`, `upload_text_file`, `read_text_file`
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "create_thread",
                            "arguments": {
                                "board_slug": "general",
                                "title": "MCP Thread",
                                "body": "Created via MCP"
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let thr_resp = body_json(resp).await;
    assert_eq!(thr_resp["result"]["isError"], false);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 5,
                        "method": "tools/call",
                        "params": {
                            "name": "upload_text_file",
                            "arguments": {
                                "filename": "mcp.txt",
                                "content": "hello from mcp"
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let up_resp = body_json(resp).await;
    let up_text = up_resp["result"]["content"][0]["text"].as_str().unwrap();
    let up_parsed: Value = serde_json::from_str(up_text).unwrap();
    let fid = up_parsed["id"].as_str().unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "read_text_file",
                            "arguments": { "file_id": fid }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rd_resp = body_json(resp).await;
    let rd_text = rd_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(rd_text.contains("hello from mcp"));

    // GET /mcp -> 405, DELETE /mcp -> 204
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 12. Revoking underlying agent token also revokes OAuth access token
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/admin/tokens/{gemini_token_id}"))
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &oauth_bearer)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pings_mentions_sse_and_mcp_flow() {
    let (app, _dir) = setup_app().await;
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    // Mint two agent tokens: Doc and Gemini
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tokens")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "Doc", "role": "agent"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let doc_token = body_json(resp).await["token"].as_str().unwrap().to_string();
    let doc_auth = format!("Bearer {doc_token}");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tokens")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "Gemini", "role": "agent"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let gemini_token = body_json(resp).await["token"].as_str().unwrap().to_string();
    let gemini_auth = format!("Bearer {gemini_token}");

    // 1. POST /api/v1/pings -> 404 for unknown target
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/pings")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"to": "nonexistent", "message": "hello"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // 2. POST /api/v1/pings (case-insensitive name) -> 201 Created
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/pings")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "to": "doc",
                        "message": "Please review wiki/ops",
                        "wiki_slug": "ops"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let ping_created = body_json(resp).await;
    let ping_id = ping_created["ping"]["id"].as_str().unwrap().to_string();
    assert_eq!(ping_created["ping"]["to_name"], "Doc");
    assert_eq!(ping_created["ping"]["from_name"], "Antigravity");
    assert_eq!(ping_created["ping"]["wiki_slug"], "ops");
    assert!(ping_created["ping"]["acked_at"].is_null());

    // 3. GET /api/v1/pings?unread=true as Doc
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pings?unread=true")
                .header(header::AUTHORIZATION, &doc_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let unread_list = body_json(resp).await;
    assert_eq!(unread_list["pings"].as_array().unwrap().len(), 1);
    assert_eq!(unread_list["pings"][0]["id"], ping_id);

    // 4. POST /api/v1/pings/{id}/ack as Doc
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/pings/{ping_id}/ack"))
                .header(header::AUTHORIZATION, &doc_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let acked = body_json(resp).await;
    assert!(acked["ping"]["acked_at"].is_string());

    // Unread is now 0, all is 1
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pings?unread=true")
                .header(header::AUTHORIZATION, &doc_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["pings"].as_array().unwrap().len(), 0);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pings")
                .header(header::AUTHORIZATION, &doc_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["pings"].as_array().unwrap().len(), 1);

    // 5. @mention auto-ping on create_post
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/boards")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"slug": "general", "name": "General"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/boards/general/threads")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"title": "Sync", "body": "Initial thread"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let tid = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/threads/{tid}/posts"))
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"body": "Hey @Doc and @gemini, please check this!"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let pid = body_json(resp).await["id"].as_str().unwrap().to_string();

    // Both Doc and Gemini should have 1 unread ping referencing tid & pid
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pings?unread=true")
                .header(header::AUTHORIZATION, &doc_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let doc_unread = body_json(resp).await;
    assert_eq!(doc_unread["pings"].as_array().unwrap().len(), 1);
    assert_eq!(doc_unread["pings"][0]["thread_id"], tid);
    assert_eq!(doc_unread["pings"][0]["post_id"], pid);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pings?unread=true")
                .header(header::AUTHORIZATION, &gemini_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let gem_unread = body_json(resp).await;
    assert_eq!(gem_unread["pings"].as_array().unwrap().len(), 1);
    assert_eq!(gem_unread["pings"][0]["thread_id"], tid);
    assert_eq!(gem_unread["pings"][0]["post_id"], pid);

    // 6. SSE stream endpoint returns 200 text/event-stream
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/stream?filter=me")
                .header(header::AUTHORIZATION, &doc_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/event-stream"));

    // 7. MCP tools/list has 18 tools and ping_agent / list_pings / ack_ping / read_file work
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &doc_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tools_resp = body_json(resp).await;
    let tools = tools_resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 27);
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"ping_agent"));
    assert!(names.contains(&"list_pings"));
    assert!(names.contains(&"ack_ping"));
    assert!(names.contains(&"read_file"));

    // Doc calls ping_agent -> Gemini
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &doc_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "ping_agent",
                            "arguments": {
                                "to": "Gemini",
                                "message": "MCP ping test",
                                "thread_id": tid
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mcp_ping_resp = body_json(resp).await;
    assert_eq!(mcp_ping_resp["result"]["isError"], false);
    let mcp_ping_val: Value =
        serde_json::from_str(mcp_ping_resp["result"]["content"][0]["text"].as_str().unwrap())
            .unwrap();
    let mcp_ping_id = mcp_ping_val["ping"]["id"].as_str().unwrap().to_string();

    // Gemini calls list_pings (unread=true)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &gemini_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "list_pings",
                            "arguments": { "unread": true }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list_resp = body_json(resp).await;
    let list_val: Value =
        serde_json::from_str(list_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(list_val["pings"].as_array().unwrap().len(), 2);

    // Gemini calls ack_ping
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &gemini_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "ack_ping",
                            "arguments": { "ping_id": mcp_ping_id }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ack_resp = body_json(resp).await;
    assert_eq!(ack_resp["result"]["isError"], false);
    let ack_val: Value =
        serde_json::from_str(ack_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(ack_val["ping"]["acked_at"].is_string());
}

async fn upload_test_file(
    app: &Router,
    auth: &str,
    filename: &str,
    content_type: &str,
    bytes: &[u8],
) -> String {
    let boundary = "----agentboardtestboundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/files")
                .header(header::AUTHORIZATION, auth)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp).await["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn attachments_and_multimodal_read_file_flow() {
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

    let (app, _dir) = setup_app().await;
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    // Create board
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/boards")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"slug": "media", "name": "Media"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let img_bytes = b"\xff\xd8\xff\xe0fake-jpeg-bytes";
    let audio_bytes = b"\x00\x00\x00\x18ftypM4A fake-m4a-bytes";
    let txt_bytes = b"hello multimodal world\nline 2";
    let vid_bytes = b"\x00\x00\x00\x18ftypmp42\xff\xfe\x80\x81fake-mp4-bytes";

    let img_id = upload_test_file(&app, &admin_auth, "capture.jpg", "image/jpeg", img_bytes).await;
    let audio_id = upload_test_file(&app, &admin_auth, "memo.m4a", "audio/mp4", audio_bytes).await;
    let txt_id = upload_test_file(&app, &admin_auth, "notes.txt", "text/plain; charset=utf-8", txt_bytes).await;
    let vid_id = upload_test_file(&app, &admin_auth, "clip.mp4", "video/mp4", vid_bytes).await;

    // Create thread with explicit attachment_ids + file:// body reference + nonexistent UUID
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/boards/media/threads")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "title": "Media Thread",
                        "body": format!("See audio file://{audio_id} and missing file://00000000-0000-0000-0000-000000000000"),
                        "attachment_ids": [img_id]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created_thread = body_json(resp).await;
    let tid = created_thread["id"].as_str().unwrap().to_string();
    let t_atts = created_thread["attachments"].as_array().unwrap();
    assert_eq!(t_atts.len(), 2);
    let t_att_ids: Vec<&str> = t_atts.iter().map(|a| a["id"].as_str().unwrap()).collect();
    assert!(t_att_ids.contains(&img_id.as_str()));
    assert!(t_att_ids.contains(&audio_id.as_str()));

    // ThreadSummary in GET /api/v1/boards/media/threads includes attachments
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/boards/media/threads")
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list_json = body_json(resp).await;
    assert_eq!(list_json["threads"][0]["attachments"].as_array().unwrap().len(), 2);

    // Create post via MCP with /api/v1/files/<txt_id> in body and attachment_ids: [vid_id]
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {
                            "name": "create_post",
                            "arguments": {
                                "thread_id": tid,
                                "body": format!("Attached notes at /api/v1/files/{txt_id}"),
                                "attachment_ids": [vid_id]
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mcp_post = body_json(resp).await;
    assert_eq!(mcp_post["result"]["isError"], false);

    // GET /api/v1/threads/{tid} returns attachments on both thread and post
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/threads/{tid}"))
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let detail = body_json(resp).await;
    assert_eq!(detail["thread"]["attachments"].as_array().unwrap().len(), 2);
    let p_atts = detail["posts"][0]["attachments"].as_array().unwrap();
    assert_eq!(p_atts.len(), 2);
    let p_att_ids: Vec<&str> = p_atts.iter().map(|a| a["id"].as_str().unwrap()).collect();
    assert!(p_att_ids.contains(&txt_id.as_str()));
    assert!(p_att_ids.contains(&vid_id.as_str()));

    // MCP read_file on image
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/call",
                        "params": { "name": "read_file", "arguments": { "file_id": img_id } }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let img_res = body_json(resp).await;
    assert_eq!(img_res["result"]["isError"], false);
    assert_eq!(img_res["result"]["content"][0]["type"], "image");
    assert_eq!(img_res["result"]["content"][0]["mimeType"], "image/jpeg");
    assert_eq!(
        img_res["result"]["content"][0]["data"],
        BASE64_STANDARD.encode(img_bytes)
    );
    assert_eq!(img_res["result"]["content"][1]["type"], "text");

    // MCP read_file on audio
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 12,
                        "method": "tools/call",
                        "params": { "name": "read_file", "arguments": { "file_id": audio_id } }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let audio_res = body_json(resp).await;
    assert_eq!(audio_res["result"]["isError"], false);
    assert_eq!(audio_res["result"]["content"][0]["type"], "audio");
    assert_eq!(audio_res["result"]["content"][0]["mimeType"], "audio/mp4");
    assert_eq!(
        audio_res["result"]["content"][0]["data"],
        BASE64_STANDARD.encode(audio_bytes)
    );
    assert_eq!(audio_res["result"]["content"][1]["type"], "text");

    // MCP read_file on text
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 13,
                        "method": "tools/call",
                        "params": { "name": "read_file", "arguments": { "file_id": txt_id } }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let txt_res = body_json(resp).await;
    assert_eq!(txt_res["result"]["isError"], false);
    assert_eq!(txt_res["result"]["content"][0]["type"], "text");
    assert_eq!(
        txt_res["result"]["content"][0]["text"],
        "hello multimodal world\nline 2"
    );

    // MCP read_file on video/binary falls back to metadata + download_path
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 14,
                        "method": "tools/call",
                        "params": { "name": "read_file", "arguments": { "file_id": vid_id } }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let vid_res = body_json(resp).await;
    assert_eq!(vid_res["result"]["isError"], false);
    assert_eq!(vid_res["result"]["content"][0]["type"], "text");
    let vid_meta: Value =
        serde_json::from_str(vid_res["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(vid_meta["download_path"], format!("/api/v1/files/{vid_id}"));
}

#[tokio::test]
async fn tool_registry_proxy_and_mcp_tools() {
    use axum::{
        extract::Path as AxumPath,
        http::HeaderMap,
        routing::patch,
        Json as AxumJson,
    };

    let (app, _dir) = setup_app().await;
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    // Mint an agent token
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tokens")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "tool-tester", "role": "agent"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let agent_token = body_json(resp).await["token"].as_str().unwrap().to_string();
    let agent_auth = format!("Bearer {agent_token}");

    // Start local mock Axum HTTP server
    let mock_router = Router::new().route(
        "/items/{id}",
        patch(
            |AxumPath(id): AxumPath<String>,
             headers: HeaderMap,
             AxumJson(body): AxumJson<Value>| async move {
                let secret = headers
                    .get("x-internal-secret")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                AxumJson(json!({
                    "echo_id": id,
                    "echo_secret": secret,
                    "echo_body": body
                }))
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_router).await.unwrap();
    });

    // Agent cannot register tools (403)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tools")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "mock.patch_item",
                        "description": "Patch an item",
                        "method": "PATCH",
                        "url_template": format!("http://{addr}/items/{{id}}")
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Admin registers public tool + admin-only tool
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tools")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "mock.patch_item",
                        "description": "Patch an item on mock server",
                        "input_schema": {
                            "type": "object",
                            "properties": { "id": { "type": "string" }, "title": { "type": "string" } },
                            "required": ["id"]
                        },
                        "method": "PATCH",
                        "url_template": format!("http://{addr}/items/{{id}}"),
                        "headers": { "X-Internal-Secret": "super-secret-123" },
                        "allowed_roles": "all"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tools")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "mock.admin_only",
                        "description": "Admin only tool",
                        "method": "GET",
                        "url_template": format!("http://{addr}/items/admin"),
                        "allowed_roles": "admin"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET /api/v1/tools hides headers_json & url_template, and filters admin tools for agents
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/tools")
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tools_json = body_json(resp).await;
    let tools_arr = tools_json["tools"].as_array().unwrap();
    assert_eq!(tools_arr.len(), 1);
    assert_eq!(tools_arr[0]["name"], "mock.patch_item");
    assert!(tools_arr[0].get("headers_json").is_none());
    assert!(tools_arr[0].get("headers").is_none());
    assert!(tools_arr[0].get("url_template").is_none());

    // Agent cannot call admin-only tool (403)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/mock.admin_only")
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // POST /api/v1/tools/mock.patch_item substitutes {id}, sends secret header + remaining JSON body
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/mock.patch_item")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "id": "42", "title": "Updated Title" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let call_res = body_json(resp).await;
    assert_eq!(call_res["ok"], true);
    assert_eq!(call_res["status"], 200);
    assert_eq!(call_res["result"]["echo_id"], "42");
    assert_eq!(call_res["result"]["echo_secret"], "super-secret-123");
    assert_eq!(call_res["result"]["echo_body"], json!({ "title": "Updated Title" }));

    // Verify tool.called event was recorded
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let events_json = body_json(resp).await;
    let events = events_json["events"].as_array().unwrap();
    assert!(events.iter().any(|e| {
        e["kind"] == "tool.called" && e["target_id"] == "mock.patch_item"
    }));

    // MCP tools/list has 20 tools
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 100,
                        "method": "tools/list",
                        "params": {}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mcp_list = body_json(resp).await;
    assert_eq!(mcp_list["result"]["tools"].as_array().unwrap().len(), 27);

    // MCP list_tools
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 101,
                        "method": "tools/call",
                        "params": { "name": "list_tools", "arguments": {} }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let mcp_tools_res = body_json(resp).await;
    assert_eq!(mcp_tools_res["result"]["isError"], false);
    let parsed_list: Value = serde_json::from_str(
        mcp_tools_res["result"]["content"][0]["text"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(parsed_list["tools"].as_array().unwrap().len(), 1);

    // MCP call_tool
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 102,
                        "method": "tools/call",
                        "params": {
                            "name": "call_tool",
                            "arguments": {
                                "name": "mock.patch_item",
                                "args": { "id": "99", "title": "Via MCP" }
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let mcp_call_res = body_json(resp).await;
    assert_eq!(mcp_call_res["result"]["isError"], false);
    let parsed_call: Value = serde_json::from_str(
        mcp_call_res["result"]["content"][0]["text"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(parsed_call["ok"], true);
    assert_eq!(parsed_call["status"], 200);
    assert_eq!(parsed_call["result"]["echo_id"], "99");
    assert_eq!(parsed_call["result"]["echo_secret"], "super-secret-123");
    assert_eq!(parsed_call["result"]["echo_body"], json!({ "title": "Via MCP" }));

    // Admin can delete tool
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/admin/tools/mock.admin_only")
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn tool_guardrails_protect_self_and_require_confirm() {
    use axum::{
        extract::{Path as AxumPath, RawQuery},
        routing::{delete, post, put},
        Json as AxumJson,
    };

    let (app, _dir) = setup_app().await;
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    let mock_router = Router::new()
        .route(
            "/stacks/{stack_id}",
            put(|AxumPath(stack_id): AxumPath<String>| async move {
                AxumJson(json!({ "updated_stack": stack_id }))
            }),
        )
        .route(
            "/containers/{container_id}/restart",
            post(|AxumPath(container_id): AxumPath<String>| async move {
                AxumJson(json!({ "restarted": container_id }))
            }),
        )
        .route(
            "/dns/{record_id}",
            delete(
                |AxumPath(record_id): AxumPath<String>, RawQuery(query): RawQuery| async move {
                    AxumJson(json!({
                        "deleted_record": record_id,
                        "raw_query": query.unwrap_or_default()
                    }))
                },
            ),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_router).await.unwrap();
    });

    for (name, method, url_template) in [
        (
            "portainer.update_stack",
            "PUT",
            format!("http://{addr}/stacks/{{stack_id}}"),
        ),
        (
            "portainer.container_action",
            "POST",
            format!("http://{addr}/containers/{{container_id}}/restart"),
        ),
        (
            "cloudflare.delete_dns_record",
            "DELETE",
            format!("http://{addr}/dns/{{record_id}}"),
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/admin/tools")
                    .header(header::AUTHORIZATION, &admin_auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "name": name,
                            "description": name,
                            "method": method,
                            "url_template": url_template,
                            "allowed_roles": "all"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // portainer.update_stack on stack 133 or 66 returns 403
    for protected_id in [json!(133), json!(66), json!("133"), json!("66")] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/tools/portainer.update_stack")
                    .header(header::AUTHORIZATION, &admin_auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "stack_id": protected_id }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"], "protected_resource");
    }

    // portainer.update_stack on non-protected stack (e.g. itso endpoint 9, stack 105) succeeds
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/portainer.update_stack")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "stack_id": 105, "endpoint_id": 9 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // portainer.container_action on agent-board or portainer-server returns 403
    for container in ["agent-board", "portainer-server-1"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/tools/portainer.container_action")
                    .header(header::AUTHORIZATION, &admin_auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "container_id": container }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // cloudflare.delete_dns_record without confirm: true returns 400
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/cloudflare.delete_dns_record")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "record_id": "other-record-123" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "confirmation_required");

    // cloudflare.delete_dns_record on protected record returns 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/cloudflare.delete_dns_record")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "record_id": "58f63ef53ccbb46b4849b01883ba385a",
                        "confirm": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "protected_resource");

    // cloudflare.delete_dns_record on another record with confirm: true succeeds and strips confirm
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/cloudflare.delete_dns_record")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "record_id": "other-record-123",
                        "confirm": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["result"]["deleted_record"], "other-record-123");
    assert!(!body["result"]["raw_query"]
        .as_str()
        .unwrap()
        .contains("confirm"));
}

#[tokio::test]
async fn list_threads_pagination_filtering_and_tool_actor_headers() {
    use axum::{http::HeaderMap, routing::post, Json as AxumJson};

    let (app, _dir) = setup_app().await;
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    // Mint an agent token
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tokens")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "Gemini", "role": "agent"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let agent_token = body_json(resp).await["token"].as_str().unwrap().to_string();
    let agent_auth = format!("Bearer {agent_token}");

    // Create the 'general' board
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/boards")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "slug": "general", "name": "General", "description": "General board" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Create 3 threads with small gaps so updated_at differs
    let mut created_ids = Vec::new();
    let mut updated_ats = Vec::new();
    for i in 1..=3 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/boards/general/threads")
                    .header(header::AUTHORIZATION, &agent_auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "title": format!("Thread {i}"),
                            "body": format!("Body {i}")
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let t = body_json(resp).await;
        created_ids.push(t["id"].as_str().unwrap().to_string());
        updated_ats.push(t["updated_at"].as_str().unwrap().to_string());
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    }

    // 1. REST limit=2 returns the 2 most recent threads
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/boards/general/threads?limit=2")
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let threads = body["threads"].as_array().unwrap();
    assert_eq!(threads.len(), 2);
    assert_eq!(threads[0]["id"], created_ids[2]);
    assert_eq!(threads[1]["id"], created_ids[1]);

    // 2. REST updated_since filters older threads
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/boards/general/threads?updated_since={}",
                    updated_ats[1]
                ))
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let threads = body["threads"].as_array().unwrap();
    assert_eq!(threads.len(), 2);
    assert_eq!(threads[0]["id"], created_ids[2]);
    assert_eq!(threads[1]["id"], created_ids[1]);

    // 3. MCP list_threads supports limit and updated_since
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "list_threads",
                            "arguments": {
                                "board_slug": "general",
                                "limit": 1,
                                "updated_since": updated_ats[1]
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mcp_body = body_json(resp).await;
    let text = mcp_body["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    let mcp_threads = parsed["threads"].as_array().unwrap();
    assert_eq!(mcp_threads.len(), 1);
    assert_eq!(mcp_threads[0]["id"], created_ids[2]);

    // 4. execute_tool injects X-Agent-Board-Actor and X-Agent-Board-Role headers
    let mock_router = Router::new().route(
        "/whoami",
        post(|headers: HeaderMap, AxumJson(_body): AxumJson<Value>| async move {
            let actor = headers
                .get("x-agent-board-actor")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let role = headers
                .get("x-agent-board-role")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            AxumJson(json!({ "actor": actor, "role": role }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock_router).await.unwrap();
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tools")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "name": "mock.whoami",
                        "description": "Echo actor headers",
                        "method": "POST",
                        "url_template": format!("http://{addr}/whoami"),
                        "allowed_roles": "all"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Call as agent ("Gemini", "agent")
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/mock.whoami")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["result"]["actor"], "Gemini");
    assert_eq!(body["result"]["role"], "agent");

    // Call as admin ("Antigravity", "admin")
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/tools/mock.whoami")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["result"]["actor"], "Antigravity");
    assert_eq!(body["result"]["role"], "admin");
}

#[tokio::test]
async fn kanban_tickets_comments_and_mcp_flow() {
    let (app, _dir) = setup_app().await;
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    // Mint an agent token ("worker-k")
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/admin/tokens")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "worker-k", "role": "agent"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let agent_tok = body_json(resp).await["token"].as_str().unwrap().to_string();
    let agent_auth = format!("Bearer {agent_tok}");

    // 1. GET /api/v1/kanban returns 5 default columns
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/kanban")
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let board = body_json(resp).await;
    let cols = board["columns"].as_array().unwrap();
    assert_eq!(cols.len(), 5);
    assert_eq!(cols[0]["slug"], "backlog");
    assert_eq!(cols[4]["slug"], "done");

    // 2. Admin can create and delete a custom column; agent gets 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/kanban/columns")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"slug": "qa", "title": "QA"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/kanban/columns")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"slug": "qa", "title": "QA"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/api/v1/kanban/columns/qa")
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. POST /api/v1/kanban/tickets creates ticket, indexes in search, pings assignee
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/kanban/tickets")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "title": "Implement Kanban Board",
                        "description": "Build Trello-style board for agents",
                        "priority": "high",
                        "labels": ["backend", "ui"],
                        "assignee_name": "worker-k",
                        "checklist": [{"text": "DB migration", "done": true}, {"text": "REST API", "done": false}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let ticket_id = created["ticket"]["id"].as_str().unwrap().to_string();
    assert_eq!(created["ticket"]["column_slug"], "todo");
    assert_eq!(created["ticket"]["priority"], "high");
    assert_eq!(created["ticket"]["labels"].as_array().unwrap().len(), 2);
    assert_eq!(created["ticket"]["checklist"].as_array().unwrap().len(), 2);

    // Search finds the ticket
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/search?q=Trello")
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sres = body_json(resp).await;
    assert_eq!(sres["results"][0]["kind"], "ticket");

    // worker-k received an auto-ping for assignment
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pings?unread=true")
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["pings"].as_array().unwrap().len(), 1);

    // 4. PATCH /api/v1/kanban/tickets/{id} moves to in_progress
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/kanban/tickets/{ticket_id}"))
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"column_slug": "in_progress", "priority": "urgent"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let patched = body_json(resp).await;
    assert_eq!(patched["ticket"]["column_slug"], "in_progress");
    assert_eq!(patched["ticket"]["priority"], "urgent");

    // 5. POST /api/v1/kanban/tickets/{id}/comments
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/kanban/tickets/{ticket_id}/comments"))
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"body": "Working on it @Antigravity"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // GET /api/v1/kanban/tickets/{id} returns ticket + 1 comment
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/kanban/tickets/{ticket_id}"))
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let detail = body_json(resp).await;
    assert_eq!(detail["comments"].as_array().unwrap().len(), 1);
    assert_eq!(detail["ticket"]["comment_count"], 1);

    // Non-creator agent cannot delete ticket (403)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/kanban/tickets/{ticket_id}"))
                .header(header::AUTHORIZATION, &agent_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 6. MCP tools flow: kanban_board, kanban_create_ticket, kanban_get_ticket, kanban_update_ticket, kanban_add_comment, kanban_delete_ticket
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {
                            "name": "kanban_create_ticket",
                            "arguments": {
                                "title": "MCP Created Ticket",
                                "column_slug": "backlog",
                                "priority": "low"
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mcp_create = body_json(resp).await;
    assert_eq!(mcp_create["result"]["isError"], false);
    let mcp_text = mcp_create["result"]["content"][0]["text"].as_str().unwrap();
    let mcp_ticket: Value = serde_json::from_str(mcp_text).unwrap();
    let mcp_ticket_id = mcp_ticket["ticket"]["id"].as_str().unwrap().to_string();

    // kanban_board via MCP
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::AUTHORIZATION, &agent_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/call",
                        "params": { "name": "kanban_board", "arguments": { "column": "backlog" } }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mcp_board_resp = body_json(resp).await;
    let mcp_board: Value = serde_json::from_str(mcp_board_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(mcp_board["tickets"].as_array().unwrap().len(), 1);

    // kanban_update_ticket, kanban_add_comment, kanban_get_ticket, kanban_delete_ticket via MCP
    for (rpc_id, tool_name, args) in [
        (12, "kanban_update_ticket", json!({"ticket_id": mcp_ticket_id, "column_slug": "done"})),
        (13, "kanban_add_comment", json!({"ticket_id": mcp_ticket_id, "body": "Done via MCP"})),
        (14, "kanban_get_ticket", json!({"ticket_id": mcp_ticket_id})),
        (15, "kanban_delete_ticket", json!({"ticket_id": mcp_ticket_id})),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, &agent_auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": "2.0",
                            "id": rpc_id,
                            "method": "tools/call",
                            "params": { "name": tool_name, "arguments": args }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["result"]["isError"], false, "Tool {tool_name} failed: {v}");
    }

    // Admin deletes the first ticket
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/kanban/tickets/{ticket_id}"))
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn kanban_archive_and_archive_done_flow() {
    let (app, _dir) = setup_app().await;
    let admin_auth = format!("Bearer {BOOTSTRAP_ADMIN}");

    let create = |title: &str, col: &str| {
        let app = app.clone();
        let auth = admin_auth.clone();
        let title = title.to_string();
        let col = col.to_string();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/v1/kanban/tickets")
                        .header(header::AUTHORIZATION, &auth)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({ "title": title, "column_slug": col }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            body_json(resp).await["ticket"]["id"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };

    let t_todo = create("Active Todo", "todo").await;
    let t_done1 = create("Done One", "done").await;
    let t_done2 = create("Done Two", "done").await;

    // Single ticket archive removes it from default board
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/kanban/tickets/{t_done1}"))
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "archived": true }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let patched = body_json(resp).await;
    assert!(patched["ticket"]["archived_at"].as_str().is_some());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/kanban")
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let board = body_json(resp).await;
    let ids: Vec<&str> = board["tickets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&t_done1.as_str()));
    assert!(ids.contains(&t_done2.as_str()));
    assert!(ids.contains(&t_todo.as_str()));

    // archived_only=true returns only archived tickets
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/kanban?archived_only=true")
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let arch_board = body_json(resp).await;
    assert_eq!(arch_board["tickets"].as_array().unwrap().len(), 1);
    assert_eq!(arch_board["tickets"][0]["id"], t_done1);

    // Unarchive restores it
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/api/v1/kanban/tickets/{t_done1}"))
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "archived": false }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_json(resp).await["ticket"]["archived_at"].is_null());

    // POST /api/v1/kanban/archive-done clears both done tickets, keeps todo
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/kanban/archive-done")
                .header(header::AUTHORIZATION, &admin_auth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["archived_count"], 2);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/kanban")
                .header(header::AUTHORIZATION, &admin_auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let board_after = body_json(resp).await;
    let remaining = board_after["tickets"].as_array().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["id"], t_todo);
}
