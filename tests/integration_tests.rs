use agent_board::{build_app, db::init_db, AppState};
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
    let state = AppState {
        pool,
        data_dir: dir.path().to_path_buf(),
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
    assert_eq!(tools.len(), 14);

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
