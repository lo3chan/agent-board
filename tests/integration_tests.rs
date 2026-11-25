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
