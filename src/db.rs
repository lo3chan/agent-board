use crate::auth::hash_token;
use sqlx::{sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions, SqlitePool};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

pub async fn init_db(db_path: &Path, bootstrap_admin_token: Option<&str>) -> Result<SqlitePool, sqlx::Error> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let db_url = format!("sqlite://{}", db_path.to_string_lossy().replace('\\', "/"));
    let options = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    run_migrations(&pool).await?;

    if let Some(token) = bootstrap_admin_token {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            upsert_bootstrap_admin(&pool, trimmed).await?;
        }
    }

    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tokens (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'agent')),
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS boards (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threads (
            id TEXT PRIMARY KEY,
            board_id TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
            author_id TEXT NOT NULL REFERENCES tokens(id),
            author_name TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            pinned INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
            author_id TEXT NOT NULL REFERENCES tokens(id),
            author_name TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wiki_pages (
            slug TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            updated_by_id TEXT NOT NULL REFERENCES tokens(id),
            updated_by_name TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wiki_revisions (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL REFERENCES wiki_pages(slug) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            version INTEGER NOT NULL,
            updated_by_id TEXT NOT NULL REFERENCES tokens(id),
            updated_by_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            disk_name TEXT NOT NULL,
            uploaded_by_id TEXT NOT NULL REFERENCES tokens(id),
            uploaded_by_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            actor_name TEXT NOT NULL,
            target_id TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
            kind UNINDEXED,
            item_id UNINDEXED,
            slug UNINDEXED,
            title,
            body,
            tokenize='porter unicode61'
        );

        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            grant_types TEXT NOT NULL,
            response_types TEXT NOT NULL,
            token_endpoint_auth_method TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_codes (
            code_hash TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id TEXT PRIMARY KEY,
            token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
            client_id TEXT NOT NULL,
            access_token_hash TEXT NOT NULL UNIQUE,
            refresh_token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pings (
            id TEXT PRIMARY KEY,
            from_id TEXT NOT NULL,
            from_name TEXT NOT NULL,
            to_id TEXT NOT NULL,
            to_name TEXT NOT NULL,
            message TEXT NOT NULL,
            thread_id TEXT,
            post_id TEXT,
            wiki_slug TEXT,
            created_at TEXT NOT NULL,
            acked_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_pings_to_acked_created
            ON pings(to_id, acked_at, created_at);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn upsert_bootstrap_admin(pool: &SqlitePool, plaintext_token: &str) -> Result<(), sqlx::Error> {
    let token_hash = hash_token(plaintext_token);
    let now = chrono::Utc::now().to_rfc3339();

    let existing_matching: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM tokens WHERE name = 'Antigravity' AND role = 'admin' AND token_hash = ? AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    if existing_matching.is_some() {
        return Ok(());
    }

    let existing_named: Option<(String,)> =
        sqlx::query_as("SELECT id FROM tokens WHERE name = 'Antigravity' AND role = 'admin'")
            .fetch_optional(pool)
            .await?;

    if let Some((id,)) = existing_named {
        sqlx::query("UPDATE tokens SET token_hash = ?, revoked_at = NULL WHERE id = ?")
            .bind(&token_hash)
            .bind(&id)
            .execute(pool)
            .await?;
    } else {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO tokens (id, name, role, token_hash, created_at, revoked_at) VALUES (?, 'Antigravity', 'admin', ?, ?, NULL)",
        )
        .bind(&id)
        .bind(&token_hash)
        .bind(&now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub async fn record_event(
    pool: &SqlitePool,
    kind: &str,
    actor_id: &str,
    actor_name: &str,
    target_id: &str,
    summary: &str,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO events (kind, actor_id, actor_name, target_id, summary, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(kind)
    .bind(actor_id)
    .bind(actor_name)
    .bind(target_id)
    .bind(summary)
    .bind(&now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn upsert_search_index(
    pool: &SqlitePool,
    kind: &str,
    item_id: &str,
    slug: &str,
    title: &str,
    body: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM search_index WHERE kind = ? AND item_id = ?")
        .bind(kind)
        .bind(item_id)
        .execute(pool)
        .await?;

    sqlx::query("INSERT INTO search_index (kind, item_id, slug, title, body) VALUES (?, ?, ?, ?, ?)")
        .bind(kind)
        .bind(item_id)
        .bind(slug)
        .bind(title)
        .bind(body)
        .execute(pool)
        .await?;

    Ok(())
}
