//! `GET /skill.md?agent=<variant>` — deployment-agnostic skill file for LLM agents.
//!
//! Serves the canonical SafeClaw skill markdown so any agent can install it
//! directly from the daemon URL. Body is always the same static template;
//! only the frontmatter (and the `Content-Disposition` filename hint) varies
//! by `?agent=` param:
//!
//! | agent    | frontmatter        | filename       |
//! |----------|--------------------|----------------|
//! | claude   | YAML name+desc     | safeclaw.md    |
//! | cursor   | YAML desc+globs    | safeclaw.mdc   |
//! | codex    | none               | AGENTS.md      |
//! | openclaw | none               | safeclaw.md    |
//! | (other)  | none               | safeclaw.md    |
//!
//! No auth, no vault context. CORS open (`Access-Control-Allow-Origin: *`)
//! so the agent can self-fetch it.
//!
//! OSS users: `http://localhost:23294/skill.md`
//! SaaS users: `https://api.safeclaw.pro/skill.md` (pro-backend transparent proxy)

use axum::{
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;

const SKILL_BODY: &str = include_str!("../../../static/safeclaw-skill.md");

const SHARED_DESCRIPTION: &str = "Forward requests to external services through the user's SafeClaw vault. SafeClaw injects stored credentials server-side; the agent never sees raw secrets. Each call is gated by a single-use, passkey-signed approval from the user. Reads $SAFECLAW_VAULT_URL + $SAFECLAW_API_KEY from the shell env. Use this skill whenever the user asks to call an external service (GitHub, Gmail, LLM provider, etc.) that may be routed through SafeClaw. Always discover available services by GETting the registry first.";

#[derive(Debug, Deserialize)]
pub struct SkillQuery {
    agent: Option<String>,
}

pub async fn skill_md(Query(q): Query<SkillQuery>) -> impl IntoResponse {
    let agent = q.agent.as_deref().unwrap_or("").to_lowercase();
    let (frontmatter, filename) = match agent.as_str() {
        "claude" => (
            format!(
                "---\nname: safeclaw\ndescription: {}\n---\n\n",
                SHARED_DESCRIPTION
            ),
            "safeclaw.md",
        ),
        "cursor" => (
            format!(
                "---\ndescription: {}\nglobs:\n  - \"**/*\"\nalwaysApply: false\n---\n\n",
                SHARED_DESCRIPTION
            ),
            "safeclaw.mdc",
        ),
        "codex" => (String::new(), "AGENTS.md"),
        _ => (String::new(), "safeclaw.md"),
    };

    let body = format!("{}{}", frontmatter, SKILL_BODY);
    let disposition = format!("inline; filename=\"{}\"", filename);

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).unwrap_or_else(|_| {
            HeaderValue::from_static("inline; filename=\"safeclaw.md\"")
        }),
    );

    (StatusCode::OK, headers, body)
}
