//! `GET /skill.md` — 302 redirect to the canonical skill on GitHub.
//!
//! The skill is the client-side usage guide for agents. Its single source of
//! truth is `skills/safeclaw/SKILL.md` in the OSS repo, served raw by GitHub.
//! The CLI also embeds the version-matched copy for `sc skill install`; this
//! redirect is the browsable current copy on `main`.
//!
//! This endpoint is kept only so older prompts / muscle memory that hit the
//! daemon still resolve — it just forwards to the same raw URL. No `?agent=`
//! variant handling: the agent reads the markdown as a guide; if it wants to
//! save it as a formatted skill file it adds its own frontmatter.

use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};

/// Canonical skill location. Points at `main` (the skill is additive and
/// deployment-agnostic, so it doesn't need to be version-pinned to a tag).
const SKILL_RAW_URL: &str =
    "https://raw.githubusercontent.com/getsafeclaw/safeclaw/main/skills/safeclaw/SKILL.md";

pub async fn skill_md() -> impl IntoResponse {
    (StatusCode::FOUND, [(header::LOCATION, SKILL_RAW_URL)])
}
