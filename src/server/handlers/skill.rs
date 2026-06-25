//! `GET /skill.md` — 302 redirect to the canonical skill on GitHub.
//!
//! The skill is the client-side usage guide for agents. Its single source of
//! truth is `static/safeclaw-skill.md` in the OSS repo, served raw by GitHub.
//! We deliberately DON'T embed it in the binary — it's a low-frequency doc
//! that would only bloat the bin, and a per-deployment copy would drift from
//! the repo. The install prompt points agents straight at the GitHub raw URL
//! (readable BEFORE install, so the agent can audit what it's about to run).
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
    "https://raw.githubusercontent.com/SafeClaw-OSS/safeclaw/main/static/safeclaw-skill.md";

pub async fn skill_md() -> impl IntoResponse {
    (StatusCode::FOUND, [(header::LOCATION, SKILL_RAW_URL)])
}
