//! Detect the product name of the AI agent harness running the CLI.

// Snapshot of https://huggingface.co/api/agent-harnesses taken 2026-10-16.
const HARNESS_ENV: &[(&str, &[&str])] = &[
    ("cowork", &["CLAUDE_CODE_IS_COWORK"]),
    ("claude-code", &["CLAUDECODE", "CLAUDE_CODE"]),
    ("codex", &["CODEX_SANDBOX", "CODEX_CI", "CODEX_THREAD_ID"]),
    ("cursor-cli", &["CURSOR_AGENT"]),
    ("cursor", &["CURSOR_TRACE_ID"]),
    ("gemini-cli", &["GEMINI_CLI"]),
    (
        "github-copilot",
        &["COPILOT_MODEL", "COPILOT_ALLOW_ALL", "COPILOT_GITHUB_TOKEN"],
    ),
    ("antigravity", &["ANTIGRAVITY_AGENT"]),
    ("augment-cli", &["AUGMENT_AGENT"]),
    ("cline", &["CLINE_ACTIVE"]),
    ("crush", &["CRUSH"]),
    ("goose", &["GOOSE_TERMINAL"]),
    ("hermes-agent", &["HERMES_SESSION_ID"]),
    ("kilo-code", &["KILOCODE_FEATURE"]),
    ("kiro", &["AGENT_CONTEXT_OUT"]),
    ("openclaw", &["OPENCLAW_SHELL"]),
    ("opencode", &["OPENCODE_CLIENT"]),
    ("pi", &["PI_CODING_AGENT"]),
    ("replit", &["REPL_ID"]),
    ("trae", &["TRAE_AI_SHELL_ID"]),
    ("vtcode", &["VTCODE=1"]),
    ("zed", &["ZED_TERM"]),
];

pub fn detect() -> Option<String> {
    detect_with(|name| std::env::var(name).ok())
}

pub fn detect_with(get: impl Fn(&str) -> Option<String>) -> Option<String> {
    for (agent, vars) in HARNESS_ENV {
        if vars.iter().any(|var| {
            if let Some(name) = var.strip_suffix("=1") {
                get(name).as_deref() == Some("1")
            } else {
                get(var).is_some_and(|value| !value.is_empty())
            }
        }) {
            return Some((*agent).to_string());
        }
    }

    for variable in ["AI_AGENT", "AGENT"] {
        if let Some(value) = get(variable) {
            if let Some(agent) = fallback_name(&value) {
                return Some(agent);
            }
        }
    }
    None
}

fn fallback_name(value: &str) -> Option<String> {
    let token = value
        .split(|ch: char| ch == '_' || ch.is_whitespace() || ch == '/')
        .next()
        .unwrap_or("");
    let name: String = token
        .chars()
        .map(|ch| ch.to_ascii_lowercase())
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .take(32)
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::detect_with;

    fn detect(values: &[(&str, &str)]) -> Option<String> {
        detect_with(|name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        })
    }

    #[test]
    fn detects_claude_code() {
        assert_eq!(detect(&[("CLAUDE_CODE", "1")]), Some("claude-code".into()));
    }

    #[test]
    fn cowork_wins_over_claude_code() {
        assert_eq!(
            detect(&[("CLAUDE_CODE_IS_COWORK", "1"), ("CLAUDE_CODE", "1")]),
            Some("cowork".into())
        );
    }

    #[test]
    fn detects_codex() {
        assert_eq!(detect(&[("CODEX_THREAD_ID", "thread")]), Some("codex".into()));
    }

    #[test]
    fn cursor_cli_wins_over_cursor() {
        assert_eq!(
            detect(&[("CURSOR_AGENT", "1"), ("CURSOR_TRACE_ID", "trace")]),
            Some("cursor-cli".into())
        );
    }

    #[test]
    fn parses_ai_agent_fallback() {
        assert_eq!(
            detect(&[("AI_AGENT", "claude-code_2-1-296_agent")]),
            Some("claude-code".into())
        );
    }

    #[test]
    fn returns_none_when_nothing_is_set() {
        assert_eq!(detect(&[]), None);
    }
}
