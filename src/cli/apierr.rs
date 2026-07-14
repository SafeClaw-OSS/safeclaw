//! Uniform CLI rendering of SafeClaw API error bodies.
//!
//! Both daemon ports answer errors as RFC 9457 problem+json — `code` +
//! `detail`, with legacy `error` / `message` dual-emitted. Render them as ONE
//! line, `<code>: <detail>`, so stderr carries the same machine code the wire
//! did and an agent can branch on it without re-parsing JSON. Non-JSON bodies
//! and older daemons degrade to the raw text.

/// Extract `(code, detail)` from an error body. Tolerates the legacy
/// `{error, message}` shape and non-JSON bodies (code `None`, body verbatim).
pub fn parse(body: &str) -> (Option<String>, String) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return (None, body.trim().to_string());
    };
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let code = get("code").or_else(|| get("error"));
    let detail = get("detail")
        .or_else(|| get("message"))
        .unwrap_or_else(|| body.trim().to_string());
    (code, detail)
}

/// One-line rendering for an HTTP error reply: `<code>: <detail>`, falling
/// back to `HTTP <status>: <body>` when the body names no code.
pub fn line(status: u16, body: &str) -> String {
    match parse(body) {
        (Some(code), detail) => format!("{}: {}", code, detail),
        (None, detail) if !detail.is_empty() => format!("HTTP {}: {}", status, detail),
        (None, _) => format!("HTTP {}", status),
    }
}

/// True iff this reply is the registry's `vault_locked` (HTTP 423 or either
/// code field), the one state every CLI surface maps to the same hint.
pub fn is_vault_locked(status: u16, body: &str) -> bool {
    status == 423 || parse(body).0.as_deref() == Some("vault_locked")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_problem_json_and_legacy_and_raw() {
        let p = r#"{"type":"https://safeclaw.pro/errors/vault_locked","code":"vault_locked","detail":"vault locked","error":"vault_locked","message":"vault locked"}"#;
        assert_eq!(
            parse(p),
            (Some("vault_locked".into()), "vault locked".into())
        );
        let legacy = r#"{"error":"conflict","message":"already exists"}"#;
        assert_eq!(
            parse(legacy),
            (Some("conflict".into()), "already exists".into())
        );
        assert_eq!(parse("nope"), (None, "nope".into()));
    }

    #[test]
    fn vault_locked_detected_by_status_or_code() {
        assert!(is_vault_locked(423, ""));
        assert!(is_vault_locked(409, r#"{"error":"vault_locked"}"#));
        assert!(!is_vault_locked(409, r#"{"error":"conflict"}"#));
    }
}
