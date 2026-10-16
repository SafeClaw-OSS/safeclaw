//! Small cross-cutting helpers with no better home.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time in unix seconds, saturating to 0 before the epoch
/// (never in practice). One shared definition for the identity-wave call sites
/// (`device_auth`, `agent_pop`/`agent_shim`, the proxy handler) that each used to
/// carry their own copy of this idiom.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A Unicode bidirectional formatting control (Trojan Source,
/// CVE-2021-42574): ALM, LRM, RLM, the embeddings and overrides LRE..RLO and
/// the isolates LRI..PDI. Displayed text can be made to read differently from
/// its bytes with these, so untrusted display text may not carry them.
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// A character untrusted text may not put in front of a human: a C0, DEL or
/// C1 control (a terminal reads these as commands, CWE-150) or a bidi control.
pub fn is_unsafe_display_char(c: char) -> bool {
    c.is_control() || is_bidi_control(c)
}

/// The one sanitizer for human-readable output of untrusted text (CLI lines
/// that print definition-derived strings, and the gate's rejection
/// messages): every unsafe character except `\n` and `\t` is replaced by its
/// visible `\u{..}` escape. The output contains no escape sequence a terminal
/// acts on, and sanitizing it again changes nothing. JSON output needs none
/// of this (serde_json escapes control characters).
pub fn terminal_safe(s: &str) -> Cow<'_, str> {
    let unsafe_char = |c: char| c != '\n' && c != '\t' && is_unsafe_display_char(c);
    if !s.chars().any(unsafe_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if unsafe_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_safe_escapes_controls_and_bidi_only() {
        assert!(matches!(terminal_safe("api.github.com"), Cow::Borrowed(_)));
        assert_eq!(terminal_safe("a\nb\tc"), "a\nb\tc");
        assert_eq!(terminal_safe("x\u{1b}[31my"), "x\\u{1b}[31my");
        assert_eq!(terminal_safe("r\rs"), "r\\u{d}s");
        assert_eq!(terminal_safe("\u{7f}\u{85}\u{9b}"), "\\u{7f}\\u{85}\\u{9b}");
        assert_eq!(terminal_safe("ab\u{202e}cd"), "ab\\u{202e}cd");
        assert_eq!(terminal_safe("\u{2066}\u{2069}"), "\\u{2066}\\u{2069}");
        // Non-ASCII text that is not a control stays as written.
        assert_eq!(
            terminal_safe("Gmail \u{90ae}\u{4ef6}"),
            "Gmail \u{90ae}\u{4ef6}"
        );
        // Idempotent.
        let once = terminal_safe("\u{1b}]0;x\u{7}").into_owned();
        assert_eq!(terminal_safe(&once), once);
    }
}
