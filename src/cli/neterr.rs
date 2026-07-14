//! OBJECTIVE network-failure messaging for the CLI's direct-to-backend calls.
//!
//! Principle: state the OBSERVED fact ("couldn't reach X") and only HINT at a
//! proxy CONDITIONALLY. A reachability failure can't tell you *why* the host is
//! unreachable, so we never assert "missing proxy" as the cause — at most we say
//! "if this machine needs a proxy for outbound HTTPS, `sc proxy set <url>`". The
//! same wording is reused everywhere (`sc sync`, `sc agent`, `sc login`, doctor)
//! so the signal an agent/human sees is uniform.

/// The one conditional proxy hint, appended to a reachability failure.
pub const PROXY_HINT: &str =
    "if this machine needs a proxy for outbound HTTPS, set one with `sc proxy set <url>`";

/// A reqwest error that is a *reachability* failure (couldn't connect, timed
/// out), as opposed to a logical/HTTP error where a proxy hint would misdirect.
pub fn is_unreachable(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout()
}

/// Message for a failed request to `target` (a host or URL). Objective either
/// way; adds the proxy hint only when the failure is a reachability one.
pub fn reach_failed(target: &str, err: &reqwest::Error) -> String {
    if is_unreachable(err) {
        format!("couldn't reach {target}: {err} — {PROXY_HINT}.")
    } else {
        format!("couldn't reach {target}: {err}")
    }
}

/// String-only variant for an error that already crossed a process boundary
/// (e.g. the daemon's sync error surfaced by `sc sync`, where we no longer have
/// the typed `reqwest::Error`): append the proxy hint iff the message looks like
/// a reachability failure and doesn't already carry it.
pub fn with_proxy_hint(msg: &str) -> String {
    if msg.contains("sc proxy set") || !looks_unreachable(msg) {
        return msg.to_string();
    }
    format!("{msg} — {PROXY_HINT}.")
}

/// Heuristic: does a stringified error read as a reachability failure? Used only
/// for the process-boundary case above; the typed path uses `is_unreachable`.
fn looks_unreachable(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.starts_with("reach ")
        || m.contains("couldn't reach")
        || m.contains("connection refused")
        || m.contains("connection reset")
        || m.contains("timed out")
        || m.contains("timeout")
        || m.contains("dns error")
        || m.contains("error sending request")
        || m.contains("connect error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_proxy_hint_only_on_reachability_and_not_twice() {
        // Reach failure → hint appended.
        let m = with_proxy_hint("reach https://api.safeclaw.pro: connection refused");
        assert!(m.contains("sc proxy set"));
        // Already carries the knob → left alone (no double hint).
        assert_eq!(
            with_proxy_hint("couldn't reach x: timed out — sc proxy set <url>"),
            "couldn't reach x: timed out — sc proxy set <url>"
        );
        // A logical/non-network error → untouched, NOT told to set a proxy.
        assert_eq!(with_proxy_hint("vault not found"), "vault not found");
    }

    #[test]
    fn looks_unreachable_matches_transport_shapes_not_logical() {
        assert!(looks_unreachable("reach host: whatever"));
        assert!(looks_unreachable(
            "error sending request for url (...): timed out"
        ));
        assert!(!looks_unreachable("HTTP 404 not found"));
        assert!(!looks_unreachable("invalid pair-token"));
    }
}
