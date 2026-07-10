//! The daemon's shared outbound HTTP client.
//!
//! Used by the oauth2 token calls, the external-store (GCP) adapter, and — via
//! `server::broker_flow` — the resident proxy's egress. Redirect policy is
//! `none` (the broker forwards a single hop; a 30x is returned to the caller,
//! never chased into a different host).

use std::time::Duration;

use once_cell::sync::Lazy;

pub static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // Fail FAST when the TCP/TLS handshake can't complete — a wrong or dead
        // egress proxy (or a firewall black-holing the route) otherwise leaves a
        // connect hanging for the OS default (~75s on macOS), stalling an OAuth
        // exchange past `sc sync`'s own 30s client timeout so the user sees a bare
        // "timeout" instead of the real "couldn't reach the provider" signal. Only
        // the CONNECT is bounded here; a slow-but-progressing response still rides
        // the per-request timeout the callers set.
        .connect_timeout(Duration::from_secs(8))
        .build()
        .expect("failed to build HTTP client")
});

