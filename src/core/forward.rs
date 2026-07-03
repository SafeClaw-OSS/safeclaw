//! The daemon's shared outbound HTTP client.
//!
//! Used by the oauth2 token calls, the external-store (GCP) adapter, and — via
//! `server::broker_flow` — the resident proxy's egress. Redirect policy is
//! `none` (the broker forwards a single hop; a 30x is returned to the caller,
//! never chased into a different host).

use once_cell::sync::Lazy;

pub static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build HTTP client")
});

