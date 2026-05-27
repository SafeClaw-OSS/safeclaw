//! Short-lived CLI commands that talk to a `safeclaw serve` daemon over HTTP.
//!
//! Each subcommand is a small async fn — kept here (not in `handlers/`)
//! because handlers are the daemon's HTTP request side; this is the
//! client side. Same binary, different mode.

pub mod admin;
pub mod doctor;
pub mod env;
pub mod webauthn;
pub mod login;
pub mod ls;
pub mod passkey;
pub mod profile;
pub mod read;
pub mod status;
pub mod store;
pub mod unlock;
pub mod vault;
pub mod write;
