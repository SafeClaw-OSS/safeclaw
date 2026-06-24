//! Short-lived CLI commands that talk to a `safeclaw start` daemon over HTTP.
//!
//! Each subcommand is a small async fn — kept here (not in `handlers/`)
//! because handlers are the daemon's HTTP request side; this is the
//! client side. Same binary, different mode.

pub mod active;
pub mod admin;
pub mod config;
pub mod custodian;
pub mod doctor;
pub mod env;
pub mod install;
pub mod login;
pub mod ls;
pub mod passkey;
pub mod secret;
pub mod service;
pub mod status;
pub mod store;
pub mod unlock;
pub mod vault;
pub mod webauthn;
