//! Short-lived CLI commands that talk to a `safeclaw serve` daemon over HTTP.
//!
//! Each subcommand is a small async fn — kept here (not in `handlers/`)
//! because handlers are the daemon's HTTP request side; this is the
//! client side. Same binary, different mode.

pub mod doctor;
pub mod login;
pub mod ls;
pub mod profile;
pub mod read;
pub mod status;
pub mod stores;
pub mod unlock;
pub mod vaults;
