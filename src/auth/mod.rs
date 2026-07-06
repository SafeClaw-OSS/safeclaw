//! Auth mechanisms.
//!
//! Under the phantom-only broker there is no per-request credential injection in
//! Rust: the agent's tool writes the phantom where the credential belongs and
//! the resident proxy substitutes the real value at egress. The only auth
//! MECHANISM that is not a textual substitution is OAuth2 (refresh -> access
//! token), in `oauth2`; `connect` completes the OAuth CONNECT handshake on the
//! daemon.

pub mod oauth2;
pub mod connect;
