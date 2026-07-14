//! Auth mechanisms.
//!
//! Under the phantom-only broker there is no per-request credential injection in
//! Rust: the agent's tool writes the phantom where the credential belongs and
//! the resident proxy substitutes the real value at egress. The auth
//! MECHANISMS that are not textual substitutions are the MINTED ones — OAuth2
//! (refresh -> access token) in `oauth2`, Snaplii's bespoke key -> JWT
//! exchange in `snaplii`; `connect` completes the OAuth CONNECT handshake on
//! the daemon.

pub mod connect;
pub mod loopback;
pub mod oauth2;
pub mod snaplii;
