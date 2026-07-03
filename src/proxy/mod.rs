//! Agent-facing broker plane.
//!
//! Live credential traffic rides the resident phantom-only HTTPS proxy (a
//! separate localhost listener owned by the daemon). The only HTTP route left
//! here is the `/export` disabled stub — raw-secret export is off the agent
//! surface (the op-plane Export ceremony is the human path).

pub mod env;
