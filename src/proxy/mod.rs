//! Broker handlers — the agent-facing R-side sugar routes.
//!
//! v1 URL surface (now served on the single daemon port, gated by the
//! agent-key — see `server::broker_router`):
//!
//! ```text
//! POST   /v/{vid}/export/{key}              R-side Export sugar
//! ANY    /v/{vid}/use/{service}             R-side Use (no sub-path)
//! ANY    /v/{vid}/use/{service}/{*rest}     R-side Use (with sub-path)
//! ANY    /v/{vid}/stream/{service}/{*rest}  streaming passthrough (git, …)
//! ```
//!
//! `use`/`export` compile the request to a sudp `Operation` and create a
//! pending approval, returning `{ op_id, r, expires_at, approve_url, poll_url }`.
//! U authorizes via `POST /op/{op_id}/approve`; R polls via `GET /op/{op_id}`.
//!
//! These used to live on a second `proxy_port` (:23295); the 2026-06-23
//! zero-inbound pivot collapsed the daemon to one port and the routes moved
//! into the main router. This module now only exposes the handler functions;
//! the route table + agent-key gate live in `server::broker_router`.

pub mod env;
pub mod stream;
pub mod use_broker;
