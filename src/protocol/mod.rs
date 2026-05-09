//! SUDP protocol layer.
//!
//! - `operation`: `Operation` = `(act, valid)` — the U↔T contract.
//! - `grant`: `Grant` = `(o, r, credential_id, user_key, assertion, opt)`
//!   submitted to /grant.
//! - `render`: human-readable rendering of an `Operation` for the approve UI.

pub mod grant;
pub mod operation;
pub mod render;

pub use grant::{validate_grant, Grant, ValidatedGrant};
pub use operation::{Act, NewCredential, Operation, Valid, WritePatch};
pub use render::render_operation;
