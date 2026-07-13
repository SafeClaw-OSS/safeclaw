//! SUDP protocol layer (deployment-facing).
//!
//! - `operation`: re-exports of [`sudp::Operation`], [`sudp::Act`],
//!   [`sudp::ActType`], etc., plus SafeClaw helpers that pull
//!   deployment-specific payloads out of `act.scope` (Enroll credential,
//!   Write patch, Export target).
//! - `grant`: `Grant` (wire form) + `validate_grant` (pre-redemption
//!   binding/freshness/assertion checks).
//! - `render`: human-readable rendering of an `Operation` for the approve UI.
//! - `consent`: acts.toml descriptor table — static consent copy for
//!   control-plane acts, interpolated over the signed op's fields.

pub mod consent;
pub mod grant;
pub mod operation;
pub mod render;

pub use grant::{validate_grant, Grant, ValidatedGrant};
pub use operation::{Act, ActType, Bind, NewCredential, Operation, RecipientPk, Valid, WritePatch};
pub use render::render_operation;
