//! v3 store adapters.
//!
//! A `Store` (configured in `vault.aux.stores`) plus its kind-specific
//! state materialises into an `Adapter` at runtime. Adapters are enum-
//! dispatched so each new kind is one variant + one match arm; this stays
//! tractable for the 3-5 stores we expect to ship and avoids the
//! `Box<dyn>` + `async-trait` dance for two adapter kinds.
//!
//! See `safeclaw/design/stores-and-items.md` §6 for the adapter contract.

mod adapter;
pub mod adapters;

pub use adapter::{build_adapter, Adapter, AdapterError};
