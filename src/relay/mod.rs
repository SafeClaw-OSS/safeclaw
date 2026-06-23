//! Cloud op-relay client (Slice-2 reachability half).
//!
//! A zero-inbound localhost daemon can't be reached by a browser approving on
//! the web. So instead of the cloud proxying *in* to the daemon, the daemon
//! **dials out**: on op creation it registers the pending op with the cloud
//! relay (op-id, its HPKE pubkey, the op summary, the challenge `r`), then
//! polls the relay for the browser-deposited grant. When the grant arrives it
//! is applied through the daemon's own `/op/{id}/approve` endpoint (so the
//! battle-tested approve path — incl. the §4.2 W_c unseal — runs unchanged).
//!
//! The relay is **blind to W_c**: the grant the browser deposits carries W_c
//! HPKE-sealed to this daemon's `sc_pk` (see `crypto::envelope`), opened only
//! here. Auth to the relay is the shared `SAFECLAW_ADMIN_KEY` for v1
//! (daemon-pubkey-pinned auth is a later tier).
//!
//! All of this is **opt-in**: when `config.relay_url` is `None` the daemon is
//! purely local (the legacy op-page path) and none of this runs.

pub mod client;
