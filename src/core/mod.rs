//! Service broker core — request routing, policy evaluation, upstream
//! forwarding, approval flow. Ported from the per-VM dev branch and adapted
//! for the SaaS multi-vault custodian.

pub mod forward;
pub mod policy;
