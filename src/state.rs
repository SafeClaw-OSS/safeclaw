//! Top-level application state.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::approval::ApprovalStore;
use crate::config::Config;
use crate::passkey::challenge::ChallengeStore;
use crate::service::ServiceRegistry;
use crate::storage::TenantDir;

/// Broadcast payload for the per-tenant SSE channel. The receiver-side filter
/// is on `tenant_id`; subscribers belonging to other tenants drop the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub tenant_id: String,
    pub approval_id: String,
    /// One of "pending" | "approved" | "rejected".
    pub kind: String,
    /// Summary of the approved Operation (act.kind, target, scope) — present
    /// for pending. Frontend uses it to render the request card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_summary: Option<Value>,
    /// Cached upstream response for broker (Use) approvals after approve —
    /// `{status, headers, body, body_base64}` JSON. Present for approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_preview: Option<Value>,
    /// Rejection reason — present for rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Broadcast channel capacity. Lagging subscribers (typically tabs sleeping
/// in a background pinch) will drop events older than this — they reconnect
/// fresh and lose history, which is acceptable for a watcher UI.
const EVENT_CHANNEL_CAPACITY: usize = 128;

pub struct AppState {
    pub config: Config,
    pub tenants: TenantDir,
    pub challenges: Mutex<ChallengeStore>,
    pub approvals: Mutex<ApprovalStore>,
    pub services: ServiceRegistry,
    pub events: broadcast::Sender<ApprovalEvent>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let tenants = TenantDir::new(&config.state_dir);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            config,
            tenants,
            challenges: Mutex::new(ChallengeStore::new()),
            approvals: Mutex::new(ApprovalStore::new()),
            services: ServiceRegistry::load(),
            events,
        }
    }

    /// Emit an event into the broadcast channel. Silently swallows the "no
    /// active subscribers" case (it's normal — happens before any /try tab is
    /// connected).
    pub fn emit_event(&self, ev: ApprovalEvent) {
        let _ = self.events.send(ev);
    }
}
