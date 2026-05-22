//! Server-Sent Events (SSE) endpoint for tenant-scoped approval lifecycle.
//!
//! `GET /events?tenant=<tenant_id>`
//!
//! Subscribes to the daemon's broadcast channel and forwards every
//! `ApprovalEvent` whose `tenant_id` matches as an SSE message. A keep-alive
//! comment is sent every 30 seconds so middleboxes don't reap the connection.
//!
//! Auth model: tenant_id is passed as a query parameter rather than a header
//! because the browser `EventSource` API does not support custom headers.
//! Since tenant_id == Supabase user.id (a public UUID — Supabase's own design),
//! it isn't a credential; an attacker enumerating it cannot do anything
//! without an active Supabase session token to drive any of the existing
//! mutating endpoints. Future hardening: signed short-lived stream tokens.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::stream::{Stream, StreamExt};
use serde::Deserialize;
use tokio_stream::wrappers::BroadcastStream;

use crate::error::Result;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub tenant: String,
}

pub async fn stream(
    State(state): State<Arc<AppState>>,
    Query(q): Query<EventsQuery>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let rx = state.events.subscribe();
    let tenant = q.tenant;

    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        let tenant = tenant.clone();
        async move {
            let ev = match result {
                Ok(ev) => ev,
                // Lagged or channel closed — drop silently; client may reconnect.
                Err(_) => return None,
            };
            if ev.tenant_id != tenant {
                return None;
            }
            let payload = match serde_json::to_string(&ev) {
                Ok(s) => s,
                Err(_) => return None,
            };
            // Emit with `event:` set to the lifecycle kind ("pending" / "approved"
            // / "rejected") so the client can `.addEventListener('pending', …)`
            // rather than parsing every message.
            Some(Ok(Event::default().event(&ev.kind).data(payload)))
        }
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keep-alive"),
    ))
}
