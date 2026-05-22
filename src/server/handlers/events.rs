//! `GET /v/{vid}/events` — vault-scoped SSE stream of approval lifecycle.
//!
//! Subscribes to the daemon's broadcast channel and forwards every
//! `ApprovalEvent` whose `tenant_id` matches the URL `{vid}` as an SSE event.
//! A keep-alive comment is sent every 30 seconds so middleboxes don't reap
//! the connection.
//!
//! Auth model: vault_id (a public UUID by current Supabase deployment design)
//! is not a credential — enumerating it cannot reveal vault state without an
//! authenticated mutating call. Future hardening: signed short-lived stream
//! tokens.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::stream::{Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use crate::error::Result;
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;

pub async fn stream(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    validate_vault_id(&vault_id)?;
    let rx = state.events.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        let vault_id = vault_id.clone();
        async move {
            let ev = match result {
                Ok(ev) => ev,
                Err(_) => return None,
            };
            if ev.tenant_id != vault_id {
                return None;
            }
            let payload = match serde_json::to_string(&ev) {
                Ok(s) => s,
                Err(_) => return None,
            };
            Some(Ok(Event::default().event(&ev.kind).data(payload)))
        }
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keep-alive"),
    ))
}
