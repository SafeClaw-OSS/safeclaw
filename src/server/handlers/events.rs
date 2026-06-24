//! `GET /v/{vid}/events` — vault-scoped SSE stream of approval lifecycle.
//!
//! Subscribes to the daemon's broadcast channel and forwards every
//! `ApprovalEvent` whose `vault_id` matches the URL `{vid}` as an SSE event.
//! A keep-alive comment is sent every 30 seconds so middleboxes don't reap
//! the connection.
//!
//! Auth model: vault_id (a public UUID by current Supabase deployment design)
//! is not a credential — enumerating it cannot reveal vault state without an
//! authenticated mutating call. Future hardening: signed short-lived stream
//! tokens.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{
    extract::{Path, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::stream::{Stream, StreamExt};
use tokio::sync::OwnedSemaphorePermit;
use tokio_stream::wrappers::BroadcastStream;

use crate::error::{AppError, Result};
use crate::server::handlers::op::validate_vault_id;
use crate::state::AppState;

/// Maximum concurrent SSE connections per vault. Generous enough for normal
/// use (browser tab + mobile + dev tool open simultaneously) while capping
/// the file-descriptor exhaustion surface from a connection-flood attack.
const MAX_SSE_PER_VAULT: usize = 50;

type SseItem = std::result::Result<Event, Infallible>;

/// Wraps a boxed stream and holds a semaphore permit. When Axum drops the
/// SSE response (client disconnects), this struct is dropped, releasing the
/// permit and decrementing the per-vault connection count automatically.
/// The inner stream is `Pin<Box<...>>` so this type is `Unpin`.
struct PermitStream {
    inner: Pin<Box<dyn Stream<Item = SseItem> + Send>>,
    _permit: OwnedSemaphorePermit,
}

impl Stream for PermitStream {
    type Item = SseItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

pub async fn stream(
    State(state): State<Arc<AppState>>,
    Path(vault_id): Path<String>,
) -> Result<Sse<impl Stream<Item = SseItem>>> {
    validate_vault_id(&vault_id)?;

    // Acquire a per-vault semaphore slot. try_acquire_owned() fails immediately
    // if all MAX_SSE_PER_VAULT slots are taken; the OwnedSemaphorePermit is
    // held in PermitStream so the slot is released when the stream drops.
    let semaphore = {
        let mut sems = state.sse_semaphores.lock().unwrap();
        Arc::clone(
            sems.entry(vault_id.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(MAX_SSE_PER_VAULT))),
        )
    };
    let permit = semaphore
        .try_acquire_owned()
        .map_err(|_| AppError::TooManyRequests)?;

    let rx = state.events.subscribe();
    let inner: Pin<Box<dyn Stream<Item = SseItem> + Send>> =
        Box::pin(BroadcastStream::new(rx).filter_map(move |result| {
            let vault_id = vault_id.clone();
            async move {
                let ev = match result {
                    Ok(ev) => ev,
                    Err(_) => return None,
                };
                if ev.vault_id != vault_id {
                    return None;
                }
                let payload = match serde_json::to_string(&ev) {
                    Ok(s) => s,
                    Err(_) => return None,
                };
                Some(Ok(Event::default().event(&ev.kind).data(payload)))
            }
        }));

    let guarded = PermitStream { inner, _permit: permit };

    Ok(Sse::new(guarded).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keep-alive"),
    ))
}
