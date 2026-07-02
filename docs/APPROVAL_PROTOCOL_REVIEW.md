# Approval protocol review — are we reinventing this? (2026-07-03)

**Question.** Our approve flow (agent's HTTP call → `202` + `approval{}` → user
taps a passkey elsewhere → agent polls `/op/{id}` → `status: ok` + `value`)
is home-grown. Is the *shape* idiosyncratic, and is the *format* modern?

**Verdict: the shape is NOT home-grown — it is the exact shape of two OAuth
standards and several mainstream products.** The format needs three small,
cheap alignments (below), not a redesign.

## 1. The same shape in the wild

| | ours | OAuth Device Flow (RFC 8628, = `gh auth login`) | OpenID CIBA (bank-grade approve-on-phone) | Stripe PaymentIntents | Azure async request-reply |
|---|---|---|---|---|---|
| initiate | `POST /use/...` → 202 | `POST /device_authorization` | `POST /bc-authorize` | `POST /payment_intents` | `POST …` → 202 |
| pending handle | `op_id` | `device_code` | `auth_req_id` | intent `id` | `Operation-Location` |
| where human approves | `approval.approve_url` (deep link) | `verification_uri_complete` | push to phone | `next_action.redirect_to_url` | — |
| agent waits by | polling `poll_url` | polling token endpoint | poll / ping / push | poll or webhook | polling the location |
| pending signal | `status: "pending"` | `authorization_pending` error | `authorization_pending` | `status: requires_action` | 200 + `status: running` |
| terminal | `ok` / `rejected` / 404-expired | token / `access_denied` / `expired_token` | same | `succeeded` / `canceled` | `succeeded` / `failed` |
| lifetime / pace | `expires_at` (+30 min) | `expires_in` + `interval` | `expires_in` + `interval` | — | `Retry-After` |

Also convergent, agent-era: **MCP's 2026-07 RC** replaced held-open SSE
server-requests with `InputRequiredResult` — *return a result that says
"input required", let the client resume with a retry*. That is exactly our
streaming captive-portal (reject-before-forward + link + retry). And MCP
elicitation mandates **URL mode** for anything credential-adjacent — our
`approve_url` *is* URL mode. The `value` envelope (`{status, headers, body,
body_base64?}`) matches AWS API Gateway's Lambda-proxy shape
(`{statusCode, headers, body, isBase64Encoded}`).

So: interrupting the HTTP flow with a pending resource + out-of-band human
approval + poll-to-resume is the *standard* way to do human-gated agent
actions in 2026 — including for payments (Stripe, x402) and step-up auth
(RFC 9470). Not 闭门造车.

## 2. Where we deviated from convention → ✅ ADOPTED (2026-07-03, rides the release after v1.0.41)

1. **Pacing signal** (RFC 8628/CIBA `interval`; Azure `Retry-After`):
   `Retry-After` header on the 202 AND on pending polls; `approval.interval`.
   Kills guess-loops like the agent's improvised 60×1s.
   (`approval/store.rs POLL_INTERVAL_HINT_SECS`, `use_broker.rs pending_202`.)
2. **`Location: /op/{id}`** on the 202 — the async-request-reply convention;
   generic HTTP tooling understands the flow without reading our docs.
3. **`approval.expires_in`** (relative seconds, clock-skew-proof) alongside the
   absolute `expires_at`.

## 3. Considered, deliberately NOT adopted

- **Held-open request until approved** (long-poll the original call): the exact
  thing MCP just *moved away from* (SEP-2322); breaks on proxies/timeouts and
  can't survive an agent restart. Our pending-resource model is the right one.
- **`user_code`** (device flow's type-this-code): unnecessary — we deep-link
  (`verification_uri_complete` equivalent).
- **Webhook/ping callback** (CIBA ping mode): agents are local + short-lived;
  SSE (`/v/{vid}/events`) already covers push. Revisit only for long-lived
  server-side agents.
- **RFC 9457 `application/problem+json` errors**: nice-to-have, a cross-cutting
  sweep of every error body; not worth it pre-launch. Keep `{error, message}`.
- **Renaming our fields to OAuth's** (`op_id`→`auth_req_id` etc.): cosplay, not
  compliance — we are not an OAuth token endpoint. Keep our names, document the
  mapping (§1 table).

## 4. Status quo of the wire contract (post v1.0.41)

- 202: `{status: "pending", op_id, r, approval: {id, approve_url, poll_url,
  expires_at, expires_in, interval}}` + `Location` + `Retry-After` headers.
- poll: `{status: "pending" | "ok" | "rejected" | "consumed", value?, ...}`;
  pending carries `Retry-After`; 404 = expired/unknown → re-POST the original
  request.
- `value` for Use = the upstream envelope **as an object** `{status, headers,
  body, body_base64?}`; for Export = the raw secret string (never parsed).
- Pending-op TTL 30 min (`approval/store.rs DEFAULT_TTL`); relay poll covers it.
