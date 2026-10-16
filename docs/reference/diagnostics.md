# Diagnostics: error codes and surfaces

This page lists SafeClaw error codes, response shapes, actions, and known blind spots. SafeClaw reports problems loudly and leaves unrelated upstream errors without a SafeClaw marker.

`src/error.rs::ScCode` is the single registry; this table is its rendering and
changes in the same commit. Codes are snake_case and stable, so never renumber
or reuse them.

## Wire shapes (one row, three renderings)

| Surface | Shape |
|---|---|
| Control port :23293 + API face :23294 | RFC 9457 `application/problem+json`: `type` (`https://safeclaw.pro/errors/<code>`), `title`, `status`, `detail` + extensions `code`, `action`, `cause`. Legacy `error`/`message` dual-emitted for one transition window. |
| Proxy MITM plane :23294 | `text/plain` (deliberately never parseable as the upstream's payload), body first line `SafeClaw: <code>: <message>`, header `x-safeclaw-error: <code>`. Captive bodies (approval / widen) keep their text+JSON-tail format and carry the code header. |
| CLI stderr | `<code>: <message>` (`cli/apierr.rs`), same code the wire carried. |

`action` = what the agent does next: `unlock` (have the user unlock), `approve`
(follow the approve URL in the body), `retry`, `configure` (a knob, named in
the message), `fix_request`, `none` (explicit refusal, do not work around it).
`cause` = attribution: `request`/`auth`/`vault`/`policy`/`config`/`internal`,
plus `environment` and `upstream` which are NOT SafeClaw problems, reported by
SafeClaw because it is the hop that observed them.

## Codes

| code | status | action | cause | meaning |
|---|---|---|---|---|
| `bad_request` | 400 | fix_request | request | malformed request |
| `unauthorized` | 401 | configure | auth | missing/invalid credential on a control/API call |
| `forbidden` | 403 | none | auth | authenticated but not allowed |
| `not_found` | 404 | fix_request | request | no such resource |
| `method_not_allowed` | 405 | fix_request | request | API face is GET-only |
| `conflict` | 409 | fix_request | request | state conflict |
| `vault_locked` | 423 | unlock | vault | vault has no in-memory key; canonical hint: run `sc up` |
| `vault_access_revoked` | 403 | configure | auth | this account is no longer a member of the vault; ask a vault admin to add it back |
| `vault_deleted` | 410 | none | vault | this vault was deleted |
| `vault_key_changed` | 409 | unlock | vault | the vault was re-keyed after its members changed; approve `sc unlock` to read rows sealed under the new key |
| `rate_limited` | 429 | retry | request | slow down |
| `internal` | 500 | retry | internal | daemon bug/failure |
| `ca_unavailable` | 500 | retry | internal | resident CA unreadable |
| `agent_key` | 407 | configure | auth | phantom-bearing request without a verified agent identity (run the agent through `sc run`; set it up with `sc setup --name <name>` or `sc agent add`) |
| `agent_not_admitted` | 403 | configure | auth | the agent proved its identity, but the account's ledger does not admit it (never approved, or revoked); refused on every vault, whatever its Agent access page lists. Fix: run `sc setup --name <name>` or `sc agent add` |
| `agent_not_in_account` | 403 | configure | auth | (cloud op relay) the agent isn't registered to the account this machine is signed in to. The daemon itself answers `agent_not_admitted`. Fix: run `sc setup --name <name>` or `sc agent add` on this machine |
| `ambiguous_phantom` | 400 | fix_request | request | bare phantom on a multi-secret connection; use a role phantom |
| `approval_needed` | 401 | approve | policy | policy asks; body carries approve/poll URLs + op id |
| `approval_register` | 503 | retry | internal | could not open the approval op |
| `approver_not_authorized` | 403 | none | auth | the passkey that approved is neither the requester nor an admin of this shared vault; the request stays pending |
| `wk_refused_v2` | 400 | none | request | an approval delivered an unlock secret instead of the vault key and the approver's signature; an approver's identity key never leaves their browser, so the daemon refuses it. The request stays pending; reload the approval page (it needs the current console) |
| `grant_id_invalid` | 403 | none | auth | the approval's identity signature is missing, does not verify, or names someone other than the owner of the passkey that approved; the request stays pending |
| `device_not_admitted` | 403 | configure | auth | this device has no valid owner-signed admit over its device and daemon keys, so no approval can be sealed to it. Fix: run `sc setup --name <name>` or `sc login` |
| `ledger_stale` | 423 | retry | environment | SafeClaw could not pull a verified device list from your account for 7 days; vaults are locked (data stays) until it reconnects |
| `ledger_device_revoked` | 403 | configure | auth | the account owner revoked this device (a verified revoke in the device list; a newer admit of a re-paired device follows its revoke). The daemon latches it. Fix: run `sc setup --name <name>` or `sc login` to pair again |
| `ledger_head_invalid` | 403 | none | auth | the account's device list does not match its owner-signed head (a forged or truncated list); the daemon keeps its previous view |
| `broker_body_limit` | 413 | configure | config | body exceeds the inspectable cap; raise `--body-cap` if legitimate |
| `egress_unreachable` | 502 | configure | environment | forward hop failed to connect (NOT a credential problem) |
| `exposes_unsupported` | 400 | fix_request | request | role not mintable yet |
| `host_forbidden` | 403 | none | policy | destination fails the private/metadata egress floor |
| `host_not_anchored` | 403 | approve | policy | connection not anchored to this host; body carries a one-tap widen |
| `multi_connection` | 400 | fix_request | request | one request named several connections |
| `no_vault` | 403 | configure | config | no vault bound to the request |
| `oauth_mint` | 502 | retry | upstream | token mint failed at the provider |
| `phantom_plain_http` | 400 | fix_request | request | phantom requires HTTPS |
| `policy_denied` | 403 | none | policy | blocked by an explicit `deny` rule |
| `refresh_forbidden` | 403 | fix_request | policy | refresh tokens never leave the vault |
| `secret_encoding` | 500 | none | internal | resolved credential not valid UTF-8 |
| `store_unavailable` | 502 | retry | upstream | an external secret store (e.g. GCP Secret Manager) failed while resolving; daemon logs have the full error |
| `unknown_connection` | 400 | fix_request | request | phantom names no known connection |
| `upstream_body` | 502 | retry | upstream | request body could not be read |
| `upstream_error` | 502 | retry | upstream | upstream answered but the exchange failed (NOT a credential problem) |

CLI exit codes: 0 ok, 1 error, 2 usage; `sc op wait`: 0 approved, 3 expired
or unknown, 4 timed out waiting, 5 not approved (a person said no, or a stated
cause), 6 ended without a decision (withdrawn by the requester or superseded
by a newer request). `sc doctor` exits non-zero if any check fails.

Op terminal states: the poll body's `status` stays `pending | ok | consumed |
rejected`; a rejected op carries `reason`, and waiters distinguish a USER
rejection from a withdrawal by the requester or a newer request replacing it:
those say so and ask for a re-run, never "rejected".
First-class wire statuses (`cancelled` / `superseded` / `expired`) need the
console's chips to change in the same release: parked as follow-up.

## Blind spots (the broker cannot yell here)

1. **Not in the path**: the process wasn't routed (no `sc run` / env bundle):
   the phantom reaches the upstream literally. Upstreams reject (401) or
   silently degrade; either way there is no SafeClaw marker. The phantom
   string itself (`__sc__*__`) is the greppable brand; the skill's routing
   check covers this.
2. **Locked before ever unlocking (this boot)**: anchor hosts live in the
   sealed blob, so a daemon restarted while locked cannot recognize brokered
   hosts and blind-tunnels them. Once a vault has been unlocked once, its
   anchors are remembered across Lock (`state.last_host_unions`) and a phantom
   sent while locked gets an explicit `vault_locked` instead.

Invariant for new proxy branches: every outcome is either **passthrough**
(not ours) or a **registry-coded error**: no third state, no silent drop.
