# Diagnostics — error codes & surfaces

Doctrine: **every problem SafeClaw can see fails loudly, in SafeClaw's name;
success is silent.** An error that carries no SafeClaw marker is not
SafeClaw's — with two physical blind spots the broker cannot see (below).

`src/error.rs::ScCode` is the single registry; this table is its rendering and
changes in the same commit. Codes are snake_case and stable — never renumber
or reuse.

## Wire shapes (one row, three renderings)

| Surface | Shape |
|---|---|
| Control port :23293 + API face :23294 | RFC 9457 `application/problem+json`: `type` (`https://safeclaw.pro/errors/<code>`), `title`, `status`, `detail` + extensions `code`, `action`, `cause`. Legacy `error`/`message` dual-emitted for one transition window. |
| Proxy MITM plane :23294 | `text/plain` (deliberately never parseable as the upstream's payload), body first line `SafeClaw: <code>: <message>`, header `x-safeclaw-error: <code>`. Captive bodies (approval / widen) keep their text+JSON-tail format and carry the code header. |
| CLI stderr | `<code>: <message>` (`cli/apierr.rs`), same code the wire carried. |

`action` = what the agent does next: `unlock` (have the user unlock), `approve`
(follow the approve URL in the body), `retry`, `configure` (a knob, named in
the message), `fix_request`, `none` (explicit refusal — don't work around it).
`cause` = attribution: `request`/`auth`/`vault`/`policy`/`config`/`internal`,
plus `environment` and `upstream` which are NOT SafeClaw problems — reported by
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
| `rate_limited` | 429 | retry | request | slow down |
| `internal` | 500 | retry | internal | daemon bug/failure |
| `ca_unavailable` | 500 | retry | internal | resident CA unreadable |
| `agent_key` | 407 | configure | auth | phantom-bearing request without a valid agent api key |
| `ambiguous_phantom` | 400 | fix_request | request | bare phantom on a multi-secret connection; use a role phantom |
| `approval_needed` | 401 | approve | policy | policy asks; body carries approve/poll URLs + op id |
| `approval_register` | 503 | retry | internal | could not open the approval op |
| `broker_body_limit` | 413 | configure | config | body exceeds the inspectable cap; raise `--body-cap` if legitimate |
| `egress_unreachable` | 502 | configure | environment | forward hop failed to connect (NOT a credential problem) |
| `exposes_unsupported` | 400 | fix_request | request | role not mintable yet |
| `host_forbidden` | 403 | none | policy | destination fails the private/metadata egress floor |
| `host_not_anchored` | 403 | approve | policy | connection not anchored to this host; body carries a one-tap widen |
| `multi_connection` | 400 | fix_request | request | one request named several connections |
| `no_vault` | 403 | configure | config | no vault bound to the request |
| `oauth_mint` | 502 | retry | upstream | token mint failed at the provider |
| `phantom_plain_http` | 400 | fix_request | request | phantom requires HTTPS |
| `policy_denied` | 403 | none | policy | explicit policy deny |
| `refresh_forbidden` | 403 | fix_request | policy | refresh tokens never leave the vault |
| `secret_encoding` | 500 | none | internal | resolved credential not valid UTF-8 |
| `unknown_connection` | 400 | fix_request | request | phantom names no known connection |
| `upstream_body` | 502 | retry | upstream | request body could not be read |
| `upstream_error` | 502 | retry | upstream | upstream answered but the exchange failed (NOT a credential problem) |

CLI exit codes: 0 ok, 1 error, 2 usage; `sc op wait`: 0 approved, 3 timeout,
4 op error, 5 rejected. `sc doctor` exits non-zero if any check fails.

## Blind spots (the broker cannot yell here)

1. **Not in the path** — the process wasn't routed (no `sc run` / env bundle):
   the phantom reaches the upstream literally. Upstreams reject (401) or
   silently degrade; either way there is no SafeClaw marker. The phantom
   string itself (`__sc__*__`) is the greppable brand; the skill's routing
   check covers this.
2. **Locked before ever unlocking (this boot)** — anchor hosts live in the
   sealed blob, so a daemon restarted while locked cannot recognize brokered
   hosts and blind-tunnels them. Once a vault has been unlocked once, its
   anchors are remembered across Lock (`state.last_host_unions`) and a phantom
   sent while locked gets an explicit `vault_locked` instead.

Invariant for new proxy branches: every outcome is either **passthrough**
(not ours) or a **registry-coded error** — no third state, no silent drop.
