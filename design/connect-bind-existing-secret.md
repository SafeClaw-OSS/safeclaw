# Bind a connection to a secret already in the vault

> Status: BUILT (core release/v1, CLI + daemon); console oauth-branch picker
> (§3) is a follow-up. Canon for the shapes involved =
> [connection-schema.md](connection-schema.md) §3/§4.
>
> Decisions after the request (supersede the text below where they differ):
> the flags are `--from-literal` / `--from-secret` (§1, breaking, no
> aliases); an agent MAY propose a binding, which takes effect only on the
> owner's passkey approval of a card listing every bound key and host
> (§4, Non-goals).

## The gap

A service-backed connection can only be created by WRITING new secret values.
Nothing can point one at a secret the vault already holds.

For an oauth2 service that means a refresh token you already have is unusable.
The only two ways to connect are:

1. re-run the provider's consent flow, which needs the account's login
   credentials, not just its token; or
2. reveal the stored secret through the passkey ceremony and deposit a second
   copy under a new key.

(2) is worse than untidy. The daemon persists a rotated refresh token back to
the BOUND key only (`persist_rotated_refresh_locked`), so after the first
rotation the original key holds a value nothing maintains. Two keys, one live.

Motivating case: six ChatGPT accounts whose refresh tokens are already in the
vault as `HEJIA_OAI_REFRESH_TOKEN_<ACCT>`. Connecting them to `openai_codex`
today costs six browser logins to accounts whose passwords may not be at hand,
or six duplicate copies plus six reveals.

## Why this is a surface gap

Everything below the CLI and the console already supports it:

- `storage/plaintext.rs:196` `secret_key_for()`: the connection record's
  `keys[ROLE]` entry wins over the identity binding. The address is stored
  data, not a computed convention.
- `service/mod.rs:67` `mint_input_role()`: an oauth2 service's mint input is
  whatever `[auth].refresh_token` names, resolved through that same
  `secret_key_for`.
- `server/handlers/approve.rs`, `connection-add` SERVICE branch: stores `keys`
  verbatim, and a connection with no deposited values is already legal
  (`values` is `Option`, absent on a pure reference).
- `components/saas-vault/connections-tab.tsx:131`: `onCreateConnection`'s
  signature already carries a `keys` map.

It was blocked in four places: the CLI refused a reference together with
`--service`, dropped references on the service path, and built `keys` only
from newly written values; the console's oauth branch renders only the
consent flow, so an oauth service has no reuse entry point (still open, §3).

## Ask

### 1. CLI, the unblocking piece

One concept, one word, kubectl-aligned: the flag names the SOURCE of a slot.
Two parallel flags of identical shape replace `--secret` and
`--use-existing` (breaking, no aliases):

- `--from-literal SLOT=VALUE` writes a new secret value (the value rides the
  local deposit; the op carries only its salted digest). A bare
  `--from-literal SLOT` prompts for the value with hidden input on a TTY.
- `--from-secret SLOT=KEY` uses a secret already in the vault; no plaintext
  anywhere. Emits `scope.secrets += KEY` and, on a service, `scope.keys[ROLE]
  = KEY`.

SLOT semantics:

- With `--service`, SLOT is one of the service's declared `secrets` roles,
  matched case-insensitively, with the same error text shape as before
  (`secret 'X' is not declared by service 'S' (its secrets: …)`). The
  `SLOT=KEY` form is required for `--from-secret`; a bare `--from-secret KEY`
  errors and says why (a key name does not say which slot it fills). No
  special case for single-secret services: the shape of a command does not
  change with the service's arity.
- For a raw connection SLOT is the vault KEY itself, so `--from-secret KEY`
  is the short form (`SLOT=KEY` is accepted only when SLOT equals KEY).
- KEY passes through as typed. Native keys fold to their stored uppercase
  form at approve, external-store keys are matched exactly.
- A slot named by both flags is an error.
- Every role of a service must be filled. A role named by neither flag is
  prompted for (hidden) on a TTY; off a TTY the command errors, listing the
  missing roles and both ways to fill them. A pure-reference service
  connection therefore never hits a "no secrets given" refusal.
- Before asking for approval the CLI prints the proposal: each slot, its
  KEY, new value or existing secret.

### 2. Daemon

The SERVICE branch now verifies every slot's KEY exactly like the RAW branch:
written here (deposited) or present across the full `store_order`, so a
mistyped KEY fails loudly at approve instead of surfacing later as a
connection whose phantom never resolves. Every declared role is a slot (its
`keys` entry, else the identity binding), so the record never binds a key the
approval did not show. Referenced keys are recorded in canonical form.

### 3. Console, follow-up

In `ConfigureConnect`'s oauth branch, offer "use a refresh token already in
this vault": a picker over `reachableKeys`, routed through the existing
`onCreateConnection(..., keys)` path instead of the consent flow. One passkey
gesture, same as today.

### 4. The approval card is signed

An agent may propose a connection, so the approval must show exactly what
the write does. At op creation the daemon computes the card from its unlocked
session state and stamps it into the signed scope, overwriting any
requester-supplied values of these fields:

- `written` / `referenced`: slot → KEY, split by whether this approval writes
  the value or binds an existing secret;
- `overwrites`: written KEYs that already hold a value;
- `destinations`: every host the bound credentials, or tokens minted from
  them, are sent to (the connection's hosts plus a minted mechanism's token
  endpoint, e.g. an oauth2 `token_url` host);
- `shared_with`: KEY → other existing connections already bound to it;
- `replaces`: an existing connection with this id is replaced.

Apply recomputes the card from the opened vault and refuses on any
difference (the vault changed between request and approval: re-run). The
create response returns the op as stored, so a local signer signs exactly
what the daemon holds. The console renders the consequence line from these
fields only.

## Decisions this forces

**Disconnect must not delete a bound key.** (OPEN: not built yet; today
`sc connection rm` keeps only keys another connection still references.) The
drawer sweeps a connection's
secret addresses on disconnect. A key that was BOUND rather than WRITTEN may
back other connections or predate the connection entirely, so sweeping it is
destructive. Record the distinction (the raw path's `secretKeys` superset,
`connections-tab.tsx:129`, already models half of it) and delete only what this
connection wrote.

**Rotation writes back to the bound key, and that is the point.** It is why
binding beats copying: one key stays live no matter how many connections read
it. Verified against OpenAI that its rotation is non-invalidating (refreshing
with a pre-rotation token still returns 200), so a key shared with other
devices does not knock them offline. Do not generalize that to every provider;
it is a property of the provider, not of this feature.

**Two connections may bind the same key.** Legal, each mints its own access
token, and the rotation write-back is already single-flighted on the per-vault
write lock.

## Non-goals

- Connecting a per-vault custom service from the CLI (`cli/connect.rs:434`).
  Different problem: the CLI's service table is compiled in and resolved
  offline, so it cannot see `aux.services`.
- Any new grant type, and any request-body injection template.
- Letting an agent APPLY a binding. An agent may propose one through the CLI
  (the decision above reverses the original non-goal); it takes effect only
  after the owner's passkey approval of the signed card (§4).

## Acceptance

1. `sc connection add codex_x --service openai_codex --from-secret
   OPENAI_CODEX_REFRESH_TOKEN=HEJIA_OAI_REFRESH_TOKEN_X` takes one approval and
   writes `aux.connections.codex_x = {service: "openai_codex", keys: {...}}`
   with no new secret in the vault. The card shows the key as referenced,
   `chatgpt.com, api.openai.com, auth.openai.com` as destinations, and any
   other connection bound to the key.
2. A request through `sc run` carrying `__sc__codex_x__` in an Authorization
   header toward `chatgpt.com` receives a minted access token.
3. After a rotation, the new refresh token lands in
   `HEJIA_OAI_REFRESH_TOKEN_X`. No second key appears.
4. Disconnecting `codex_x` leaves `HEJIA_OAI_REFRESH_TOKEN_X` in the vault.
5. A KEY that does not exist is refused with the "no such secret" error, not
   at first use: at request time when the vault has no external store that
   could hold it, else at approve.
