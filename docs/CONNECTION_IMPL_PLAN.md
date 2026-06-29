# Connection Layer — Implementation Plan

> Build checklist for the FULL connection layer in one pass. Spec =
> [CONNECTION_SCHEMA.md](CONNECTION_SCHEMA.md) (read first). Delete this file once
> landed. **No migration — landing = wipe vault + recreate + re-test.**

## Decision points (settle before coding)

- **DP1 ⭐ same-provider naming.** gmail / gdrive / gcalendar share Google with
  separate scoped tokens; as *default* (unprefixed) connections their mainstream
  secret names must not collide. **Lean:** service-distinct names
  (`GMAIL_REFRESH_TOKEN`, `GOOGLE_DRIVE_REFRESH_TOKEN`,
  `GOOGLE_CALENDAR_REFRESH_TOKEN`) + a validator check that shipped recipes'
  default secret names are unique. *Alt:* always-prefix (loses bare 1:1) / one
  unified `google` connection.
- **DP2 config-slot syntax.** Proposed `url = "https://{{connection.host}}"` +
  `[upstream.connection].params = ["host"]`. Confirm or adjust.
- **DP3 default connection.** Connect-without-naming → `connection_id ==
  service_id`. Keep.
- **DP4 redirect_uri** → provider config (`google.toml`), out of the handshake.
  Decided.
- **DP5 UI** — "+ add connection" → user types a handle (slug) → multiple
  connections per service.
- **DP6 recipe field name** — keep `secret = "<MAINSTREAM>"` (value is the role)
  or rename `secret` → `credential`. Minor.
- **DP7 reconnect** of a Connected service — transient overlap (entry in
  `connecting` while old one stays in `connections`); keep the old secret serving
  until the new one lands, then replace.
- **DP8 landing** — delete the live vault, re-enroll, re-test. No compat.

## Daemon (wt-connect-daemon)

- [ ] `storage/plaintext.rs` — replace minimal `connections{oauth_pending}` with
  TWO maps: `connecting {id → {service, config, code, verifier}}` +
  `connections {id → {service, config}}`. Drop `OAuthPending`-in-record.
- [ ] `auth/connect.rs` — read `aux.connecting`; exchange (code + verifier +
  provider.redirect_uri); write secret `[<id>:]<ROLE>`; **MOVE** entry
  connecting→connections; **delete the legacy flat `*_oauth_pending` read path
  entirely** (no dual-read). Rewrite tests.
- [ ] secret addressing `[<conn_id>:]<MAINSTREAM>` (default = no prefix) —
  `server/broker.rs` (resolve_auth_value / secret lookup) + `proxy/use_broker.rs`
  + `proxy/stream.rs`.
- [ ] **route by connection_id** (invasive hot-path) — `server/mod.rs` routes
  `/use/{conn}` `/stream/{conn}`; resolve `conn → connections[conn].service →
  recipe`; cache key `(vault, connection_id)` in `state.rs`; op-scope + audit by
  conn_id. Trace the whole chain first.
- [ ] `{{connection.host}}` template + `[upstream.connection].params` — parse in
  `service/mod.rs`, render in `server/broker.rs`.
- [ ] provider `redirect_uri` — `service/mod.rs` ProviderDef; connect.rs uses it.
- [ ] `service/validate.rs` — DP1 default-name uniqueness; only-declared-params
  fillable.
- [ ] registry `connect` descriptor (`server/handlers/registry.rs`) — expose
  `redirect_uri` so the frontend builds the consent URL from it.

## Recipes (wt-connect-daemon/services)

- [ ] all `secret =` → mainstream ALL-CAPS (gmail/gdrive/gcal per DP1;
  `GITHUB_TOKEN`, `GITLAB_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, …).
  Strict community naming, don't invent.
- [ ] gitlab self-hosted: `{{connection.host}}` + `[upstream.connection].params
  = ["host"]`.
- [ ] `_providers/google.toml`: add `redirect_uri`.

## Frontend (wt-connect-frontend)

- [ ] `lib/vault-grant.ts` — VaultAux `connections{oauth_pending}` → `connecting`
  + `connections` (shapes per doc); add `Connecting` type.
- [ ] `lib/oauth-connect.ts` — pending payload `{code, verifier}`; read
  `redirect_uri` from the descriptor for the consent URL.
- [ ] `vault-wizard.tsx` + `saas-vault.tsx` + `tab-connections.tsx` — seal into
  `aux.connecting[id] = {service, config, code, verifier}`; status from
  connecting/connections; disconnect removes connection + its namespaced secret.
- [ ] multi-connection UI ("+ add connection", name a handle, N rows per
  service) — DP5.
- [ ] show mainstream secret names.

## Verify

- [ ] daemon `cargo test --lib` green; recipes pass validator.
- [ ] frontend `tsc --noEmit` + `next build` green.
- [ ] bump version, tag release, redeploy local; wipe + recreate vault; e2e the
  default gmail connection AND a second named connection.
