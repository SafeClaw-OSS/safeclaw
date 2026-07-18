# Stores and Items — Design Proposal (v3)

**Status**: Proposal — 2026-05-24 (revised post-discussion)
**Builds on**: [SERVICES.md](./SERVICES.md) v2
**Supersedes**: `SOURCE_ABSTRACTION.md` (stub)

This document is the canonical specification for SafeClaw's stores/items
abstraction. The design was converged through a multi-round discussion
under the constraint of **minimum complexity**:

- No top-level item catalog / mapping table.
- Items live inside their owning store; the item name *is* the store key.
- Resolution is **priority-based** across stores (`store_order`).
- Frontend has **one screen** (stores + their items, with optional
  validation check), no per-adapter UI dispatch.
- Adapter contract is minimal: four methods + two constants.

---

## 1. Why this exists

SafeClaw v2 hardcodes the user's SafeClaw vault as the only place a
credential can live. Real users keep credentials in 3–10 places: the
SafeClaw vault (personal), 1Password (company shared), GCP / AWS Secret
Manager (production), etc. Dev branch already has a working file vault
for blob-typed credentials (PEMs, SA JSON) but it's not exposed through
a uniform abstraction.

v3 unifies all of this under two concepts — **Stores** (backends) and
**Items** (named entries inside stores) — so:

- Service authors write `{{X}}` in service.toml without caring where X
  comes from.
- Users compose existing secret stores into a single per-request
  approval plane.
- Files work through the same model.

---

## 2. Conceptual layers

```
┌─────────────────────────────────────────────────────────────┐
│  ① Registry (static, on disk)                               │
│    service.toml files — service definitions, default policy │
├─────────────────────────────────────────────────────────────┤
│  ② Protocol layer (this design)                             │
│    stores       : connected backends, each with its items   │
│    store_order  : resolution priority                       │
├─────────────────────────────────────────────────────────────┤
│  ③ Adapter layer (per store kind)                           │
│    native-secrets / native-files / gcp / aws / 1p / ...     │
├─────────────────────────────────────────────────────────────┤
│  ④ Persistence (vault.enc + files/<uuid>.enc + index.json)  │
└─────────────────────────────────────────────────────────────┘
```

This document scopes ② and ③. service.toml (Registry) and physical
encryption (Persistence) are documented elsewhere.

---

## 3. Naming and concepts

| Term | Meaning |
|------|---------|
| **Vault** | The user's whole encrypted tenant — everything behind the passkey |
| **Store** | A connected backend that holds items (native or external) |
| **Item** | A named entry inside a store. The name is what `{{X}}` templates use |
| **Adapter** | The code implementing a store kind |
| **Kind** | Adapter discriminator (`native-secrets`, `gcp-secret-manager`, ...) |
| **Category** | `value` or `file` — declared by the adapter; fixes item shape |

Two principles to internalize:

1. **The item's name IS its key inside the store.** There is no
   rename / mapping layer. If service.toml writes `{{openai_api_key}}`,
   then somewhere in your store_order there must be a store with an
   item literally named `openai_api_key`.

2. **Resolution is priority-based.** Stores are searched in
   `store_order`; first match wins. Deterministic, auditable, no
   silent failure on store errors.

---

## 4. Store categories

Each adapter declares a category that fixes the shape of items in its
store:

| Category | Item shape (the value of `items[<name>]`) |
|----------|---|
| `value`  | a string — the secret value itself (only stored locally for native-secrets; for external stores, this is absent because data is remote) |
| `file`   | `{ blob_id, size, ... }` — metadata; the bytes live in `files/<blob_id>.enc` |

The category is an **explicit field** in each store's record, not
derived from kind. Adapter declares its category via a constant
(`Adapter::CATEGORY`); schema validates that `stores[<id>].category`
matches `Adapter::CATEGORY` for the given kind.

`config-file` (non-sensitive files) is omitted; no real use case yet.

---

## 5. Resolution algorithm

To resolve item name `X` for a `{{X}}` template (or `{{file:X}}` if
that gets added later):

```
required_category := value | file    // determined by template form

for store_id in store_order:
    store := stores[store_id]
    if store.category != required_category: continue
    
    match adapter(store).resolve(X):
        Ok(Some(bytes)) → return bytes     // found, use it
        Ok(None)        → continue          // not in this store, try next
        Err(e)          → return Err(e)     // store call failed; STOP, surface
return Err(NotFound)
```

Three rules, deliberately rigid:

- **Category filter**: value templates only see value stores; file
  templates only see file stores.
- **First match wins**: deterministic resolution via `store_order`.
- **Errors stop**, "not found" continues. A `429` / `403` / `503` from
  GCP is not "key doesn't exist" — it's a failure to query, surfaced
  to the caller.

There is no silent cross-store fallback on errors. Auditable: the chain
+ store_order tells you exactly which store served any value.

---

## 6. Adapter contract

The complete surface between the broker and any store kind:

```rust
trait Adapter {
    const KIND: &'static str;          // discriminator string
    const CATEGORY: Category;          // Value | File

    /// Validate adapter-specific config fields in stores[<id>].
    fn from_config(cfg: serde_json::Value) -> Result<Self>;

    /// Look up an item by name. Three outcomes:
    ///   Ok(Some(_)) — found, returns bytes
    ///   Ok(None)    — name not present in this store
    ///   Err(_)      — store call failed (network, auth, …)
    fn resolve(&self, name: &str) -> Result<Option<Bytes>>;

    /// Enumerate item names this adapter knows about.
    /// Used by the validation-check UI and the store-browser.
    fn list(&self) -> Result<Vec<String>>;

    /// Sanity check (e.g., credentials still valid).
    fn health(&self) -> Result<()>;
}
```

Everything else is adapter-internal. Adapters decide:

- What fields appear in their `stores[<id>]` config record.
- Where local data lives (e.g., `native-secrets.items`, blob files).
- How they interpret names (e.g., 1P maps `openai_api_key` to a field
  somewhere — adapter's responsibility, not protocol's).

**Sensitive credentials always live as items in `native-secrets`.**
Adapter configs reference them by name (`credentials_item: "_gcp_sa_json"`).
Adapter resolves the referenced item recursively (terminates at
`native-secrets` — the trust root).

---

## 7. Vault schema

```jsonc
// vault.enc — decrypted shape
{
  "version": 3,

  // ─── Protocol layer ──────────────────────────────────────────
  "stores": {
    "native-secrets": {
      "kind": "native-secrets",
      "category": "value",
      "items": {
        "openai_api_key": "sk-...",
        "_gcp_sa_json":   "...",
        "_1p_sa_token":   "ops_..."
      }
    },

    "native-files": {
      "kind": "native-files",
      "category": "file",
      "items": {
        "github_app.pem": { "blob_id": "uuid-1", "size": 1234 }
      }
      // actual blob bytes live in files/<blob_id>.enc
    },

    "prod-gcp": {
      "kind": "gcp-secret-manager",
      "category": "value",
      "project_id": "my-proj",
      "credentials_item": "_gcp_sa_json"
      // no items field — data is remote
    },

    "team-1p": {
      "kind": "1password-sa",
      "category": "value",
      "credentials_item": "_1p_sa_token"
    }
  },

  "store_order": [
    "native-secrets",
    "prod-gcp",
    "team-1p",
    "native-files"
  ],

  // ─── Connections (CONNECTION_SCHEMA.md) — orthogonal to this design ─
  "connecting":  { /* in-flight OAuth handshakes, keyed by connection_id */ },
  "connections": { /* established connections, keyed by connection_id */ },

  // ─── Policy — ONE tree (POLICY.md) ────────────────────────────
  "policy": {
    "timeout": 300,
    "default":    { "read": "allow", "write": "allow" },
    "categories": { "llm": { "read": "allow", "write": "allow" } },
    "connections": {
      // per-CONNECTION user policy, keyed by connection_id; rules sourced
      // from the connection's service recipe, merged with these edits
      "gmail": {
        "default": { "read": "ask" },
        "rules":   { "read-email": { "level": "allow" } }
      }
    }
  },

  // ─── Other vault state (orthogonal — not part of this design) ─
  "audit_retention_days": 30,
  "push_subscriptions":   [ /* web-push endpoints */ ],
  "vapid_private_key":    "..."
}
```

### 7.1 Per-field justification

Every top-level field has a documented reason. No dead fields.

| Field | Source | Disposition | Rationale |
|-------|--------|------------|-----------|
| `version` | new (v3) | required | Schema-version negotiation |
| `stores` | new (this design) | required | Connected backends + their data |
| `store_order` | new (this design) | required | Resolution priority |
| `connecting` | connections layer | sparse | In-flight OAuth handshakes, keyed by `connection_id`. See [CONNECTION_SCHEMA.md](CONNECTION_SCHEMA.md). |
| `connections` | connections layer | sparse | Established connections, keyed by `connection_id`. Status is derived. See [CONNECTION_SCHEMA.md](CONNECTION_SCHEMA.md). |
| `policy` | new (replaces split) | optional | The whole policy tree — `timeout`, the read/write `default` floor, per-`category` floors, and per-`connection` user policy. Rules carry their access `level` directly. Sparse; absent on fresh vaults → daemon uses `Policy::default()`. The canonical reference is [POLICY.md](POLICY.md). **Replaces the old split `service_state` + `policy_defaults`.** |
| `audit_retention_days` | new | optional | Audit-log retention in days. `None` = keep forever. |
| `push_subscriptions` | dev's `notifications.subscriptions` (flattened) | required | Per-user web-push endpoints; sensitive (deanonymizing). Renamed because dev's two-level nesting (`notifications.subscriptions`) carried no information. |
| `vapid_private_key` | dev (unchanged) | required | Server-side push signing key |

The `policy` tree (rust: `core::policy::Policy`) is sparse and self-defaulting at
every layer:

- `timeout` — approval hold, seconds.
- `default` — global read/write floor (`Levels { read?, write?, ttl? }`) when no
  rule and no more-specific default matches. Values are access **decisions**
  (`allow | ask | ask-always | deny`). The read/write split is the method-derived
  base (`is_write_method`). See [POLICY.md](POLICY.md).
- `categories` — per-category floor (e.g. `llm`, `channel`); beats `default`.
- `connections.<connection_id>` — per-**connection** user policy
  (`ConnectionPolicy { default?, rules }`). The built-in rule set comes from the
  connection's *service* recipe (`policy.toml`); `rules` is a sparse map keyed by
  rule id where each `RuleConfig { match?, label?, body?, level?, ttl? }` either
  **overrides** a built-in rule by id (set `level`/`ttl`), or (if it carries
  `match`) **adds** a new rule. Connections are addressed by `connection_id`, NOT
  per-service — see [CONNECTION_SCHEMA.md](CONNECTION_SCHEMA.md).

### 7.2 What's removed from v2/dev

| v2/dev field | Replaced by |
|----------|-------------|
| Top-level service-defined keys (`wallet`, `gatewayToken`, ...) | items in `native-secrets.items` |
| `files: [{id, name, size}]` | `native-files.items` |
| `services.X.upstream` / `services.X.auth` (registry shadow) | Read live from service.toml at runtime |
| `service_state` (per-service policy overrides) | folded into `policy.connections.<connection_id>` (per-connection, not per-service) |
| `policy_defaults` (global preferences) | folded into the top-level `policy` tree (`timeout` / `default` / `categories`) |
| per-rule `ask_ttl`; the interim `risk` tier + per-vault `risk`→level map | rules carry their access `level` directly; the cache TTL field is `ttl` |

---

## 8. Invariants

Enforced by the vault-write code path. Not visible at the schema level.

| Invariant | Why |
|-----------|-----|
| For every `store_id` in `store_order`: `stores[store_id]` exists | Order must reference real stores |
| Every entry in `stores` has its ID appear in `store_order` exactly once | Order is a permutation, not a subset |
| `stores[<id>].category` matches `Adapter::CATEGORY` for `kind` | Adapter precondition |
| `from_config` accepts the store's adapter-specific fields | Store must be usable |
| For `kind = "native-files"`: every `items[<name>].blob_id` corresponds to an existing `files/<blob_id>.enc` | Catalog ↔ blob consistency |
| Reserved store IDs (`native-secrets`, `native-files`) cannot be user-renamed | Built-in stores are stable references |

### 8.1 On atomicity

vault.enc is **one** file. Every update reads-decrypts-modifies-encrypts-
writes the whole file as one operation. A logical change touching
multiple fields is one atomic disk write. There is no partial-update
window and no cross-section consistency hazard.

---

## 9. Service.toml — v3 changes

### 9.1 Removals

| v2 | v3 |
|----|-----|
| `auth = { type = "bearer", env = "X" }` | Removed. Use `[upstream.headers] Authorization = "Bearer {{X}}"` |
| `auth = { type = "header", header = "X-Key", env = "X" }` | Removed. Use `[upstream.headers] X-Key = "{{X}}"` |
| `auth = { type = "query", param = "key", env = "X" }` | Removed. Use `[upstream.query] key = "{{X}}"` |
| `auth = { type = "path", env = "X" }` | Removed. URL with `:placeholder` + `[upstream.path_params]` |
| `auth = { type = "basic", env = "X" }` | Removed. Use `[upstream.headers] Authorization = "Basic {{b64:X}}"` |
| `[[vault]]` schema declarations | Removed. Required items are derived from template scan; optional `[items]` block provides descriptions |
| `{{env.X}}` / `{{service.vault.X}}` template prefixes | Removed. Just `{{X}}` |

### 9.2 Kept / repurposed

```toml
[[upstream]]
id  = "default"
url = "https://api.openai.com"           # Clean base URL — no auth in the URL

[upstream.headers]                         # Headers injected on every forward
Authorization = "Bearer {{openai_api_key}}"

[upstream.query]                           # Query params auto-attached
api_key = "{{some_service_key}}"

[upstream.path_params]                     # URL `:name` placeholder substitution
bot_token = "{{telegram_bot_token}}"
# Used with url = "https://api.telegram.org/:bot_token"

[upstream.locked]                          # Existing — unchanged
response = "Please unlock the SafeClaw vault to use this service."

[upstream.auth]                            # Reserved for stateful auth
provider = "oauth2"                        # currently the only supported value
# Other providers (aws-sigv4 / hmac-sha256 / …) reserved for the future.
```

### 9.3 Semantics

- **Replace-all-matching**: for each name set by upstream config, broker
  first removes all matching entries from the agent's request, then
  writes the broker's value. Auth cannot be polluted by the agent.
- URL `:placeholder` substitution happens before forwarding; only
  declared `path_params` are substituted. Undeclared placeholders error.
- `[upstream.auth]` exists only when complex auth (OAuth2, future
  SigV4 / HMAC) is needed. Service.toml without it is valid and common.

### 9.4 Optional `[items]` block

Pure UI hint for the connect-service flow. Required items are derived
from scanning `{{X}}` template occurrences across service.toml.

```toml
[items]
openai_api_key = "Your OpenAI API key from platform.openai.com"
github_app_pem = "GitHub App private key (PEM file)"
```

---

## 10. Templates

| Form | Resolves to | Errors when |
|------|-------------|-------------|
| `{{X}}` | item X's string value (resolved across value stores per §5) | X has file category; no store provides X |
| `{{b64:X}}` | item X's value, base64-encoded | X has file category; no store provides X |
| `{{file:X}}` | (reserved) | not in v3.0 — see §13 |

---

## 11. Physical layout

### 11.1 On-disk

Unchanged from dev. v3 only changes the logical shape inside `vault.enc`.

| File | Format | Sensitivity |
|------|--------|-------------|
| `vault.enc` (= `vault.dat`) | sudp `SealedState` JSON — outer envelope holds `{ version, registry, credentials, ciphertext }`; `ciphertext` decrypts to a sudp `ProtectedState` (see §11.2) | encrypted under DEK `K` |
| `files/<uuid>.enc` | `iv ‖ ct ‖ tag` AES-256-GCM, plaintext = file bytes | encrypted under same DEK |
| `index.json` | unencrypted metadata cache (store list, item names, file sizes — no values) | UI offline display |

Same-DEK / separate-blob pattern stays. Adding a value item only
rewrites vault.enc (small). Adding a file writes one new
`files/<uuid>.enc` and updates vault.enc. A 5MB PDF does not force
re-encrypting the whole vault.

**One vault.enc** (not multiple). Splitting per-store would buy nothing
(same DEK; no security benefit) and would cost cross-file atomicity.

### 11.2 Inside the ciphertext — Design B split

The §7 schema is the *logical* view. Physically, the decrypted
`ProtectedState M = { targets, peers, aux }` splits the v3 schema across
two of sudp's three fields:

| sudp field | What we put there | Why |
|------------|-------------------|-----|
| `M.targets` | `native-secrets` item bytes, keyed by bare item name | sudp's `TargetValue` zero-on-drop + b64-binary-safe encoding gives byte-safe storage for the only store kind that holds authoritative bytes locally |
| `M.aux` | `{ version, stores, store_order, policy, connecting, connections, … }` + every other store's items metadata (no native-secrets items here — they're in targets) | sudp's "deployment-specific auxiliary state, out-of-scope of the protocol" slot |
| `M.peers` | (sudp-internal credential rewrap map — untouched by v3) | structural |

Runtime code goes through `storage::plaintext::VaultPlaintextView` which
merges the two pools so callers query items by name through the
store_order without caring about layout. The §7 example is what you'd
see after the merge.

---

## 12. UI surfaces

### 12.1 Vault detail page — primary screen

One screen. Three sections:

**Stores list** (with drag-to-reorder for `store_order`):

```
[≡] native-secrets       (3 items)        [browse]
[≡] prod-gcp             (12 remote items) [browse]
[≡] team-1p              (8 remote items)  [browse]
[≡] native-files         (1 file)          [browse]
                                              [+ Connect store]
```

**Store browser** (per-store, shown on click):

- For `native-secrets`: CRUD on local items (add / edit value / delete)
- For `native-files`: file picker for upload, list of uploaded files,
  download / delete
- For external (gcp / aws / 1p): **read-only** list of items in that
  remote; "Open in [GCP / AWS / 1P] console" link for editing upstream

**Validation check** (read-only, auto-derived):

```
Items required by enabled services:
  openai_api_key      ← native-secrets        (active)
                      ← prod-gcp              (shadowed)
  github_token        ← prod-gcp              (active)
  github_app_pem      ← native-files          (active)
  stripe_secret       ⚠ UNRESOLVED
```

User fixes UNRESOLVED by adding the name to some store, or by
reordering `store_order` to bring the right store forward.

### 12.2 Connect store dialog

Per adapter kind, a specific config form (paste GCP SA JSON, paste 1P
SA token, ...). Validates by calling `health()` before saving. New
store appended to `store_order` at the bottom (user can drag up).

### 12.3 No item-level binding UI

There is no "where does item X live" form. Items belong to whichever
store they were created in. To move an item, user creates it in the
new store and deletes from the old.

---

## 13. Out of scope (v3.0)

- **`{{file:X}}` template form**. Files materialize to a tmpfs path
  when passed to local exec steps. Template syntax is deferred until
  that materialization path is built.
- **OAuth2 generalization**. Tokens have refresh cycles — different
  from static items. OAuth subsystem stays separate; templates
  reference OAuth-managed entries via the same `{{X}}` syntax.
- **Cross-store policy** ("auto-approve OpenAI ≤10/hr, always ask
  Stripe"). Belongs in the policy DSL.
- **Adapter-side writes**. SafeClaw reads from external stores. Writes
  go through each provider's own UI (deeplink from the store browser).
- **Caching**. Every resolve hits the store. External adds 50–300ms;
  acceptable for pre-launch volumes.

---

## 14. Migration from v2

Pre-launch — no user data to migrate. In-tree service definitions
migrate mechanically:

1. **Remove `[[vault]]` blocks** from every service.toml.
2. **Rewrite `auth = {...}`** into `[upstream.headers]` / `.query` /
   `.path_params` templates per §9.2.
3. **OAuth2 services** keep their auth as `[upstream.auth] provider = "oauth2"`.
4. **Existing dev's top-level vault keys** (`wallet`, `gatewayToken`, ...)
   become items in `native-secrets.items`. Service-author convention:
   prefix with the service id (`nodpay_wallet_safe` etc.) for clarity.
5. **Existing dev's `files: []` entries** become entries in
   `native-files.items`, preserving the UUID as `blob_id`.

Protocol version bump: `health.version` increments. Frontend gates
compat via the version handshake.

---

## 15. Adapter catalog (v3.0)

### 15.1 `native-secrets` (built-in; reserved ID `native-secrets`)

- **`KIND`** = `"native-secrets"`, **`CATEGORY`** = `Value`
- **Config**: no fields beyond `kind` + `category`.
- **Data**: `stores["native-secrets"].items: { name → string }`.
- **`resolve(name)`**: returns `items[name]` as bytes, or `Ok(None)`.

### 15.2 `native-files` (built-in; reserved ID `native-files`)

- **`KIND`** = `"native-files"`, **`CATEGORY`** = `File`
- **Config**: no fields beyond `kind` + `category`.
- **Data**: `stores["native-files"].items: { name → { blob_id, size } }`.
  Bytes live in `files/<blob_id>.enc`.
- **`resolve(name)`**: looks up `blob_id` from items; decrypts
  `files/<blob_id>.enc`; returns bytes.

### 15.3 `gcp-secret-manager` (category = value)

- **Config**:
  ```jsonc
  { "kind": "gcp-secret-manager",
    "category": "value",
    "project_id": "<gcp-project>",
    "credentials_item": "<native-secrets item name holding SA JSON>" }
  ```
- **`resolve(name)`**: GCP SDK `accessSecretVersion(project_id, name, "latest")`.
- **IAM**: per-secret `roles/secretmanager.secretAccessor` recommended
  for item-level scoping.

### 15.4 `1password-sa` (category = value, adapter deferred)

- **Config**: `{ kind, category, credentials_item }`
- **`resolve(name)`**: searches the SA-bound 1P vault for an item with
  a field matching `name`. Exact match semantics — no fuzzy lookup.
- **Vault scoping**: user creates a dedicated 1P vault (e.g.,
  `SafeClaw-Agent`) and binds the SA to only that vault.

### 15.5 `aws-secrets-manager` (category = value, adapter deferred)

- **Config**: `{ kind, category, region, credentials_item }`
- **`resolve(name)`**: AWS SDK `GetSecretValue(SecretId=name)`.

---

## 16. Security considerations

- **Trust root**: SafeClaw vault remains the trust root. All external-
  store credentials are items in `native-secrets`, encrypted under the
  user's passkey. An attacker with the encrypted vault file cannot
  decrypt store credentials without the passkey.
- **Credential chain termination**: every `credentials_item` reference
  ultimately resolves through `native-secrets`. There is no path to a
  non-native store credential without first unlocking the vault.
- **Per-request approval preserved**: stores/items change the
  *physical fetch path* only. The passkey-signed approval at the moment
  of action is unchanged.
- **Network surface**: connecting an external store means SafeClaw makes
  outbound calls to that provider on every relevant broker request —
  observable to the provider. Document in the Connect-store dialog.
- **Source-side audit**: external stores have their own audit logs;
  cross-correlation is possible. Note for security-aware users.

---

## 17. Open questions

Things I decided but flagged for re-review:

1. ~~**`service_state` naming**~~ — RESOLVED. `service_state` is gone; per-user
   policy now lives in the `policy` tree, keyed per-**connection**
   (`policy.connections.<connection_id>`), not per-service.
2. **Default `store_order` for new vaults** — proposal:
   `[native-secrets, native-files]`. External stores appended at the
   bottom on connect. Reasonable?
3. **`vapid_private_key` location** — currently inside vault.enc;
   technically server identity, not user data. Could move to a separate
   sealed file alongside `sc_sk.jwk`. Defer until next crypto refactor.
4. **Validation-check refresh strategy** — re-run on vault open, on
   service add/remove, on store config change. Aggressive enough? Too
   aggressive (rate-limit external `list()` calls)?

---

## 18. Glossary

| Term | Meaning |
|------|---------|
| Vault | The user's whole encrypted tenant (passkey-protected) |
| Store | A backend holding items (native or external) |
| Item | A named entry inside a store; addressed by `{{X}}` templates |
| Adapter | Code implementing a store kind |
| Kind | Adapter discriminator (`native-secrets`, `gcp-secret-manager`, ...) |
| Category | `value` or `file` — fixes item shape; declared by adapter |
| Native | A store whose backing is SafeClaw's own storage (`native-*`) |
| `store_order` | Priority list determining resolution order across stores |

---

## 19. Related

- [`SERVICES.md`](./SERVICES.md) — service.toml v3 schema; uses items
  via `{{X}}` templates per §10
- [`PROTOCOL.md`](./PROTOCOL.md) — wire protocol; §5.2 references this
  doc as canonical for M (vault plaintext) content; `/c/registry`
  `required_items` is derived from template scan
