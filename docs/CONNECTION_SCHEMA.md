# Connection Data Schema

> **What this is.** THE concrete data-schema reference for *connections* — the
> exact shapes that live in a vault and how secrets, status, and routing derive
> from them. Companion to [CONNECTIONS_AND_AUTH.md](CONNECTIONS_AND_AUTH.md)
> (which covers the lifecycle + rationale); this doc is the schema of record.
>
> **Status.** Everything below is **DECIDED** except §4 (recipe *defines* vs
> *suggests* the secret keys), which is **OPEN** — pros/cons laid out for a call.
>
> **Pre-launch, so: no migration.** When this lands it *replaces* the shipped
> minimal shape (v1.0.20, see §8). There is **no back-compat path and no
> dual-read**. Landing procedure = **wipe the vault, recreate it, re-test.**

---

## 1. Where the data lives

A vault's decrypted body is a `ProtectedState { targets, peers, aux }`, sealed
under the per-vault key `K` (ciphertext at rest *and* in the cloud blob — the
cloud never sees any of this in clear).

- **`aux.connections`** — the structured per-connection records (this doc's §2).
- **`targets`** — the flat secret map; connection secrets live here under
  namespaced keys (§3).

Both pools are inside the same sealed body, so a connection record and its
secrets have identical confidentiality.

---

## 2. The connection record

```jsonc
"aux": {
  "connections": {
    "<connection_id>": {
      "service":      "<service_id>",        // the recipe (TYPE) this instantiates
      "oauth_pending": {                     // transient — present only mid-connect
        "code":         "<authorization code>",
        "verifier":     "<PKCE code_verifier>",
        "redirect_uri": "http://127.0.0.1:8765/safeclaw/oauth/callback"
      },
      "params": {                            // OPTIONAL — only recipe-declared re-map slots (§6)
        "<declared_param>": "<value>"
      }
    }
  }
}
```

| field | who sets it | notes |
|---|---|---|
| **`<connection_id>`** (the map key) | user | The connection's **handle** *and* its identity. A slug `^[a-z0-9][a-z0-9_-]{0,63}$`. Flows through routes / cache / op-scope / audit. |
| **`service`** | user (at create) | The recipe/type this is an instance of. **Decouples id from type** → a vault can hold many connections of one service. |
| **`oauth_pending`** | browser (connect), daemon clears it | The cloud-blind handshake relayed through the sealed vault; the daemon exchanges it, then deletes it. Transient. |
| **`params`** | user, **only** for slots the recipe marked per-connection | Non-secret re-map values (e.g. a self-hosted `host`). Anti-SSRF: see §6. |

### Why `connection_id` is *also* the display name (no separate `label`)

An earlier draft had both `"gmail-work"` (id) and `"label": "Work"`. That's the
**same semantic stored twice** — drop one. We keep the **id as the handle**: the
user names the connection, it slugifies to the id, and that string is what shows
in the UI *and* what addresses it (`/use/gmail-work`). One field, one source of
truth.

- Trade-off (accepted): **renaming a connection = a new id** = re-keying its
  secrets. Fine pre-launch; if rename-without-rekey ever matters, that's the
  moment to add an opaque id + mutable label — not before.

---

## 3. Secrets — uniform `<connection_id>:<secret_key>`

Every connection secret is stored in `targets` under:

```
<connection_id>:<secret_key>
```

- **Delimiter `:`** — invalid in env-var names, so a namespaced secret key can
  never masquerade as an env var the agent might pick up.
- **Uniform. No "default connection" special case, no flat `<svc>_refresh_token`
  legacy name, no migration.** Every connection — including the first/only one —
  uses the namespaced form.

```jsonc
"targets": {
  "gmail:refresh_token":      "<bytes>",
  "gmail-work:refresh_token": "<bytes>",
  "acme-gitlab:token":        "<bytes>"
}
```

### Status is DERIVED, never stored

There is no `status` field on a connection (nothing to drift out of sync):

| condition | status |
|---|---|
| `aux.connections[id].oauth_pending` present | **Connecting** |
| all of the recipe's required `<id>:<secret_key>` present | **Connected** |
| some required keys present, some missing | **Partly configured** |
| none present, no pending | **Not configured** |

"Connected" wins over a lingering pending — the durable secret is the source of
truth, so a row never sticks on "Connecting".

---

## 4. ⚖️ OPEN DECISION — does the recipe **define** or **suggest** `<secret_key>`?

The namespace half (`<connection_id>:`) is owned by the connection. The question
is who owns the **`<secret_key>`** half — i.e. **does the connection have the
right to define its own secret-key names, or are they fixed by the recipe?**

(Note: this is *only* about secret keys. The non-secret re-map **params** in §6
are recipe-declared either way — that part is decided.)

### Option A — **DEFINE** (recipe fixes the secret keys; connection cannot deviate)

The `service.toml` declares the exact secret keys/roles it reads (e.g.
`refresh_token`, or `token`). A connection of that type has *exactly* those
keys; it can't add or rename. The daemon validates a connection's secrets
against the recipe's declared set.

| | |
|---|---|
| **Pro — audit** | The complete secret-key set of any connection is knowable from the recipe alone. The recipe *is* the contract. |
| **Pro — resolution safety** | `{{secret.refresh_token}}` in the recipe always resolves to a key guaranteed present (or a clean "not connected") — never a typo'd/missing key. |
| **Pro — uniformity** | Every connection of a type has identical key shape → console UI + tooling are trivial, no per-connection variance. |
| **Pro — fewer footguns** | No silently-misnamed key that never gets read. |
| **Con — rigidity** | A connection needing a variant/extra credential (e.g. one account's upstream wants an extra header token) can't express it without a new/custom recipe. |
| **Con — recipe churn** | Small credential differences force new recipes. |

### Option B — **SUGGEST** (recipe proposes defaults; connection may define/override)

The `service.toml` proposes default secret keys, but a connection may define its
own (add, rename, override).

| | |
|---|---|
| **Pro — flexibility** | A connection carries extra/renamed secret keys without authoring a recipe (ad-hoc / power-user). |
| **Pro — fewer recipes** | One recipe covers near-variants; the connection patches the difference. |
| **Con — audit** | The secret-key set is no longer derivable from the recipe; you must inspect each connection. Weakens "the recipe is the audited contract" — SafeClaw's core pitch. |
| **Con — resolution risk** | The recipe's `{{secret.X}}` may reference a key the connection renamed/omitted → runtime "missing secret", or worse, silently reads the wrong key. |
| **Con — inconsistency** | Connections of one type diverge in shape → console/tooling must handle per-connection schemas. |

### Neutral framing

- **A** ties the credential vocabulary to the **audited recipe** (consistency &
  review-first). **B** moves it to the **connection** (flexibility-first).
- A middle path exists if wanted: recipe **defines required** roles (fixed
  names) **and optionally allows** extra connection-defined keys — this gets B's
  flexibility for the extras while keeping A's guarantee for what the recipe
  actually injects. It inherits B's audit/resolution caveats for the extra keys
  only.

*No recommendation embedded — your call.*

---

## 5. Routing

- A connection is addressed at **`/use/<connection_id>`** and
  **`/stream/<connection_id>`**.
- Per request, the daemon resolves **`connection_id → record.service → recipe`**
  once, then injects using the recipe + that connection's namespaced secrets.
- `connection_id` is the unit that flows through the **broker cache key
  `(vault, connection_id)`**, the **op scope**, and the **audit log** — not the
  service id.

---

## 6. Re-map slots (recipe-declared, **decided**)

A connection can only fill the slots the **recipe explicitly marks** as
per-connection — two kinds:

- **credential roles** — the secret keys (§3/§4).
- **dynamic params** — non-secret per-connection values, e.g. a `host` /
  `subdomain` for a self-hosted upstream.

Everything else — endpoints, `auth_mode`, scopes, the egress host of a normal
recipe — is **fixed by the type**. A connection can **never** re-point an
audited recipe's host or token endpoint (that would be SSRF / hijack). This is
the hard security boundary of the connection layer.

> The exact `service.toml` syntax for marking a slot per-connection (e.g. a
> `[[connection.params]]` block, or a `{{connection.host}}` template marker) is
> a recipe-format detail to finalize alongside §4 — the *rule* (only declared
> slots, host stays fixed) is settled.

---

## 7. Full example — two Gmail accounts + a self-hosted GitLab

```jsonc
// ── aux.connections ────────────────────────────────────────────────
"connections": {
  "gmail":       { "service": "gmail" },
  "gmail-work":  { "service": "gmail" },
  "acme-gitlab": { "service": "gitlab", "params": { "host": "git.acme.com" } }
}

// ── targets (flat secret map) ──────────────────────────────────────
"targets": {
  "gmail:refresh_token":      "<bytes>",
  "gmail-work:refresh_token": "<bytes>",
  "acme-gitlab:token":        "<bytes>"
}
```

- `GET /use/gmail-work/...` → daemon resolves `gmail-work → gmail` recipe →
  injects `Bearer {{oauth.access_token}}` minted from `gmail-work:refresh_token`.
- `acme-gitlab` reuses the `gitlab` recipe but substitutes the declared `host`
  slot (allowed — it's a marked param) while the auth shape stays fixed.

---

## 8. Delta from the shipped minimal (v1.0.20)

v1.0.20 shipped a **deliberately minimal** `aux.connections`: `connection_id ==
service_id`, **flat** secrets (`gmail_refresh_token`), and a legacy-flat read
path. This doc supersedes that:

| | v1.0.20 (minimal) | this schema (full) |
|---|---|---|
| connections per service | one (`id == service`) | many (`id` ≠ `service`) |
| record fields | `oauth_pending` only | `service` + `oauth_pending` + `params` |
| secret naming | flat `<svc>_refresh_token` | uniform `<conn>:<secret_key>` |
| routing | by service id | by `connection_id` |
| recipe owns secret keys | n/a | **§4 — open** |
| compat path | reads legacy flat key | **none — removed** |

**Landing = wipe + recreate.** No migration, no dual-read. The old flat-key
read path is deleted; existing test vaults are recreated from scratch.
