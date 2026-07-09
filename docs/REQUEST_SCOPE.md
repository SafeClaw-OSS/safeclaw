# Request scope — per-service `vars` / `scope` / `when` / `consent`

Phase 2 of the ask-always binding work ([CREDENTIAL_BROKER.md](./CREDENTIAL_BROKER.md)
§14 one-shot; [POLICY.md](./POLICY.md) for the level vocabulary). Phase 1 bound an
`ask-always` approval to `(connection, method, host, path)`. Phase 2 lets a
service declare the **body/query fields** that further identify an action, so:

- policy can decide on a field value: `when = "vars.amount > 80" → ask-always`;
- the approval **binds** those field values, so approving `$80` cannot be
  replayed as `$180` (the grant misses and re-prompts);
- the approval screen can **show** the human what they are authorizing
  ("Pay $80 to Acme"), not just `POST /v2/purchase`.

It is entirely opt-in: a service with no `[requests]` behaves exactly as before.

## Design principles this obeys

See [../memory principles] — restated so this doc stands alone:

- **P1 one boundary.** What policy judges and what a phantom resolves against is
  ONE buffered view of the request. A phantom-bearing request whose body exceeds
  `--body-cap` is refused (413), never forwarded policy-blind. So a field the
  policy can't read cannot be silently bypassed.
- **P2 over-limit = refuse, never prompt.** We never ask a human to approve
  content they can't see.
- **P3 policy is an explicit contract.** A `when` referencing an undefined var is
  **false** (not fail-closed to the rule). A request that matched no shape has no
  vars; a rule's `when` on it simply doesn't fire. The engine invents nothing.
- **P4 show ⊆ bind.** Every var a `consent` template interpolates MUST be in that
  shape's `scope`. Enforced at **build time** (see Verification), not by
  auto-adding to scope.
- **P5 default body not bound.** No `[requests]` / no `scope` ⇒ the body is not
  part of the grant identity (Phase-1 behavior). Binding a field is an explicit,
  per-service choice.

## Where each piece lives

A clean split by rate-of-change and owner ("delete `policy.toml` → only the
access *level* changes; parsing / binding / display are untouched"):

| Piece | File | Why |
|---|---|---|
| `[requests.<name>]` = `match`, `vars`, `scope`, `consent` | **service.toml** | API facts: which fields exist, which are identity vs noise, how to phrase them. Invariant across users; only the service author knows them. |
| rule `when` (+ `level`, `ttl`) | **policy.toml** (or user `aux.policy`) | The decision. Varies per user/connection; references vars by name. |

A request that matches a shape's `match` makes that shape's vars available to any
rule that also matches — the shape and the rule are joined by the request, not by
an explicit reference.

## `service.toml` — the `[requests]` section

```toml
[requests.purchase]
match = "POST /v2/purchase"                 # same grammar as a policy rule's match
vars.amount   = "/amount"                   # bare string = body JSON Pointer (RFC 6901)
vars.merchant = "/merchant_id"
vars.force    = { in = "query", at = "force" }   # a query parameter
scope   = ["amount", "merchant"]            # which vars BIND the grant (⊆ declared vars)
consent = "Pay {amount} to {merchant}"      # human phrasing; {name} vars must be ⊆ scope
```

- **`match`** — `"METHOD /path"` (or `"/path"` for any method); `*` = one segment,
  `**` = trailing depth. Exactly the policy-rule matcher (`match_spec`). A list is
  an OR. Shapes should not overlap; the first declared wins and a build lint warns.
- **`vars.<name>`** — an address into the request:
  - a **bare string** = a JSON Pointer into the (JSON or form-urlencoded) **body**;
  - `{ in = "query", at = "<param>" }` = a **query** parameter by name;
  - `{ in = "body", at = "/ptr" }` = the explicit long form of the bare string.
  Addressing is structural (RFC 6901), never a regex over serialized bytes, so
  key order / whitespace don't matter. A pointer that doesn't resolve, or a body
  that isn't parseable, yields an **undefined** var.
- **`scope`** — the subset of vars whose VALUES become part of the grant identity.
  Absent or `[]` ⇒ nothing bound (P5). Whitelist only in v1 (see Deferred).
- **`consent`** — a template rendered on the approval screen. `{name}` interpolates
  var `name`; every referenced var must be in `scope` (P4, build-enforced).

### `in` and the pointer space (why this, not a home-grown scheme)

`in = "body" | "query"` is the OpenAPI parameter-location convention and the same
split RFC 9421 (HTTP Message Signatures) draws between the message body and
`@query-param`. Body addressing is RFC 6901 JSON Pointer, which serde_json
resolves natively (`Value::pointer`) — one pointer resolves to exactly one value,
which is what a deterministic grant identity needs. (Multi-value JSONPath, RFC
9535, is a future need only if a rule must range over an array; deferred.)

## `policy.toml` — the `when` predicate

A rule gains ONE optional field, `when`, AND-combined with `match` and `body`:

```toml
[[rule]]
id    = "purchase"
match = "POST /v2/purchase"
level = "ask"                 # base: a purchase always asks once

[[rule]]
id    = "purchase-large"
match = "POST /v2/purchase"
when  = "vars.amount > 80"    # refinement: a large one asks EVERY time
level = "ask-always"
```

`when` grammar (v1): `vars.<name> <op> <literal>`, `op ∈ > < >= <= == !=`,
literal is a number or a `"quoted string"`. The `vars.` prefix mirrors K8s
ValidatingAdmissionPolicy's `variables.<name>` (and leaves room for future
built-ins like `request.method`); it composes toward CEL if the grammar ever
needs to grow, without a parser dependency today.

Because rules resolve **most-restrictive-wins**, the two rules above need no
special handling: `amount = 100` matches both → `ask-always` wins; `amount = 50`
matches only the base → `ask`. A `when` that references an undefined var makes its
rule simply not match (P3).

Qualified form `vars.<shape>.<name>` disambiguates when one rule spans several
shapes: it is defined only when THAT shape matched, else undefined (→ false).

## What gets bound, and how a tampered replay is caught

At op-create the proxy records, in the op's `scope`, the extracted values of the
shape's `scope` vars (plus the `consent` template). The `ask-always` grant key is
Phase-1's tuple **plus a digest of those bound values**:

```
(connection, method, host, path, scope_digest)
scope_digest = stable hash of the sorted (scope-var, value) pairs; "" when none
```

- **Legit replay** — same command → same field values → same digest → the
  single-use grant is found and consumed. A `nonce` field NOT in `scope` can vary
  freely; it never enters the digest.
- **Tampered replay** — `amount` changed `$80 → $180` → different digest → the
  grant misses WITHOUT being consumed (so the honest replay still works), and
  policy re-evaluates: `$180 > 80` → `ask-always` → a fresh prompt for `$180`.

The BODY as a whole is still not hashed (P5); only the declared `scope` fields
are. That is the point: bind the fields that define the action, ignore the noise.

## Consent display

The op carries `consent` = `{ template, vars: { name: value, … } }` (the scope
values, which are what the user is authorizing). The approval frontend renders
the template and, for a long value (a whole email body, a large JSON field),
folds it behind a "show details" toggle — a pure front-end hide/show over data
the daemon already sent. The daemon never truncates the value it binds; only the
display folds. (A value large enough that it shouldn't traverse the op-relay at
all — hundreds of KB — degrades to a `sha256:…(size)` digest with the label; rare.)

## The three worked services

### snaplii — the showcase (body threshold + bind + consent)

```toml
# service.toml
[requests.purchase]
match = "POST /v2/purchase"
vars.amount   = "/amount"
vars.merchant = "/merchant_id"
scope   = ["amount", "merchant"]
consent = "Pay {amount} to {merchant}"
```
```toml
# policy.toml  (purchase base stays ask; a large purchase escalates)
[[rule]] id="purchase"       match="POST /v2/purchase" level="ask"
[[rule]] id="purchase-large" match="POST /v2/purchase" when="vars.amount > 80" level="ask-always"
```
Exact body field names (`/amount`, `/merchant_id`) are pinned at e2e against the
live Snaplii A2M API and adjusted if they differ.

### gmail — bind a large body field

```toml
[requests.send]
match = "POST /gmail/v1/users/me/messages/send"
vars.raw = "/raw"                 # the base64url RFC822 message — the whole email
scope   = ["raw"]
consent = "Send this email"       # v1: raw folded/opaque; WYSIWYG decode is v2
```
Binding `raw` means an approved email cannot be swapped for a different one on
replay. Decoding base64url→RFC822 to show subject/to/body legibly is a v2 consent
transform; v1 binds and labels it.

### github — the opt-out baseline

github's dangerous actions are identified by **path** (`DELETE /repos/*/*`,
`PUT /repos/*/*/collaborators/*`), which Phase 1 already binds and which the
approve screen already shows legibly. So github needs **no** `[requests]` — it is
the proof that the feature is opt-in and that a path-identified action needs
nothing new. (The one body-shaped gate, `make-public`, keeps its existing `body`
regex; migrating it to a `when` is possible but buys nothing here.)

## Verification

Two layers, matching where the data lives. (There is no `cargo build` TOML gate
in this repo — `build.rs` only `include_str!`s the files; the de-facto build
check is `cargo test` over the compiled-in defs, which CI runs.)

**Intra-`service.toml`** — in `validate_service_inner` (`src/service/validate.rs`),
which already holds the parsed `ServiceDef`, so no new plumbing:
- every `scope` entry names a declared `var` (`scope ⊆ vars`);
- every `{token}` in a `consent` template is in `scope` (**P4 show ⊆ bind**);
- a body var address is an RFC 6901 pointer (leading `/`); a query `at` is
  non-empty.
- `deny_unknown_fields` on `RequestShape` makes a typo (`scopee = …`) a parse
  error, not a silent drop.

Enforced against every shipped service for free by the existing
`compiled_services_pass_validator` test.

**Cross-file `service.toml` × `policy.toml`** — `validate_service_policy(service,
policy)` parses both and checks every rule `when`: it must `Condition::parse`,
and its `vars.<name>` must be declared by some `[requests]` shape. Run over the
compiled pairs by the `compiled_policies_when_vars_are_declared` test — so if a
future edit drops snaplii's `amount` var while a rule still says
`vars.amount > 80`, the suite goes red. (`policy.toml` has no
`deny_unknown_fields` today, a pre-existing gap: a mistyped rule FIELD name is
still silently ignored — orthogonal to this feature.)

## Deferred (documented, not built in v1)

- **Blacklist scope** `scope = "body"` + `except = ["/nonce"]` (bind the whole
  body minus noise, via a canonical digest). None of the three services need it;
  whitelist covers them. Shape is reserved.
- **WYSIWYG consent transforms** (gmail base64url→RFC822 decode for display).
- **JSONPath (RFC 9535)** multi-value addressing for array-ranging conditions.
- **CEL** for `when` once the grammar outgrows `var op literal`.
