# Request scope — per-service `vars` / `scope` / `when` / `consent`

Phase 2 of the ask-always binding work ([credential-broker.md](credential-broker.md)
§14 one-shot; [../reference/policy.md](./../reference/policy.md) for the level vocabulary). Phase 1 bound an
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
consent = "Pay {{ vars.amount }} to {{ vars.merchant }}"   # {{ vars.x | filter }} template
```

- **`match`** — `"METHOD /path"` (or `"/path"` for any method); `*` = one segment,
  `**` = trailing depth. Exactly the policy-rule matcher (`match_spec`). A list is
  an OR. Shapes should not overlap; if they do, selection is deterministic (the
  matching shape whose name sorts first wins) so the bound digest stays stable.
- **`vars.<name>`** — an address into the request:
  - a **bare string** = a JSON Pointer into the **body** (parsed as JSON; v1 is
    JSON-only — a non-JSON body leaves body vars undefined, which is safe: a
    `when` doesn't fire and nothing is bound);
  - `{ in = "query", at = "<param>" }` = a **query** parameter by name;
  - `{ in = "body", at = "/ptr" }` = the explicit long form of the bare string.
  Addressing is structural (RFC 6901), never a regex over serialized bytes, so
  key order / whitespace don't matter. A pointer that doesn't resolve, or a body
  that isn't parseable, yields an **undefined** var.
- **`scope`** — the subset of vars whose VALUES become part of the grant identity.
  Absent or `[]` ⇒ nothing bound (P5). Whitelist only in v1 (see Deferred).
- **`consent`** — ONE template string, using the SAME `{{ vars.x | filter }}`
  pipe grammar as git-integration's `{{ secret.X | basic }}` (the Liquid / Jinja
  convention). Two shapes:
  - **plain interpolation** — `"Buy from {{ vars.merchant }} for {{ vars.amount }}"`;
  - **a rich renderer via a filter** — `"{{ vars.raw | email }}"`, where `email`
    is console code (like git's `basic` = base64) that decodes the bound
    base64url message into a From/To/Subject/Body card.

  A filter names console code (declarative toml, code in the console — the same
  split as `[auth]`); adding a renderer is adding a filter, no schema change.
  Every referenced `vars.<name>` must be in `scope` (P4, build-enforced), and a
  filter reads ONLY that bound value. **Values are auto-escaped by the
  renderer** (React text nodes) — they come from the agent, so a value
  containing `<script>` is displayed, never executed (XSS-safe). A filter never
  fetches a URL from a value (no SSRF); the approve action is passkey-gated (not
  a template/CSRF concern).

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

The op scope carries `consent` (the `{{ vars.x | filter }}` template) and
`scope_vars` (the bound values — what the user is authorizing). The console
parses the template and renders each reference:

- a plain `{{ vars.x }}` → the escaped value inline ("Buy from Acme for 40");
- `{{ vars.raw | email }}` → decode the bound base64url message into a
  From/To/Subject/Body card;
- an unknown filter / no template → a generic bound-field list.

The technical request (method/host/path) and the raw bound values fold under a
"▶ Advanced Details" disclosure — a pure front-end hide/show over data the
daemon already sent. The daemon never truncates the value it binds; only the
display folds. (A bound value over 8 KiB is bound by `sha256:…#len` so the op
stays small; its preview degrades to that marker.)

## The three worked services

### snaplii — the showcase (body threshold + bind + consent)

```toml
# service.toml
[requests.purchase]
match = "POST /v2/purchase"
vars.amount   = "/amount"
vars.merchant = "/merchant_id"
scope   = ["amount", "merchant"]
consent = "Buy from {{ vars.merchant }} for {{ vars.amount }}"
```
```toml
# policy.toml — small-value convenience, big-value confirmation (contactless norm)
[[rule]] id="purchase"       match="POST /v2/purchase" level="ask"
[[rule]] id="purchase-large" match="POST /v2/purchase" when="vars.amount > 100" level="ask-always"
```
A small purchase is `ask` (approve once, reuse window) but BOUND to amount +
merchant — approving "$40 to Acme" cannot be ridden by "$75 to EvilCorp" (a
different value re-prompts). Over the threshold escalates to `ask-always`
(every spend confirmed, single-use). To make small purchases frictionless with
no tap, set the base to `allow`. Exact body field names (`/amount`,
`/merchant_id`) and the threshold are pinned at e2e against the live A2M API.

### gmail — bind a large body field

```toml
[requests.send]
match = "POST /gmail/v1/users/me/messages/send"
vars.raw = "/raw"                 # the base64url RFC822 message — the whole email
scope   = ["raw"]
consent = "{{ vars.raw | email }}"   # the `email` filter → From/To/Subject/Body card
```
Binding `raw` means an approved email cannot be swapped for a different one on
replay. The `email` filter (console code, like git's `| basic`) decodes
base64url→RFC822 into a legible card, the raw message under Advanced Details.

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

## Known limitations (deliberate for v1)

Surfaced by the adversarial review; each fails SAFE (toward more gating / a
re-prompt) or is a documented author responsibility, none is a silent bypass:

- **A scoped decision binds; the tier picks single-use vs reuse.** A request
  that resolves a non-empty scope is bound for BOTH `ask` and `ask-always`:
  `ask-always` is single-use (every request re-prompts); a scoped `ask` peeks —
  reused for the SAME bound values within its window, but a DIFFERENT value
  (a different amount / merchant) still misses and re-prompts. So a scoped-ask
  consent is never a false promise. A scoped `ask` is right for the
  small-value-convenience tier (contactless norm): a distinct purchase is
  approved once, an *identical* repeat rides the window, a *different* one
  re-prompts. If even an identical repeat must re-confirm (a high-value spend),
  use `ask-always` (single-use). If any small purchase should be frictionless
  with no tap, use `allow`. (An UNSCOPED `ask` — no `[requests]` — keeps the
  Phase-1 connection-wide window: the documented usable-but-not-bound default.)
- **Whitelist binds only named fields.** A body field not in `scope` is neither
  shown nor bound — the author must name every field that defines the action
  (P4/P5). For snaplii, if the live purchase body carries a recipient/SKU, add
  it to `scope` at e2e.
- **`when` is a refinement, not a gate of last resort (P3).** An undefined var
  makes its rule not fire; if a `when` rule were the ONLY thing between a path
  and a permissive floor, an unreadable field would fall through to that floor.
  Always keep a base rule (snaplii's `purchase → ask` under the
  `purchase-large → ask-always`). Verification requires a `when` var to be
  bound, but does not (cannot) prove a base rule exists.
- **Parser differential.** The binding assumes SafeClaw's JSON parse equals the
  upstream's. `serde_json` is duplicate-key-last-wins and lenient in ways a
  given API may not share; a crafted body (`{"amount":180,"amount":80}`) could
  bind/show one value while the upstream acts on another. This is the
  proxy-vs-origin parsing class (cf. request smuggling); out of scope for v1.
- **Numeric canonicalization.** `80`, `80.0`, `8e1` compare equal to a `when`
  threshold but bind three different digest strings — so a replay that
  re-serializes the number differently re-prompts (fails safe, never
  under-binds). A literal byte-identical replay is unaffected.
- **Large values bind by digest.** A bound value over 8 KiB (a big email) binds
  its `sha256:…#len` instead of the verbatim value, so the op stays under the
  relay's size limit; its console preview degrades to the marker.

## Deferred (documented, not built in v1)

- **Blacklist scope** `scope = "body"` + `except = ["/nonce"]` (bind the whole
  body minus noise, via a canonical digest). None of the three services need it;
  whitelist covers them. Shape is reserved.
- **WYSIWYG consent transforms** (gmail base64url→RFC822 decode for display).
- **JSONPath (RFC 9535)** multi-value addressing for array-ranging conditions.
- **CEL** for `when` once the grammar outgrows `var op literal`.
