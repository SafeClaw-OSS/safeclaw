# Consent templates — the ONE grammar for approval copy

Two authorship domains, one grammar, one renderer contract:

| Domain | Declares | Lives in | Params come from |
|---|---|---|---|
| Service (`service.toml [requests].consent`) | what a brokered REQUEST means | the service definition | request-bound `scope_vars` (P4: show ⊆ bind) |
| Product (`src/protocol/acts.toml`) | what a VAULT OPERATION means | core, next to the act implementation | the signed op's `target` / `scope` fields |

Every approval surface (grant page, CLI prompt, audit row) renders
**static reviewed template ⊕ signed op bytes** — requester-authored prose can
never reach an approval surface (ERC-7730 / RFC 9396 shape).

## Grammar

`{{ vars.<path> | <filter> }}`

- acts.toml paths: `vars.target` → `op.act.target`; `vars.scope.<key>` →
  `op.act.scope[<key>]` (one level, no deep paths).
- requests paths: `vars.<name>` → the bound `scope_vars` entry.
- `| filter` is display-only. Renderers MUST accept and MAY ignore any filter.
  Currently defined: `basic` (requests only, git credential preview). Adding a
  filter requires updating BOTH renderers (core `protocol::consent` +
  console `interpOp` in `app/grant/[id]/page.tsx`) and the shared vectors below.

## Value rendering (P3 rules — both renderers MUST match)

- undefined / missing / null → empty string
- string → verbatim; number → decimal
- `true` → `yes`; `false` → empty
- array → string elements joined with `", "`
- a FACT row whose value renders empty is omitted entirely
- values are truncated (core: 120 chars + `…`)

## acts.toml descriptor fields

`action` (+`action_zh`) — verb-object title, doubles as the approve button
label. `explain` (+`explain_zh`) — one sentence, ALWAYS rendered inline.
`tone` — `neutral | info | danger`; advisory upward-only (clients keep a
built-in danger floor per act kind; a catalog can raise tone, never lower).
`facts` — `{label, label_zh?, value}` rows; labels `Service` / `Host` /
`Connection` / `Secret in use` map onto the console's standard pretty rows.

## Drift gates

- `consent::tests::dispatch_and_table_agree` — every dispatched custom act has
  a descriptor and vice versa (`DISPATCHED_CUSTOM_ACTS` in approve.rs).
- Shared vectors: `consent::tests` (`renders_action_facts_and_p3_rules`,
  `bool_and_missing_vars_render_per_p3`, `filters_accepted_and_ignored`) are
  the normative examples; a console renderer change must keep them true.

## Distribution

`sc registry --json` (the published SSoT catalog, opt-in like policy rules) →
CI `registry.json` → backend `/registry` passthrough → console. Version skew
falls back: no descriptor → humanized slug card, never a raw debug dump.
