# Connections: how a secret becomes a phantom

A secret in the vault is just a value. A **connection** is what makes it
spendable: the binding of secret(s) to a service's hosts, addressed by a
phantom.

```
secret  HF_TOKEN = hf_xxx…                      inert storage
   +
anchor  huggingface.co                          where it may be spent
   =
connection "hf_token"  →  phantom __sc__hf_token__
```

Three rules keep this unambiguous:

- **A phantom resolves to exactly one value.** Each slot of a connection is
  bound to one secret KEY, so there is no guessing. Two connections may bind
  the same KEY; the approval that creates the second one says so.
- **Hosts come from one source.** A catalog service declares its hosts; a
  custom connection anchors its own. Either way the agent can't move them.
- **Host is a constraint, never a selector.** The broker validates the
  destination against the anchor; it never picks a credential *because* of
  where traffic is going.

## The catalog

Services ship as declarative definitions (`services/*/service.toml`): hosts,
secret shapes, OAuth wiring, and human-labeled policy rules. GitHub, OpenAI,
Anthropic, Gemini, Gmail, Google Drive, GCP, Supabase, Railway, GitLab, npm,
crates.io, Telegram and more are built in; agents discover what's connected
with `sc connection ls`.
Adding a service is a TOML file, not a plugin: [SERVICES.md](reference/services.md).

## Ways to connect

- **OAuth services**: connect from the console; SafeClaw runs the flow and
  manages token refresh. The agent's phantom stays stable across refreshes.
- **Paste a key in the console**: encrypted in your browser before upload.
- **At the terminal**: `sc set HF_TOKEN --host huggingface.co` prompts for
  the value, takes one passkey approval, and the value never leaves your
  machine.
- **`sc connection add`**: fills each secret slot from a new value
  (`--from-literal SLOT=VALUE`) or from a secret already in the vault
  (`--from-secret SLOT=KEY`, no value shown anywhere). With `--service`, a
  slot is one of the service's secret roles; for a custom connection it is
  the KEY itself (`--from-secret KEY`). A service's primary credential role
  is required (prompted for on a terminal); its other roles, like
  Cloudflare's account ID, are optional.

  ```
  sc connection add codex_work --service openai_codex \
      --from-secret OPENAI_CODEX_REFRESH_TOKEN=WORK_REFRESH_TOKEN
  sc connection add myapi --host api.example.com --from-literal API_TOKEN=…
  ```

  Your agent may run it to propose a connection. Nothing is written until you
  approve with your passkey, and the approval lists every key the connection
  binds (new or existing), every host it sends them to, and any other
  connection already using the same key.

  `sc connection rm <id>` deletes the secrets that connection wrote, unless
  another connection uses them. A secret it was bound to with
  `--from-secret` stays in the vault, and so does every secret of a
  connection added before SafeClaw recorded which secrets a connection
  writes; the command lists each kept key and why.
- **Any other HTTPS API**: a custom connection with your own host anchor.
  The catalog is a convenience, not a boundary.
- **External stores**: keep values in your own secret manager (e.g. GCP
  Secret Manager); SafeClaw fetches at use, and the value still never
  reaches the agent.

## Multiple accounts

Accounts differ by phantom *value*, not env-var name: `__sc__github__` and
`__sc__github_work__` are two connections behind the same `GITHUB_TOKEN`
variable. See [`sc run` and phantoms](sc-run.md).
