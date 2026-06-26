# Git / GitHub / GitLab via SafeClaw — implementation spec

> **Status: DECIDED design, to be implemented.** Companion to
> [CONNECTIONS_AND_AUTH.md](./CONNECTIONS_AND_AUTH.md) (provider/service/connection
> + `[setup]` + `{{secret.X|filter}}`). This doc nails down the **git** case on
> top of that schema. Grounded in the live code: the streaming primitive
> ([src/proxy/stream.rs](../src/proxy/stream.rs)), the broker-plane agent-key gate
> ([src/api_key.rs](../src/api_key.rs)), and git's official `insteadOf` /
> `http.extraHeader` / env-config (`GIT_CONFIG_COUNT`, git ≥ 2.31).

## 0. Mental model — git is **three** things stacked

| What | Route | Injection | Who never sees the secret |
|------|-------|-----------|---------------------------|
| **A. REST API** (`gh api`, GraphQL, issues/PRs) | `/v/{vid}/use/{svc}` broker (buffered) | `Authorization: Bearer <token>` | the agent |
| **B. git transport** (clone/push/pull, smart-HTTP) | `/v/{vid}/stream/{svc}/{*rest}` (unbuffered) | `Authorization: Basic <base64(...)>` | the git process |
| **C. point git AT the broker** | `[setup]` tool-config (`git insteadOf`) | — | (config, touches no secret) |

So:

- **github** = A + B sharing one PAT.
- **gitlab** = A + B sharing one PAT.
- **"git"** = the B+C mechanism; any other forge (self-hosted, Bitbucket, Gitea)
  is an instance of it.

## 1. Decisions (locked)

1. **One service, two upstreams, one connection/secret.** Merge the legacy
   `github` (REST) + `github-git` (stream) split into a single `github` service
   with a `rest` upstream and a `git` upstream, both referencing the same
   `github_token`. Under connection namespacing (`<connection_id>:<role>`) two
   separate services would split the shared secret into `github:…` vs
   `github-git:…` — the merge avoids that. **gitlab** the same.
   - **Hard dependency:** [stream.rs](../src/proxy/stream.rs) currently selects
     `svc.upstream.first()`. After the merge the first upstream is `rest`
     (`stream=false`) → `/stream/github` would 409. stream.rs **must** change to
     `find(|u| u.stream)`. **The recipe merge and this one-line code change must
     land together**, or git breaks.
2. **PAT, not OAuth, for v1.** github/gitlab connect = "write one secret into the
   vault" (the trivial existing set-secret path) — **no `[provider]` block, no
   consent flow, no refresh machinery**. OAuth is a future onboarding nicety, not
   a simplification (it would *add* the consent + refresh infra).
3. **git is allow-only.** Streaming can't run the pause-and-hold passkey approval
   ceremony (a 500 MB packfile is live). [stream.rs](../src/proxy/stream.rs)
   already rejects non-allow services. Non-possession still holds regardless — the
   agent never sees the raw PAT. Approval (ask-level) is for high-risk ops
   (Export, payments), not git.
4. **Parameterized Basic filter.** GitHub and GitLab build HTTP Basic differently:
   - GitHub: token as username, empty password → `base64(token + ":")`.
   - GitLab: username must be non-empty (`oauth2`), token as password →
     `base64("oauth2:" + token)`.
   Add a parameterized filter: **`{{secret.X | basic:USER}}` = `base64(USER + ":" + token)`**.
   Bare `{{secret.X | basic}}` (= `base64(token + ":")`) stays for GitHub +
   back-compat. (Today's recipe uses the `{{secret_basic.X}}` alias until the pipe
   grammar lands.)
5. **SSH remotes get rewritten to HTTPS-through-broker.** `insteadOf` rewrites
   `git@github.com:` and `ssh://git@github.com/` too — so an SSH user routes
   through the broker with the vaulted PAT and **no longer needs their SSH key**.
   The agent inspects `git remote -v` and adapts (iron rule), not a blind rewrite.
6. **Self-hosted / enterprise / Bitbucket / Gitea = per-vault custom recipe**
   (rides `feat/per-vault-custom-recipes`): the user pastes a recipe pinning their
   host + token role + `stream=true`; validator checks it; it lands as a per-vault
   connection.
   - **Private-host policy (decision: option a).** The validator's anti-SSRF rule
     blocks RFC1918 / loopback / `.internal` egress — exactly where internal
     self-hosted git lives. A **first-party / console-reviewed (trusted)** custom
     recipe may **explicitly opt a host out**, per-recipe, e.g.
     `allow_private_host = true`, honored **only** in trusted mode (never for an
     arbitrary uploaded recipe in strict mode). Public hosts need no opt-out.

## 2. The auth chain (verified against live code)

git can't natively carry SafeClaw's agent key, but it can attach a static header.
The chain:

```
git request  (carries  Authorization: Bearer <SAFECLAW_API_KEY>)
  → broker plane :23295, middleware require_api_key  →  sha256(key) ∈ synced hash-set   [api_key.rs]
  → stream.rs strips inbound `authorization` (L123)  →  injects  Authorization: Basic <…github…>
  → forwards to github.com
```

- The agent key is **consumed by the middleware, then scrubbed by stream.rs before
  forwarding** — GitHub only ever receives the injected Basic. git never sees the
  PAT; the agent key never reaches the upstream. **This path is real, not assumed.**
- **Where `SAFECLAW_API_KEY` lives: the agent's environment, never disk.** Use
  git's env-config so nothing is written to `~/.gitconfig`:

  ```bash
  export GIT_CONFIG_COUNT=2
  export GIT_CONFIG_KEY_0="url.$ROUTE.insteadOf"      GIT_CONFIG_VALUE_0="https://github.com/"
  export GIT_CONFIG_KEY_1="http.$ROUTE.extraHeader"   GIT_CONFIG_VALUE_1="Authorization: Bearer $SAFECLAW_API_KEY"
  ```

  `$ROUTE` and `https://github.com/` are non-secret and **may** instead be
  persisted with `git config` (they leak nothing). Only the `extraHeader`
  carrying the key should stay env-only. The `git config --global …extraHeader`
  form works too but writes the key to disk — avoid for the key line; if you must
  persist it, use a dedicated `0600` file (e.g. `~/.safeclaw/gitconfig`) included
  via `include.path`, **never** the user's tracked `~/.gitconfig`.
- **`http.<url>.extraHeader` keys off the *rewritten* (broker) URL**, not
  `github.com` — git applies `http.*` config to the actual request URL after
  `insteadOf`. Both the `insteadOf` and the `extraHeader` config key on `$ROUTE`.
- **Set `GIT_TERMINAL_PROMPT=0`** when an agent runs git: if the api_key is wrong
  the broker returns 401 and git would otherwise **hang on an interactive
  credential prompt**. With the flag it fails fast instead.
- **Vault must be unlocked.** stream.rs needs the credential resident in the
  unlock-bootstrapped cache (allow services). Locked vault → 409. `sc up` first.

## 3. The recipes

### `services/integration/github/service.toml` (merged)

```toml
[service]
id = "github"
name = "GitHub"
category = "integration"

# A. REST API  →  /v/{vid}/use/github
[[upstream]]
id  = "rest"
url = "https://api.github.com"
  [upstream.auth]
  secret = "github_token"                       # renamed from `env` this schema wave
  [upstream.headers]
  Authorization = "Bearer {{secret.github_token}}"

# B. git smart-HTTP  →  /v/{vid}/stream/github
[[upstream]]
id     = "git"
url    = "https://github.com"
stream = true
  [upstream.auth]
  secret = "github_token"                       # same secret, same connection
  [upstream.headers]
  Authorization = "Basic {{secret.github_token | basic}}"   # base64(token + ":")

[[api]]
path = "*"
  [[api.steps]]
  target  = "upstream:rest"
  returns = true

# C. tool-config: let the agent point git at the broker (iron rule — goal + blocks
#    + a canonical example; the agent adapts to the user's real remotes).
[setup]
goal  = "Route the user's git remotes through SafeClaw so the GitHub PAT never enters git or the agent process."
route = "{{proxy_base}}/stream/github/"          # daemon-rendered (carries the real connection_id)
auth  = "Authorization: Bearer {{api_key}}"      # agent fills {{api_key}} from $SAFECLAW_API_KEY
example = '''
# Inspect first — don't assume github.com:
git remote -v ; git config --get-regexp '^url\.'

# Off-disk config (preferred for agents): key stays in the environment.
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0="url.{{route}}.insteadOf"     GIT_CONFIG_VALUE_0="https://github.com/"
export GIT_CONFIG_KEY_1="http.{{route}}.extraHeader"  GIT_CONFIG_VALUE_1="{{auth}}"

# SSH remotes? Rewrite them too (then the SSH key is no longer needed):
#   url.{{route}}.insteadOf = "git@github.com:"
#   url.{{route}}.insteadOf = "ssh://git@github.com/"
'''

[policy.levels]
read  = "allow"
write = "allow"          # streaming = allow-only (see §1.3)
```

### `services/integration/gitlab/service.toml` (greenfield, same shape)

```toml
[service]
id = "gitlab"
name = "GitLab"
category = "integration"

[[upstream]]
id  = "rest"
url = "https://gitlab.com/api/v4"
  [upstream.auth]
  secret = "gitlab_token"
  [upstream.headers]
  PRIVATE-TOKEN = "{{secret.gitlab_token}}"     # canonical PAT header (Bearer also accepted — verify at impl)

[[upstream]]
id     = "git"
url    = "https://gitlab.com"
stream = true
  [upstream.auth]
  secret = "gitlab_token"
  [upstream.headers]
  Authorization = "Basic {{secret.gitlab_token | basic:oauth2}}"   # base64("oauth2:" + token)

[[api]]
path = "*"
  [[api.steps]]
  target  = "upstream:rest"
  returns = true

[setup]
goal  = "Route the user's git remotes through SafeClaw so the GitLab PAT never enters git."
route = "{{proxy_base}}/stream/gitlab/"
auth  = "Authorization: Bearer {{api_key}}"
example = '''
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0="url.{{route}}.insteadOf"     GIT_CONFIG_VALUE_0="https://gitlab.com/"
export GIT_CONFIG_KEY_1="http.{{route}}.extraHeader"  GIT_CONFIG_VALUE_1="{{auth}}"
'''

[policy.levels]
read  = "allow"
write = "allow"
```

## 4. Connect (user side — one-time, no git commands)

1. Console → **Add connection → GitHub** → paste a PAT (scopes: `repo` for
   private repos; `read:org` etc. as needed).
2. That writes the vault item `github_token`. Done.

No OAuth, no daemon exchange — the plain set-secret path. Every agent on that
vault now self-configures git; **the user never touches git config or repeats
this per agent.** (GitLab identical with a GitLab PAT → `gitlab_token`.)

## 5. Setup (agent side — zero user interaction)

1. Agent reads `/v/{vid}/registry` → sees `github` connected, with a `[setup]`
   block.
2. Agent applies the `[setup]` (the env-config from §2/§3), substituting its own
   `$SAFECLAW_API_KEY` for `{{api_key}}`.
3. `git clone/push/pull` now route through the broker; PAT injected at egress.

**Who renders which template var** (resolves the skill-draft open item):

| Var | Rendered by | Why |
|-----|-------------|-----|
| `proxy_base`, `route`, `connection_id` | **daemon, in `/registry`** | daemon knows its bind addr, vid, and the connection_id (needed for multi-account `/stream/github-work/`); the agent shouldn't hand-assemble the URL |
| `api_key` | **agent, from `$SAFECLAW_API_KEY`** | daemon holds only the key *hash*; and the iron rule wants the agent using *its own* key, running the command itself |

Iron-rule compliant: daemon supplies routing facts, the agent brings its own key,
runs the commands, and adapts to the real remotes. **No canned `sc git connect`,
no decoy token, no concealed interception.**

### 5.1 Persist the inputs, derive the config each session (NOT per-session-set, NOT persisted-render)

The git config is a **projection of the environment**, not a piece of state to
either re-type every session or write to disk. Split by sensitivity:

| Piece | Sensitivity | Source | On disk? |
|-------|-------------|--------|----------|
| `insteadOf` (route rewrite) | non-secret | vault-derived — **`sc env` knows it** | doesn't matter |
| `extraHeader` (the api_key) | the agent's own key | the agent's environment (set once in its profile) | **no** |

**Mechanism — `sc env` emits the git routing too**, riding the pattern the agent
already uses (`eval "$(sc env)"`). `sc env` renders the `route`, and emits the
api_key line as the **literal text `$SAFECLAW_API_KEY`** (unexpanded) — the
agent's shell expands it from *its own* profile at `eval` time, so **`sc env`
never handles the key** (preserving its current "does not emit `SAFECLAW_API_KEY`"
design, see [src/cli/env.rs](../src/cli/env.rs)):

```bash
# added to `sc env` output, for each connected git service:
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0="url.<route>.insteadOf"     GIT_CONFIG_VALUE_0="https://github.com/"
export GIT_CONFIG_KEY_1="http.<route>.extraHeader"  GIT_CONFIG_VALUE_1="Authorization: Bearer $SAFECLAW_API_KEY"
```

So the answer to "per-session or one-time?": **inputs persist once** (the profile's
`SAFECLAW_API_KEY` + `eval "$(sc env)"`), the **config re-derives every session**
with zero manual work, nothing secret on disk, no stale state. The `[setup]` block
in `/registry` stays the canonical declaration; `sc env` is its shell projection.

> **Caveat — `GIT_CONFIG_COUNT` is a single global counter**, not composable with a
> user's own `GIT_CONFIG_*`. In the dedicated-agent-VM product line nothing else
> uses it → non-issue. On a shared human box, `sc env` must continue the existing
> count (read it, append) rather than overwrite.

## 6. Usage scenarios

- **New clone** — set the env-config, then `git clone https://github.com/o/r`
  rewrites to the broker automatically.
- **Existing repo** — `insteadOf` rewrites at *use* time (doesn't touch the stored
  remote), so already-cloned repos route through the broker once the config is set;
  no remote edits.
- **push & pull** — `insteadOf` (not `pushInsteadOf`) covers fetch + push in one.
- **Multi-account** — second connection `github-work` (secret `github-work:github_token`);
  map its host alias to `/stream/github-work/`. Cleanest disambiguation is per-repo
  config (account A's repos use `github`, account B's use `github-work`) since both
  point at real `github.com`.
- **SSH remote** — agent sees `git@github.com:` and rewrites it (§1.5); SSH key no
  longer needed.
- **REST** — `gh api` / GitHub API → `/v/{vid}/use/github` (Bearer), sharing the
  same PAT as the git transport.

## 7. Boundaries (own these)

- **Allow-only** (§1.3) — no *per-request* approval. Not a security hole
  (non-possession holds either way); a **feature gap** for "human-gate before
  push," closed by the pre-grant window (§7.1).
- **Unlock required** — git works only while the vault is unlocked (`sc up`).
- **api_key placement** — keep it in env via `GIT_CONFIG_*` (§2/§5.1); the only
  footgun is `git config --global …extraHeader`, which we don't use.
- **Large packfiles** — streamed unbuffered (body limit disabled on the route);
  fine. Network interruptions behave like normal git over a proxy.

### 7.1 Approval-gated git (future) — the pre-grant *window*, not a non-interrupting protocol

You **cannot** pause a live packfile to collect a passkey tap, and a held-open
stream has no clean way to hand the approve-link back. The fix is **not** to make
the streaming protocol non-interrupting — it's to **move the gate before the
stream**, `sudo`-style: approve a **time-boxed window**, not each request.

```
1. before git runs, the agent calls a normal BUFFERED endpoint:
   "request git access to <connection> for N minutes"
2. → returns { op_id, approve_url }   ← a normal response, so the link IS deliverable
                                         (it is NOT a stuck stream)
3. user taps passkey → grants a time-boxed window for that connection
4. agent runs git; /stream/ checks "is there a live grant window?" → allow → streams
5. window expires → the next git op requests a fresh grant
```

This reconciles both constraints: the stream never pauses (approval happened
*before* it), and the approve-link rides the buffered pre-grant call. UX is also
*better* than per-request — one tap per session, not per `git fetch`.

**Where the allow-only constraint must be surfaced** (so a user choosing "ask" on a
git service isn't silently ignored):

1. **Recipe validation** — reject `stream = true` + non-allow policy **at
   load/validate time** (today [stream.rs](../src/proxy/stream.rs) rejects only at
   request time → a late 403). Message: "streaming services are allow-only;
   per-request approval is unsupported — use a pre-grant window (roadmap)."
2. **[PROTOCOL.md](./PROTOCOL.md)** policy section — state the invariant: streaming
   routes require allow-level; ask/ask-always/deny are incompatible with streaming.
3. **Console UI** — when a user sets a streaming/git service to "ask," explain it
   and (when built) offer the window model instead.
4. **This doc** — §1.3 / §7 / §7.1.

## 8. Build checklist

0. **Merge** `github` + `github-git` → one service, two upstreams (§3); delete the
   hidden `github-git` recipe. **Together with**:
1. **stream.rs**: select `find(|u| u.stream)` instead of `.first()` (§1.1) — hard
   dependency; ship in the same commit as the merge.
2. **Template engine**: add `{{secret.X | basic:USER}}` (§1.4); keep bare `basic`
   + the `secret_basic` alias.
3. **gitlab recipe** (§3) — new service. Verify the REST PAT header
   (`PRIVATE-TOKEN` vs `Bearer`) against a live GitLab at impl time.
4. **`[setup]` → `/registry` rendering** of `proxy_base`/`route`/`connection_id`
   (§5); parser already landed. Per CONNECTIONS_AND_AUTH §9 the registry-render is
   shared with the broader setup work.
5. **`sc env` git projection** (§5.1): emit `GIT_CONFIG_*` for connected git
   services (route rendered; api_key as the literal `$SAFECLAW_API_KEY`); continue
   any existing `GIT_CONFIG_COUNT`.
6. **Validator**: (a) reject `stream = true` + non-allow at validate time (§7.1);
   (b) `allow_private_host` honored only in first-party/trusted mode (§1.6, opt a).
7. **Skill**: promote [git-streaming-skill-draft.md](./git-streaming-skill-draft.md)
   into the live skill, with `GIT_TERMINAL_PROMPT=0`, the env-config form, and the
   SSH-rewrite note.
8. **Smoke test** (still outstanding): real `git clone` + `git push` (large
   packfile) through `/v/{vid}/stream/github/`.

## 9. Deferred / out of scope

- OAuth connect for github/gitlab (onboarding nicety; not a simplification).
- Approval-gated git — feasible via the pre-grant window (§7.1); deferred, v1 is
  allow-only.
- Native SSH transport (we migrate SSH → HTTPS-through-broker instead).
- `grant.rs:29` HPKE plaintext fallback — unrelated to git but must close before
  any "cloud-blind" claim.
