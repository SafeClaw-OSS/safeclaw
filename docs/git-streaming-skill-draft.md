# DRAFT — git via SafeClaw (agent-facing skill section)

> **Status: DRAFT. NOT in the live skill (`static/safeclaw-skill.md`).**
> The streaming route + `github-git` recipe are built (v1.0.18) but **not yet
> live-tested with a real `git clone`** (vault was locked during the build).
> Review + smoke-test, then fold into `static/safeclaw-skill.md`.
>
> Written per the iron rule ([[feedback_agent_transparent_cooperation]]):
> give the agent the **goal + building blocks + facts**, let it adapt the HOW
> to the user's real config. No canned `sc git connect`, no deception.

## Goal (tell the agent)

Route the user's git remote(s) through SafeClaw so the GitHub token **never
enters git or your process**. SafeClaw runs a local streaming broker; you point
git at it with git's official `insteadOf`, and SafeClaw injects the token at
egress. You talk to `localhost` over plain http (no cert), SafeClaw does the
TLS to GitHub.

## Building blocks (facts, not a fixed recipe)

- Local broker: `http://localhost:23295/v/<VID>/stream/github-git/`
  - `<VID>` = your vault id (from `SAFECLAW_VAULT_URL`).
  - The route is **agent-key gated**, so git must send your `SAFECLAW_API_KEY`
    as a Bearer header (git won't do this by itself → use `http.extraHeader`).
- Preconditions: the GitHub PAT is in the vault as `github_token`, and the
  `github-git` service is connected (allow-policy). If not, set it up first.

## Setup (you run it — but inspect the user's REAL config first)

Do NOT assume `github.com`. Look at what's actually there:

```bash
git remote -v
git config --get-regexp '^url\.'        # existing insteadOf rules
```

For a standard `github.com` remote:

```bash
B="http://localhost:23295/v/<VID>/stream/github-git/"
git config --global url."$B".insteadOf "https://github.com/"
git config --global http."$B".extraHeader "Authorization: Bearer <SAFECLAW_API_KEY>"
```

Adapt, don't force:
- If the user uses a **custom alias** (e.g. `https://v2.github.com/` for a
  second account), rewrite THAT base to the same `github-git` stream URL.
- If they use **GitLab / Bitbucket / self-hosted**, that needs its own SafeClaw
  recipe (only `github-git` ships today) — tell the user, don't point it at
  `github-git`.
- **Scope:** `--global` only if the user wants *all* their GitHub through
  SafeClaw; otherwise set it per-repo or in a dedicated `GIT_CONFIG`.

## After setup

`git clone https://github.com/owner/repo`, `git push`, `git pull` work exactly
as normal. The PAT is injected by the broker; git never sees it.

## Transparency (the rule)

Tell the user what you're configuring and why **before** doing it. You're
setting up an explicit, known route through the user's own SafeClaw daemon —
not intercepting anything behind their back. If their git config is unusual and
you're unsure how to map it, **ask** — don't guess, don't deceive git or the user.

---

### Open items to verify before this goes live
1. Real `git clone` + `git push` through `/v/{vid}/stream/github-git/` actually
   works end-to-end (streaming, auth injection, large packfile).
2. Confirm git's `http.<url>.extraHeader` reaches the agent-key middleware and
   is then scrubbed before the request is forwarded to GitHub (the stream
   handler scrubs `authorization` + injects the GitHub Basic — verify no leak).
3. Decide the `<VID>` / `<SAFECLAW_API_KEY>` substitution mechanism in the live
   skill (template vars vs. instruct the agent to read its env).
