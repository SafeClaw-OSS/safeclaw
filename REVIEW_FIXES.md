# Phantom-only broker — post-build review fixes (2026-07-04)

An adversarial review (6 dimensions, find → independent-skeptic verify) ran over
the phantom-only build. 9 findings were CONFIRMED, 1 PLAUSIBLE. All CONFIRMED are
fixed below; the 1 PLAUSIBLE is an accepted limitation (documented).

## Fixed — core (branch `feat/broker-phantom`)

| # | Sev | What | Fix |
|---|-----|------|-----|
| handler.rs:226 | HIGH | registry advertised a service default phantom `__sc__<service>__` the proxy couldn't resolve (no `aux.connections` record) | proxy now synthesizes the default connection (`conn == service`) on a snapshot miss when `<conn>` names a known service; hosts derived from the record in hand (not a 2nd cache lookup that would miss the synth and wrongly empty the anchor) |
| registry.rs | HIGH/gap | raw connections (`sc set --host`, `sc connect`) never appeared in discovery; catalog rows advertised phantoms keyed differently than the proxy resolves | registry now emits one `category:"connection"` row per `aux.connections` entry (raw + named), carrying the ready-made phantom(s) + anchored hosts — the ONLY ids the proxy resolves. Service catalog rows no longer carry a phantom (a phantom names a connection). Round-trip consistent. |
| secret.rs:51 | MED | `sc set --no-broker` / `--host none` left a prior raw connection live (item still agent-usable) | the NoBroker arm now removes `aux.connections[lower(key)]` |
| proxy/mod.rs:34 | MED (sec) | proxy bound `config.listen` → `--listen 0.0.0.0` exposed the auth-less injector on all interfaces | proxy binds `127.0.0.1` unconditionally (loopback-only, independent of the control plane's `--listen`) |
| validate.rs:92 | MED | service `secrets`/`oauth2.secret` role validator allowed `__`/trailing `_`, so an advertised role phantom couldn't be parsed | role must start with a letter, no `__`, no trailing `_` (matches the phantom grammar); same rule aligned in `cli/conn.rs::valid_role` |
| secret.rs:153 | LOW | `sc rm KEY` left a dangling raw connection | `sc rm` also drops `aux.connections[lower(key)]` |
| secret.rs:67 | LOW | `sc set --host` validated the FQDN AFTER the unlock passkey (wasted a touch) | host + conn-id validation moved before unlock (mirrors `sc connect`) |
| resolver.rs:19 | (robustness) | greedy phantom regex could fuse two adjacent phantoms into one unparseable match | segment grammar tightened to single-underscore runs; regression test added |
| broker_flow.rs:151 | (defense) | `resolve_auth_value` derived oauth-ness from the compiled registry only → a custom `[oauth2]` service could fall through to injecting the raw refresh token | resolve oauth config from compiled AND custom (`aux.services`); if the pipeline says oauth but no config is found, fail closed (never return `raw`) |

## Fixed — console (branch `feat/broker-phantom-fe`)

- curated direct-secret connect now seals an `aux.connections` record (was: secret only → phantom unresolvable, named connection vanished).
- Add-connection catalog sourced from the per-vault `/v/{vid}/registry` so user-authored custom services (`aux.services`) are connectable.
- console renders the daemon's new `category:"connection"` rows (raw + named connections). `tsc --noEmit` + `next build` green.

## Accepted limitation (PLAUSIBLE, not fixed this pass)

- **Cold-locked single vault → phantom blind-tunnels instead of a clean 423.**
  `should_intercept` only MITMs hosts anchored by an UNLOCKED vault's connections;
  a locked (or never-unlocked) vault exposes no host list to intercept on, so a
  phantom sent while the only vault is locked reaches the upstream verbatim and
  returns a mystery 401 rather than `423 vault_locked`. No credential leaks (the
  phantom is never substituted). Correct fix needs the daemon to persist a
  locked vault's anchored-host set (out of scope here). Mitigation: `sc status`
  surfaces lock state, so the skill's routed-discipline preflight ("check
  `sc status` first") already tells the agent to `sc up` before firing a phantom.

## Build status

`cargo build` green (2 pre-existing warnings only); `cargo test --lib` 192 passed / 0 failed.
