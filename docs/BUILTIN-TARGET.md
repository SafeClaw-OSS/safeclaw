# Design: `target = "builtin"` for native service APIs

## Problem

Services like `files` have their API logic implemented in Rust (vault encryption, approval flow, DEK lifecycle), but their API surface is invisible to the agent because they don't declare `[[api]]` or `[[upstream]]` in service.toml. The agent can't discover or call them.

Current workarounds are all bad:
- **No TOML declaration** → service invisible in safeclaw.md service table
- **Using `help` as visibility signal** → implicit coupling, edge-case-prone
- **Fake `[[upstream]]` to localhost** → HTTP round-trip to same process, defeats the purpose
- **Fake `[[api]]` with no steps** → step engine returns `{"ok": true}` instead of actual data

## Goal

Services with Rust-native handlers should declare their API surface in TOML like any other service, using a dedicated target type that routes to the in-process handler.

```toml
# services/system/files/service.toml

[service]
id = "files"
name = "Files"
category = "system"
help = "..."

[[api]]
method = "GET"
path = "/"
  [[api.steps]]
  target = "builtin"
  returns = true

[[api]]
method = "GET"
path = "/{id}"
  [[api.steps]]
  target = "builtin"
  returns = true

[[api]]
method = "POST"
path = "/upload"
  [[api.steps]]
  target = "builtin"
  returns = true

[[api]]
method = "POST"
path = "/remove"
  [[api.steps]]
  target = "builtin"
  returns = true

[policy.levels]
read = "ask"
write = "ask"

[[policy.rules]]
method = "GET"
path_exact = "/"
level = "allow"
```

## Architecture

### Current flow (broken for files)

```
Agent → proxy (23295) → is_local? NO (no [[api]]) → forward_request → needs upstream URL → ✗
```

### Proposed flow

```
Agent → proxy (23295) → is_local? YES (has [[api]]) → handle_local_service
     → step engine → target = "builtin" → dispatch to registered Rust handler
     → handler executes in-process (no HTTP round-trip)
     → response returned to agent
```

### State sharing

ProxyState and AppState already share:
- `vault: Arc<Vault>` — same instance
- `config: Config` — same struct (includes `data_dir`)
- `approval_manager: Arc<ApprovalManager>` — same instance
- `audit_log: Arc<AuditLog>` — same instance

ProxyState is **missing**:
- `keypair` — needed for passkey verification (upload/remove auth)
- `challenges` — needed for passkey challenge flow
- `rate_limiter` — not needed for builtin handlers

Options:
1. **Add `keypair` to ProxyState** — simplest, proxy already runs in same process
2. **Shared inner state** — extract common state into a shared struct
3. **Keep passkey ops on admin API** — builtin handlers that need passkey auth delegate to admin API internally

Option 1 is recommended — minimal change, proxy is trusted (localhost-only).

### Handler registry

```rust
// In core/router.rs or a new core/builtin.rs

type BuiltinHandler = Box<dyn Fn(&ProxyState, &str, &str, Bytes) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

fn builtin_registry() -> HashMap<&'static str, BuiltinHandler> {
    let mut m = HashMap::new();
    m.insert("files", Box::new(handle_builtin_files) as BuiltinHandler);
    m
}

async fn handle_builtin_files(state: &ProxyState, method: &str, path: &str, body: Bytes) -> Response {
    match (method, path) {
        ("GET", "/" | "") => { /* read index.json, return files list */ },
        ("GET", id) => { /* read encrypted file, needs approval DEK */ },
        ("POST", "/upload") => { /* encrypt + store file, needs passkey */ },
        ("POST", "/remove") => { /* delete file, needs passkey */ },
        _ => not_found(),
    }
}
```

### Step engine change

In `handle_local_service` (router.rs ~771), when executing a step with `target = "builtin"`:

```rust
// Current targets: "safeclaw" (run command), "safeclaw.vault" (vault read), "upstream:*" (HTTP forward)
// New: "builtin" → dispatch to handler registry

if target == "builtin" {
    let handler = builtin_registry.get(service_name);
    return handler(state, method, path, body).await;
}
```

## Files handler migration

Current files handlers live in `server/routes.rs` and use `State<Arc<AppState>>`:

| Handler | Auth | What it does |
|---------|------|-------------|
| `vault_files_list` | none | Read index.json → return file list |
| `vault_files_read_approved` | approval session | Read encrypted file with DEK from approval |
| `vault_files_read` | passkey | Decrypt file with user key |
| `vault_files_upload` | passkey | Encrypt + store file |
| `vault_files_remove` | passkey | Delete encrypted file |

Migration plan:
1. Move handler logic into `core/builtin_files.rs`
2. Adapt to use `ProxyState` instead of `AppState`
3. For passkey-requiring handlers: either add keypair to ProxyState, or use approval flow exclusively (agent always goes through 202 → approve → replay)
4. Keep admin API handlers as thin wrappers calling the same core functions (for browser/console access)

## Scope

| Item | Files | Effort |
|------|-------|--------|
| Add `target = "builtin"` to step engine | `core/router.rs` | ~20 lines |
| Handler registry | `core/builtin.rs` (new) | ~30 lines |
| Files TOML declarations | `services/system/files/service.toml` | ~20 lines |
| Migrate files handlers | `core/builtin_files.rs` (new) | ~150 lines |
| Add keypair to ProxyState | `core/router.rs`, `main.rs` | ~5 lines |
| Update `is_agent_visible` | `service/mod.rs` | already done |
| Tests | `tests.rs` | ~50 lines |

## Benefits

- **Agent visibility**: files appears in safeclaw.md service table (has `[[api]]`)
- **No HTTP round-trip**: handlers execute in-process
- **Unified TOML surface**: all agent-callable APIs declared in service.toml
- **Policy integration**: files policy rules work through normal policy engine
- **Extensible**: future builtin services just register a handler

## Non-goals (this iteration)

- Moving ALL admin API endpoints to builtin (only files for now)
- Changing the approval flow architecture
- Breaking existing admin API routes (keep them for browser/console access)
