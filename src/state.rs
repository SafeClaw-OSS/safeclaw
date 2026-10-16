//! Top-level application state.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::approval::ApprovalStore;
use crate::audit::AuditRegistry;
use crate::config::Config;
use crate::passkey::challenge::ChallengeStore;
use crate::service::ServiceRegistry;
use crate::storage::VaultDir;

/// Broadcast payload for the per-vault SSE channel. The receiver-side filter
/// is on `vault_id`; subscribers belonging to other vaults drop the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub vault_id: String,
    pub approval_id: String,
    /// One of "pending" | "approved" | "rejected" | "cancelled".
    pub kind: String,
    /// Summary of the approved Operation (act.kind, target, scope) — present
    /// for pending. Frontend uses it to render the request card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_summary: Option<Value>,
    /// Cached upstream response for broker (Use) approvals after approve —
    /// `{status, headers, body, body_base64}` JSON. Present for approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_preview: Option<Value>,
    /// Rejection reason — present for rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Broadcast channel capacity. Lagging subscribers (typically tabs sleeping
/// in a background pinch) will drop events older than this — they reconnect
/// fresh and lose history, which is acceptable for a watcher UI.
const EVENT_CHANNEL_CAPACITY: usize = 128;

// ── Vault state (H3 / PROTOCOL.md §6.3) ──────────────────────────────────────
//
// Per-vault runtime state. Daemon boots Locked; user runs the SUDP
// `Custom("vault-unlock")` op to transition Unlocked (and side-effect a
// per-service secrets_cache bootstrap for `allow`-policy services). No auto-
// lock timer — that would break the `allow` invariant ("once unlocked, no
// further friction during the session"). Lock is always user-initiated via
// `Custom("vault-lock")` op.

/// A cached secret value with optional expiry. Per PROTOCOL.md §6.2,
/// memory residence is policy-driven:
///   - `allow` services → `expires_at = None` (lives the whole unlocked
///     session, populated at unlock bootstrap)
///   - `ask` services → `expires_at = Some(unix_secs)`, filled after
///     `approval-confirm` with the matched rule's `ttl`
///   - `ask-always` services → never in `entries`; their one-shot grants
///     live in `op_grants`, keyed by the approved request tuple
///
/// `cache_lookup` does lazy eviction: an entry past its `expires_at`
/// is removed and treated as a miss. No active sweeper today —
/// expired bytes linger in memory until the next lookup, which is
/// acceptable since the daemon already holds plaintexts for all
/// allow-level services anyway.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: Vec<u8>,
    /// `None` = never expires within the unlocked session (allow-level).
    /// `Some(t)` = expires at unix-second `t` (ask-level TTL).
    pub expires_at: Option<u64>,
    /// `true` = this value was pre-loaded at unlock by `bootstrap_cache_from_view`
    /// (the connection's read floor is `allow`), NOT produced by a passkey grant.
    /// Residency only: a value in `entries` (bootstrapped or held after an
    /// approval) serves requests the policy allows, and an ask-level request
    /// only once the ask-grant ledger (`ask_grants`) authorized it. The
    /// ask-always path never reads `entries` at all (see `op_grants`).
    pub from_bootstrap: bool,
    /// The agent whose approval put this value here (`None` for bootstrap /
    /// residency entries). Informational: residency never authorizes an ask.
    pub agent_prefix: Option<String>,
}

/// How long an approved `ask-always` one-shot grant stays redeemable
/// (`op_grants` expiry = approve-time + this). Generous on purpose: the
/// replay is agent-driven, and an agent that only acts when its user next
/// prompts it can take many minutes. Safety comes from single-use + exact
/// request binding, not from this window.
pub const ASK_ALWAYS_REPLAY_WINDOW_SECS: u64 = 1800;

/// The identity of a request-bound grant (`SecretsCache::op_grants`): the
/// approving agent, the request line, the bound-values digest, and the tier
/// that minted it. Host is lowercased.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpGrantKey {
    pub agent: String,
    pub conn: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub scope_digest: String,
    pub tier: crate::approval::reuse::BoundTier,
}

impl OpGrantKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent: &str,
        conn: &str,
        method: &str,
        host: &str,
        path: &str,
        scope_digest: &str,
        tier: &crate::approval::reuse::BoundTier,
    ) -> OpGrantKey {
        OpGrantKey {
            agent: agent.to_string(),
            conn: conn.to_string(),
            method: method.to_string(),
            host: host.to_ascii_lowercase(),
            path: path.to_string(),
            scope_digest: scope_digest.to_string(),
            tier: tier.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecretsCache {
    /// service_id → cached auth value with per-entry expiry. Filled by:
    ///   - unlock bootstrap (only services whose default read level is
    ///     `allow` — see `bootstrap_cache_from_view`)
    ///   - post-approval insert from `approve_op` for `ask` and `allow`-
    ///     cache-miss paths (the secret was fresh-decrypted under the
    ///     grant's W_c during forward; we re-use it for subsequent
    ///     requests up to the policy TTL).
    /// `ask-always` services are deliberately absent (PROTOCOL.md §6.2
    /// "ask-always 服务: 永不进 cache").
    pub entries: HashMap<String, CacheEntry>,
    /// service_id → { secret_name → bytes } for every direct secret an
    /// `allow`-level service references. Populated at unlock bootstrap so the
    /// allow fast-path can resolve *multi-secret* services (e.g. a Twilio-style
    /// `account_sid` + `auth_token` pair) without a vault view — which only
    /// exists behind a fresh grant. Single-secret services get a one-entry
    /// map; oauth services get no entry (their token comes from `oauth_access`).
    /// Lives the whole unlocked session (allow semantics); wiped on lock.
    pub allow_secrets: HashMap<String, HashMap<String, Vec<u8>>>,
    /// The effective policy tree — the vault's `aux.policy` overlaid on the
    /// compiled-in `Policy::default()` at unlock/refresh (so unset parts use
    /// safe defaults). Holds default floors, per-tag, and per-connection
    /// user policy. Built-in per-service rules are NOT cached here — they're
    /// read live from the service registry at eval and merged with this tree's
    /// `connections.<id>.rules`. Rebuilt on every vault write → a policy edit is
    /// realtime on the next request.
    pub policy: crate::core::policy::Policy,
    /// Audit log retention in days. Snapshot of `aux.audit_retention_days`
    /// at unlock. `None` = keep forever. Used by `GET /v/{vid}/approvals` to
    /// opportunistically prune old rows before listing.
    pub audit_retention_days: Option<u32>,
    /// The ask-grant ledger: what an approved, unscoped `ask` authorizes,
    /// decoupled from whether the credential value is resident. Key:
    /// `(agent_prefix, connection_id, host, unit)` where `unit` is the policy
    /// unit that produced the ask (`crate::approval::reuse::GrantUnit`): the
    /// matched rule's id and the request's class, or the default floor's class
    /// (read / write). Value: Unix-epoch-second expiry.
    ///
    /// `evaluate_request_decision` downgrades a later `Ask` to `Allow` only
    /// when the policy, re-run on that request, lands on the same unit for the
    /// same agent, connection, and host. So approving rule A never serves rule
    /// B, a read approval (rule or floor) never serves a write, and an allow-level miss
    /// (which writes no entry) never serves an ask. Scoped paths and
    /// `ask-always` never consult it (they are request-bound, `op_grants`).
    ///
    /// Same memory window as the rest of the cache: dropped on lock and on
    /// every vault change (the cache is rebuilt), and a daemon restart starts
    /// empty (vaults boot Locked).
    pub ask_grants: HashMap<(String, String, String, crate::approval::reuse::GrantUnit), u64>,
    /// Request-bound grants, keyed by the REQUEST the user approved and the
    /// tier that minted it ([`OpGrantKey`]): agent-bound like `ask_grants` (a
    /// grant minted for agent A's request cannot be spent by agent B), and
    /// tier-bound (`crate::approval::reuse::BoundTier`): an ask-always grant is
    /// redeemed only by an ask-always request, a scoped ask's `exact` grant
    /// only by a scoped ask of the same unit, a single-use ask grant only by an
    /// ask a rule with no id decided. Written by `approve_op`; a single-use
    /// tier is consumed (removed) by the proxy's replay exactly once, `exact`
    /// is read within its window. This is what makes an `ask-always`
    /// approval mean "this action, once": a grant minted for `POST /v2/purchase`
    /// can never be spent by a different method/host/path on the same
    /// connection, and the ask-always path never falls back to the conn-keyed
    /// `entries` (so it can't ride a plain-ask leftover or the allow residency).
    ///
    /// `scope_digest` (Phase 2) folds the values of the service's declared
    /// `[requests]` scope fields into the identity (`""` when a service declares
    /// none — the Phase-1 path-only key). So approving `amount=80` cannot be
    /// replayed as `amount=180`: the redeem re-extracts the fields, the digest
    /// differs, the grant misses (without being consumed) and re-prompts. See
    /// `crate::service::scope_digest` and design/request-scope.md.
    ///
    /// Expiry is deliberately GENEROUS (`ASK_ALWAYS_REPLAY_WINDOW_SECS`, not a
    /// short grace): an agent that only replays when its user next prompts it
    /// (e.g. a chat agent) may take minutes to re-run. Single-use + exact
    /// binding is what makes the long window safe — time is not the guard.
    /// Same memory window as the rest of the cache: dropped on lock/refresh.
    pub op_grants: HashMap<OpGrantKey, CacheEntry>,
    /// Item names present in the decrypted `native-secrets` kv (names only,
    /// never values). Surface for `GET /v/{vid}/secret-keys` so the frontend
    /// can decide which services are "reachable" without paying for an
    /// external-store roundtrip. Populated at unlock; cleared on lock.
    pub native_keys: HashSet<String>,
    /// External stores' LIVE adapters, built once at unlock so `list()`
    /// (`GET /v/{vid}/secret-keys`) and the allow-path lazy fill
    /// (`lazy_fill_external`) can call out without re-decrypting the vault.
    /// Sharing one instance per store for the whole unlocked session is
    /// what makes the adapter's internal OAuth-token cache real (a fresh
    /// instance per call re-mints every time). Sparse — only kinds with an
    /// adapter (today: gcp-secret-manager) populate.
    ///
    /// F-19: the adapter owns the SA private key and zeroizes it on drop,
    /// so lock still scrubs the credential with the rest of the cache.
    pub external_stores:
        HashMap<String, (crate::storage::plaintext::Store, Arc<crate::store::Adapter>)>,
    /// `aux.store_order` filtered to the stores present in
    /// `external_stores`, preserving the vault's resolution order. The lazy
    /// fill walks THIS (first match wins) so external residency can never
    /// disagree with `resolve_value_async`'s store_order semantics.
    pub external_store_order: Vec<String>,
    /// External stores that FAILED to materialise at unlock (bad SA JSON,
    /// missing credentials_item, …): `store_id → sanitised reason`. Fail
    /// loudly: `secret-keys` surfaces these as `store_errors` so a
    /// misconfigured store shows up broken in the console instead of
    /// silently vanishing. Full error goes to the daemon log only (F-20).
    pub external_store_errors: Vec<(String, String)>,
    /// Key NAMES the external stores expose, enumerated in the background
    /// right after unlock (`unlock_vault` spawns one `list()` sweep) and
    /// amended by every successful lazy fill. Registry `connected` and the
    /// `entries` listing read native ∪ THIS, so an external-backed
    /// connection looks connected to agents. Shared slot (`Arc<Mutex<…>>`)
    /// so the background sweep can write back without re-entering the
    /// vault-states lock; names only, never values. Advisory — resolution
    /// authority stays with the adapters (a name missing here still
    /// lazy-fills; a stale name here just shows optimistic status).
    pub external_keys: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// Derived OAuth access_tokens, keyed by service_id. These are the
    /// short-lived bearer values minted by exchanging the long-lived
    /// `refresh_token` (which lives in `entries`) at the provider's
    /// /token endpoint. **Never persisted to vault** — the design says
    /// only the immutable refresh_token enters the vault; the
    /// access_token is derived state that's allowed to evaporate on
    /// lock / daemon restart (next /use just re-mints it).
    ///
    /// `expires_at` tracks the provider-reported expiry (with a 60s
    /// safety margin baked in at insert time). `cache_lookup`'s
    /// generic eviction doesn't apply here — `oauth_access_lookup`
    /// has its own lazy eviction below.
    ///
    /// Keyed by **`sha256(refresh_token)`** hex (§5): the access token is a pure
    /// function of the refresh token, so keying on the INPUT auto-invalidates on
    /// reconnect / refresh rotation (new refresh → natural miss → fresh mint) and
    /// two accounts never collide for free (different refresh → different key).
    pub oauth_access: HashMap<String, CacheEntry>,
    /// Routing snapshot: `connection_id → { service, hosts }`, taken from
    /// `aux.connections` at unlock (CONNECTION_SCHEMA.md §6). A brokered request
    /// resolves its connection's service through this map (falling back to
    /// `conn` itself when absent — an unconnected service IS its own default
    /// connection). Wiped on lock.
    ///
    /// NOTE on the maps above (`entries`, `allow_secrets`, `oauth_access`,
    /// `ask_grants`): the daemon keys them by **connection_id**, so two
    /// connections of one service never share a cache slot. Policy is likewise
    /// per-connection (`policy.connections.<id>`), while the built-in rules it
    /// merges come from the shared service definition.
    pub connections: HashMap<String, crate::storage::plaintext::Connection>,
    /// The vault's **authorized-agents table** (design §11.1), keyed by `ag_id`
    /// (`derive_id(Agent, pubkey)`). Snapshot of `view.aux.agents` at
    /// unlock/refresh. **Presence = authorized**; an `ag_id` with no entry is not
    /// in the table. Consulted ONLY on the AIK (PoP) path where the daemon knows
    /// the presented `ag_id`; the legacy Basic api-key path (dual-auth window)
    /// carries an api-key prefix, which is never in this `ag_`-keyed table → the
    /// mask lookup misses → the caller falls to the legacy allow (nothing bricks
    /// until bearers retire).
    pub agents: std::collections::BTreeMap<String, crate::storage::plaintext::AgentEntry>,
    /// Custom (per-vault `aux.services`) service definitions, validated at
    /// unlock. Wiped on lock (Default drop). A custom service folds into
    /// discovery like a compiled one and never shadows a built-in id.
    pub custom_services: HashMap<String, crate::service::ServiceDef>,
    /// The vault's `aux.services` entries as stored (valid or not, with their
    /// sources): what `sc service ls` lists and what a `service-add` /
    /// `service-rm` card is computed against at op creation. Wiped on lock.
    pub service_entries: std::collections::BTreeMap<String, crate::service::source::StoredService>,
    /// The names of the vault's console install requests
    /// (`service_request:<id>`), handled on each sync. Wiped on lock.
    pub service_requests: Vec<String>,
}

#[derive(Debug)]
pub enum VaultState {
    Locked,
    Unlocked {
        cache: SecretsCache,
        /// Retained state key `K` (zeroized on drop). Held for the unlocked
        /// session so a sealed blob pulled from cloud sync can be re-decrypted
        /// and the cache refreshed WITHOUT another passkey (Slice 3 realtime
        /// sync — matches 1Password's "vault key resident while unlocked").
        /// Dropped (wiped) on lock/delete along with the rest of this variant.
        state_key: zeroize::Zeroizing<Vec<u8>>,
        /// Unix epoch seconds when this Unlocked state began. Informational
        /// only today (no auto-lock); kept for future audit / debug.
        #[allow(dead_code)]
        unlocked_at: u64,
    },
}

/// A loopback OAuth connect awaiting its `?code&state` redirect. Points a
/// pending `state` (RFC 6749) at the (vault, connection) whose sealed
/// `connecting` entry holds the matching code_verifier, and carries the
/// loopback PORT its provider will redirect to (allowlist-checked at
/// registration — `ServiceRegistry::loopback_allowlist`): 8765 for the
/// canonical callback, 1455 for openai_codex's registered one.
#[derive(Clone)]
pub struct PendingLoopback {
    pub vault_id: String,
    pub conn_id: String,
    pub port: u16,
    inserted_at: std::time::Instant,
}

/// Why the sync did not apply a local change ([`AppState::note_sync`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncNote {
    /// A person's change to the record: it changed elsewhere meanwhile and
    /// was set aside (`sc sync` asks to re-run it).
    ChangedElsewhere(String),
    /// SafeClaw's automatic upgrade of this vault paused on the record: it
    /// changed elsewhere meanwhile; the upgrade retries.
    UpgradePaused(String),
    /// Refused, with why (a full sentence).
    Refused(String),
}

impl SyncNote {
    /// The note as a sentence; `None` for a set-aside change (`sc sync`
    /// words that one itself).
    pub fn sentence(&self) -> Option<String> {
        match self {
            SyncNote::ChangedElsewhere(_) => None,
            SyncNote::UpgradePaused(r) => Some(format!(
                "SafeClaw's automatic upgrade of this vault paused: {} changed elsewhere meanwhile; it retries at the next unlock",
                r
            )),
            SyncNote::Refused(why) => Some(why.clone()),
        }
    }
}

/// The key a pending rotation's note is kept under in the sync notes.
fn rotation_note_key(conn_id: &str) -> String {
    format!("rotation {}", conn_id)
}

/// Process-wide daemon state.
///
/// Any new per-vault field must be classified by the revocation teardown and
/// the exhaustive `revoke_teardown_clears_every_vault_object_and_deletes_only_with_proof` test.
pub struct AppState {
    pub config: Config,
    pub vaults: VaultDir,
    /// Last successful cloud contact per vault (unlock initialises, sync
    /// successes refresh). Drives the shared-vault offline lease (team §7.5):
    /// a daemon cut off from the cloud — network loss OR revoked/offboarded
    /// credentials parking its sync — keeps serving a SHARED vault only for
    /// the lease window.
    pub cloud_contact: Mutex<HashMap<String, std::time::Instant>>,
    /// Server-authoritative vault sharedness (team §4: explicit `kind`, default
    /// private), delivered on the `/blob` sync envelope OUTSIDE the sealed body —
    /// `kind` is a server operational fact, never E2E. `true` = shared, `false` =
    /// private; an ABSENT entry (never synced, or an old server that omits the
    /// field) reads as private via `vault_is_shared` — the fail-safe default so a
    /// personal vault (and any pre-sync state) is never leased. Supersedes the old
    /// "derive shared from the E2E members map" heuristic (review H1). In-memory
    /// only, repopulated on each pull — same restart-softness as `cloud_contact`,
    /// which the offline lease already accepts (it is a soft backstop).
    pub vault_shared: Mutex<HashMap<String, bool>>,
    /// Vaults whose cloud sync returned `SC_UPGRADE_REQUIRED` — this daemon is too
    /// old for their (newer) item format (design 甲). While set, the broker refuses
    /// with [`crate::error::ScCode::UpgradeRequired`] so the AGENT gets an actionable
    /// "run `sc upgrade`" instead of a silent parked-sync failure. In-memory only,
    /// (re)set by the sync path; cleared when a sync succeeds again.
    pub vault_upgrade_required: Mutex<std::collections::HashSet<String>>,
    /// Local changes the sync did not apply, vault → item id → why
    /// ([`SyncNote`]). Shown by `sc sync` and `sc status`; cleared when a
    /// later write or push of that row lands. In-memory only.
    pub sync_conflicts: Mutex<HashMap<String, std::collections::BTreeMap<String, SyncNote>>>,
    /// Vaults whose pull at unlock failed and is being retried in the
    /// background: vault → the last error. Shown by `sc status`.
    pub catch_up_failures: Mutex<HashMap<String, String>>,
    /// Rotated OAuth refresh tokens not stored in the vault yet: vault →
    /// `(connection id, role)` → the new token. The session already uses
    /// each; the next sync stores it again. In-memory only.
    pub pending_rotations: Mutex<
        HashMap<String, std::collections::BTreeMap<(String, String), zeroize::Zeroizing<String>>>,
    >,
    /// Team-edition extension hooks (team-edition §9 open/closed split). The
    /// open build leaves the [`crate::team_hooks::NoopHooks`] default (no team
    /// policy); the closed `safeclaw-ee` overlay injects real ones via
    /// [`AppState::with_team_hooks`]. Serve-time team policy (the offline lease,
    /// etc.) lives behind these, never inline in open core.
    pub team: std::sync::Arc<dyn crate::team_hooks::TeamHooks>,
    /// Vaults whose addressing migration completed locally but whose cloud
    /// `format=2` mark hasn't landed yet — the sync loop drains this after a
    /// successful item push (团队 §8.3: mark only after the rows are up).
    pub pending_format_mark: Mutex<std::collections::HashSet<String>>,
    /// Owner lock-list registrations awaiting delivery: vault → blinded ids of
    /// the config singletons (computed at unlock while K was in hand; the sync
    /// loop POSTs them once for SHARED vaults). §5.15 two-tier write model.
    pub pending_config_ids: Mutex<HashMap<String, Vec<String>>>,
    pub challenges: Mutex<ChallengeStore>,
    pub approvals: Mutex<ApprovalStore>,
    /// Batch-approve root memo (design/batch-approve.md §Daemon verify 5):
    /// `credential_id ‖ "|" ‖ op_ids.join(",")` → (Merkle root over the
    /// batch's stored β's, expiry = max sibling expiry). PURE MEMO of a
    /// function of the daemon's own op store — it only skips the sibling
    /// loads + rebuild on later rows of the same batch; the WebAuthn verify
    /// and every per-row check still run on every row, so a stale or
    /// adversarial entry can never approve anything (a wrong root just fails
    /// signature verification). Bounded: entries expire with their batch and
    /// the map is hard-capped (oldest-expiry evicted).
    pub batch_roots: Mutex<HashMap<String, ([u8; 32], u64)>>,
    pub services: ServiceRegistry,
    pub events: broadcast::Sender<ApprovalEvent>,
    /// Per-vault Locked/Unlocked state. Absent entry = Locked. Lives entirely
    /// in process memory; daemon restart returns all vaults to Locked.
    pub vault_states: Mutex<HashMap<String, VaultState>>,
    /// Vaults explicitly refused by the backend as no longer accessible to
    /// this account. In-memory only: discovery clears a mark on re-add.
    pub revoked_vaults: Mutex<HashSet<String>>,
    /// The hosts each vault anchored the last time it was seen Unlocked
    /// (lowercased, refreshed on every union pass). Kept ACROSS Lock so the
    /// proxy still recognizes — and MITMs — brokered-host traffic while the
    /// vault is locked: a phantom then meets an explicit `vault_locked`
    /// instead of leaking upstream through a blind tunnel. Connections live in
    /// the sealed blob, so this memory is the only locked-time anchor
    /// knowledge; persisted to a cleartext `host-anchors.json` (host names only,
    /// non-sensitive) so it survives a daemon restart while a vault stays locked,
    /// and pruned when the vault is deleted.
    /// Lock order: always `vault_states` first, then this.
    pub last_host_unions: Mutex<HashMap<String, Vec<String>>>,
    /// The canonical JSON of `last_host_unions` last written to disk, so the hot
    /// CONNECT path rewrites the durable cache only when the anchor set actually
    /// changes. Host names only — non-sensitive.
    pub host_unions_persisted: Mutex<String>,
    /// Per-vault audit log (PROTOCOL.md §5.3). Connections opened lazily on
    /// first write/query per vault. Survives daemon restarts — unlike
    /// `approvals` / `vault_states` which are in-memory only.
    pub audits: AuditRegistry,
    /// Daemon HPKE outer-envelope keypair (PROTOCOL.md §4.2.1 M1). Loaded
    /// once at startup, used to open pending-passkey seals (cross-device
    /// add-passkey) and — in future — `[HPKE: MUST]` grant submissions.
    pub sc: crate::crypto::envelope::ScKeyPair,
    /// Per-vault async mutex serializing vault.dat read-modify-write cycles.
    /// Two concurrent approve calls on the same vault both read the pre-write
    /// state and race to rename the tmpfile — the second write wins silently.
    /// Holding this lock for the full approve lifetime prevents that race.
    /// Uses tokio::sync::Mutex so it can be held across await points.
    pub vault_write_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// One live cloud watcher per vault. Entries are retained when a task exits
    /// and replaced by `ensure_watcher` after observing `is_finished()`.
    pub watchers: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    /// Wake cells owned alongside watcher handles so teardown can park a vault
    /// before aborting its task.
    pub watcher_cells: Mutex<HashMap<String, Arc<crate::sync_stream::WakeCell>>>,
    /// Debounce set for account-stream `access` hint probes.
    pub access_probes: Mutex<HashSet<String>>,
    /// Per-vault SSE connection semaphore (cap = MAX_SSE_PER_VAULT).
    /// OwnedSemaphorePermit is stored in each live stream; dropping the
    /// stream drops the permit, automatically releasing the slot.
    pub sse_semaphores: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
    /// This device's standing in the account principal ledger and the account's
    /// admitted agents (DESIGN-principal-ledger-enforced W2/W3/W6). Fail closed:
    /// nothing serves until a decision is loaded ([`crate::principal_ledger::init_gate`]).
    pub ledger: Mutex<crate::principal_ledger::LedgerGate>,
    /// Serializes ledger pulls (the loop and the on-miss re-pull) and stamps the
    /// last one, so an agent miss re-pulls at most once per 2 s. tokio Mutex:
    /// held across the fetch.
    pub ledger_sync: tokio::sync::Mutex<Option<std::time::Instant>>,
    /// Single-flight for the allow-path external-store lazy fill
    /// (`lazy_fill_external`): a burst of first requests on a GCP-backed
    /// connection must resolve ONCE, not once per request. tokio Mutex —
    /// held across the store round-trip so concurrent misses wait for the
    /// in-flight fill and then hit the cache on their re-check.
    pub external_fill_lock: tokio::sync::Mutex<()>,
    /// OAuth connections whose refresh_token was rejected (`invalid_grant`) at
    /// /use — surfaced via `/registry` as `needs_reauth` so the console prompts a
    /// reconnect. Keyed by `(vault_id, connection_id)`. In-memory + self-healing:
    /// cleared on a successful refresh or a fresh connect; a still-dead token
    /// re-marks on the next use.
    pub oauth_reauth_needed: Mutex<std::collections::HashSet<(String, String)>>,
    /// Authorization codes this daemon has already REDEEMED (sha256-hex → when).
    /// An OAuth code is single-use: a stale write (a buggy web Save, a
    /// cross-device echo, or a pull that re-introduces the `connecting` entry
    /// before our success push lands) can resurrect a code we already consumed.
    /// Re-exchanging it earns `invalid_grant`, which the connect state machine
    /// would misread as a terminal failure and use to clobber the live
    /// connection. This is the idempotency key: skip any code already here.
    /// Daemon-local + NEVER synced (so no stale write can revert it); in-memory
    /// (a restart empties it, by which point the cloud has converged). Entries
    /// self-reap after `REDEEMED_CODE_TTL` (codes expire ~10min upstream).
    pub oauth_redeemed_codes: Mutex<HashMap<String, std::time::Instant>>,
    /// Most-recent lifecycle-ceremony op this daemon has open, keyed by
    /// `(vault_id, ceremony_name)` (e.g. `vault-unlock`). When a new ceremony op
    /// is created it supersedes the prior one — the daemon withdraws the stale
    /// op from the relay so the console stops showing "1 approval waiting" after
    /// a `sc unlock` was abandoned + retried. See requester-cancel design.
    pub live_ceremony_ops: Mutex<HashMap<(String, String), String>>,
    /// Random per daemon PROCESS (hex). Rides every op-relay register so the
    /// backend can cancel a previous process's pending rows: the op store is
    /// in-memory and poll tasks spawn only at mint, so a pre-restart row can
    /// never apply (design/approvals-inbox.md D1, restart zombies).
    pub boot_id: String,
    /// The device egress proxy the resident proxy's forward hop tunnels through,
    /// in a swappable cell so `sc proxy set/clear` HOT-reloads it via
    /// `/proxy/reload` — no daemon restart, no vault re-unlock. Shared with the
    /// hudsucker forward connector (see `proxy::upstream`); the reqwest side
    /// swaps via `core::forward::reload_egress_proxy`.
    pub egress_proxy: crate::proxy::upstream::EgressProxyCell,
    /// In-flight loopback OAuth connects awaiting their `?code&state` redirect on
    /// the shared 8765 callback. `state` → the (vault, connection) whose sealed
    /// `connecting` entry holds the matching code_verifier. Populated each sync
    /// tick from a `connecting` entry that carries a `state` and no code yet;
    /// consumed + removed when `auth::loopback` catches the redirect. In-memory +
    /// daemon-local; entries self-reap at the 2h ceiling (`LOOPBACK_PENDING_TTL`)
    /// so an abandoned consent never lingers.
    pub oauth_pending: Mutex<HashMap<String, PendingLoopback>>,
    /// Guard so each on-demand loopback listener runs as a SINGLE shared
    /// instance PER PORT: a port is present while its listener task is live.
    /// `auth::loopback::ensure_running` inserts and spawns only on a fresh
    /// port, so N concurrent connects share ONE listener per port (the daemon
    /// never races itself into a port conflict). A port is removed when its
    /// task exits (idle self-close or bind failure).
    pub oauth_listener_running: Mutex<std::collections::HashSet<u16>>,
    /// Secret values a local CLI deposited for a pending write op
    /// (`connection-add` / `secret-set`), keyed by their salted digest. The op
    /// carries ONLY the digest in `act.scope` — the full op JSON rides to the
    /// cloud op-relay for the grant page, so plaintext values must never be in
    /// it (and the salt keeps a weak value from being brute-forced from the
    /// public digest). Approving the op binds the digest via β; the act then
    /// takes the stash, re-verifies the digest, and writes the values. In-memory
    /// + daemon-local; entries self-reap after their own op-window TTL.
    pub op_payloads: Mutex<HashMap<String, OpPayloadEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultWriteRevoked;

impl std::fmt::Display for VaultWriteRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("vault access revoked")
    }
}

/// One deposited value-set awaiting its op's approval. See
/// [`AppState::op_payloads`].
pub struct OpPayloadEntry {
    inserted_at: std::time::Instant,
    ttl: std::time::Duration,
    nonce: [u8; 32],
    pub values: std::collections::BTreeMap<String, String>,
}

pub(crate) fn host_anchors_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join("host-anchors.json")
}

/// Deterministic (sorted vids + hosts) JSON of the host-anchor union, so an
/// unchanged set has a stable string for the skip-rewrite compare and the file
/// on disk is stable across boots.
fn canonical_unions_json(map: &HashMap<String, Vec<String>>) -> String {
    let sorted: std::collections::BTreeMap<&str, Vec<&str>> = map
        .iter()
        .map(|(k, v)| {
            let mut hs: Vec<&str> = v.iter().map(|s| s.as_str()).collect();
            hs.sort_unstable();
            (k.as_str(), hs)
        })
        .collect();
    serde_json::to_string(&sorted).unwrap_or_default()
}

/// Load the durable host-anchor union (host names only — non-sensitive). Best
/// effort: any read/parse error yields an empty map (falls back to the
/// pre-persistence behaviour of blind-until-unlock).
fn load_host_unions(state_dir: &std::path::Path) -> (HashMap<String, Vec<String>>, String) {
    match std::fs::read(host_anchors_path(state_dir)) {
        Ok(bytes) => match serde_json::from_slice::<HashMap<String, Vec<String>>>(&bytes) {
            Ok(map) => {
                let json = canonical_unions_json(&map);
                (map, json)
            }
            Err(_) => (HashMap::new(), String::new()),
        },
        Err(_) => (HashMap::new(), String::new()),
    }
}

impl AppState {
    /// Inject the closed `safeclaw-ee` team hooks (team-edition §9). The open
    /// build leaves the [`crate::team_hooks::NoopHooks`] default; the overlay's
    /// `main` calls this on the fresh `AppState` before it is wrapped in `Arc`.
    /// Chainable.
    pub fn with_team_hooks(
        mut self,
        hooks: std::sync::Arc<dyn crate::team_hooks::TeamHooks>,
    ) -> Self {
        self.team = hooks;
        self
    }

    pub fn new(config: Config) -> Self {
        let vaults = VaultDir::new(&config.state_dir);
        // Durable host-anchor union (host names only): lets a daemon restarted
        // while a vault is still locked keep MITMing that vault's brokered hosts.
        let (loaded_unions, loaded_unions_json) = load_host_unions(&config.state_dir);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let audits = AuditRegistry::new(vaults.clone());
        let sc = crate::crypto::envelope::ScKeyPair::load_or_generate()
            .expect("sc_sk load/generate failed — check ~/.safeclaw/crypto perms");
        Self {
            config,
            vaults,
            cloud_contact: Mutex::new(HashMap::new()),
            vault_shared: Mutex::new(HashMap::new()),
            vault_upgrade_required: Mutex::new(std::collections::HashSet::new()),
            sync_conflicts: Mutex::new(HashMap::new()),
            catch_up_failures: Mutex::new(HashMap::new()),
            pending_rotations: Mutex::new(HashMap::new()),
            team: std::sync::Arc::new(crate::team_hooks::NoopHooks),
            pending_format_mark: Mutex::new(std::collections::HashSet::new()),
            pending_config_ids: Mutex::new(HashMap::new()),
            challenges: Mutex::new(ChallengeStore::new()),
            approvals: Mutex::new(ApprovalStore::new()),
            batch_roots: Mutex::new(HashMap::new()),
            services: ServiceRegistry::load(),
            events,
            vault_states: Mutex::new(HashMap::new()),
            revoked_vaults: Mutex::new(HashSet::new()),
            last_host_unions: Mutex::new(loaded_unions),
            host_unions_persisted: Mutex::new(loaded_unions_json),
            audits,
            sc,
            vault_write_locks: Mutex::new(HashMap::new()),
            watchers: Mutex::new(HashMap::new()),
            watcher_cells: Mutex::new(HashMap::new()),
            access_probes: Mutex::new(HashSet::new()),
            sse_semaphores: Mutex::new(HashMap::new()),
            ledger: Mutex::new(crate::principal_ledger::LedgerGate::default()),
            ledger_sync: tokio::sync::Mutex::new(None),
            external_fill_lock: tokio::sync::Mutex::new(()),
            oauth_reauth_needed: Mutex::new(std::collections::HashSet::new()),
            oauth_redeemed_codes: Mutex::new(HashMap::new()),
            live_ceremony_ops: Mutex::new(HashMap::new()),
            boot_id: {
                use rand::RngCore as _;
                let mut b = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut b);
                b.iter().map(|x| format!("{:02x}", x)).collect()
            },
            egress_proxy: crate::proxy::upstream::new_cell(),
            oauth_pending: Mutex::new(HashMap::new()),
            oauth_listener_running: Mutex::new(std::collections::HashSet::new()),
            op_payloads: Mutex::new(HashMap::new()),
        }
    }

    /// Stash-lifetime ceiling. Each entry carries its own TTL — the vault's
    /// approval window + slack (see op_payload.rs), so the stash strictly
    /// outlives every moment its op is still approvable. The "user approved
    /// but the deposited value had already expired" failure was exactly a
    /// fixed 300s here under a longer op window; per-entry TTLs from the ONE
    /// policy knob make that class structurally impossible. The ceiling only
    /// bounds a pathological policy value.
    const MAX_OP_PAYLOAD_TTL: std::time::Duration = std::time::Duration::from_secs(86_460);
    /// Flood cap. A human runs one `sc connect` at a time; 32 concurrent
    /// pending stashes is already pathological.
    const MAX_OP_PAYLOADS: usize = 32;

    /// Salted commitment over a value-set: `sha256(DS ‖ nonce ‖ canonical(values))`.
    /// BTreeMap serialization is key-sorted, so `to_vec` is canonical.
    fn op_payload_digest(
        nonce: &[u8; 32],
        values: &std::collections::BTreeMap<String, String>,
    ) -> String {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(b"safeclaw/v1/op-payload");
        h.update(nonce);
        h.update(serde_json::to_vec(values).unwrap_or_default());
        h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Deposit a value-set; returns the digest the op's `act.scope` must carry.
    /// `None` when the stash is full (flood guard).
    pub fn op_payload_insert(
        &self,
        values: std::collections::BTreeMap<String, String>,
        ttl: std::time::Duration,
    ) -> Option<String> {
        use rand::RngCore as _;
        let ttl = ttl.min(Self::MAX_OP_PAYLOAD_TTL);
        let mut m = self.op_payloads.lock().unwrap();
        let now = std::time::Instant::now();
        m.retain(|_, e| now.duration_since(e.inserted_at) < e.ttl);
        if m.len() >= Self::MAX_OP_PAYLOADS {
            return None;
        }
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let digest = Self::op_payload_digest(&nonce, &values);
        m.insert(
            digest.clone(),
            OpPayloadEntry {
                inserted_at: now,
                ttl,
                nonce,
                values,
            },
        );
        Some(digest)
    }

    /// The KEY names a live (unexpired) stash holds, without consuming it or
    /// exposing a value: the mint-time card reads which keys an op writes.
    pub fn op_payload_keys(&self, digest: &str) -> Option<Vec<String>> {
        let m = self.op_payloads.lock().unwrap();
        let entry = m.get(digest)?;
        if entry.inserted_at.elapsed() >= entry.ttl {
            return None;
        }
        Some(entry.values.keys().cloned().collect())
    }

    /// Consume the stash for an approved op. Single-use (removed on take);
    /// expired entries and digest mismatches (defense-in-depth recompute)
    /// yield `None` — the caller fails the act closed.
    pub fn op_payload_take(
        &self,
        digest: &str,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        let entry = self.op_payloads.lock().unwrap().remove(digest)?;
        if entry.inserted_at.elapsed() >= entry.ttl {
            return None;
        }
        if Self::op_payload_digest(&entry.nonce, &entry.values) != digest {
            return None;
        }
        Some(entry.values)
    }

    /// Publish the ledger standing. Anything but `Open` evicts K from every
    /// vault at once (park / lock / wipe); data stays on disk.
    pub fn set_ledger(&self, gate: crate::principal_ledger::LedgerGate) {
        let open = gate.device == crate::principal_ledger::DeviceGate::Open;
        *self.ledger.lock().unwrap() = gate;
        if !open {
            let mut states = self.vault_states.lock().unwrap();
            for st in states.values_mut() {
                *st = VaultState::Locked;
            }
        }
    }

    /// Why this device may not unlock or broker right now (the ledger standing),
    /// or `None` when it is admitted and within the lease.
    pub fn ledger_refusal(&self) -> Option<crate::error::AppError> {
        use crate::principal_ledger::DeviceGate;
        match self.ledger.lock().unwrap().device {
            DeviceGate::Open => None,
            DeviceGate::NotAdmitted => Some(crate::error::AppError::DeviceNotAdmitted),
            DeviceGate::Stale => Some(crate::error::AppError::LedgerStale),
            DeviceGate::Revoked => Some(crate::error::AppError::LedgerDeviceRevoked),
        }
    }

    /// Does the account ledger admit agent `agent_id` (latest event an admit)?
    /// `false` with no verified decision (fail closed).
    pub fn agent_admitted(&self, agent_id: &str) -> bool {
        self.ledger
            .lock()
            .unwrap()
            .agents
            .as_ref()
            .is_some_and(|a| a.contains(agent_id))
    }

    /// Tests: an admitted, in-lease device with these admitted agents.
    #[cfg(test)]
    pub fn open_ledger_for_tests(&self, agents: &[&str]) {
        self.set_ledger(crate::principal_ledger::LedgerGate {
            device: crate::principal_ledger::DeviceGate::Open,
            agents: Some(agents.iter().map(|s| s.to_string()).collect()),
        });
    }

    /// TTL for the redeemed-code ledger. OAuth authorization codes expire
    /// ~10min after issue; 15min covers clock skew, then entries self-reap.
    const REDEEMED_CODE_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

    /// Record that this daemon successfully redeemed `code` — the idempotency
    /// key that stops a stale re-introduction from re-exchanging it. See
    /// [`Self::oauth_redeemed_codes`].
    pub fn note_code_redeemed(&self, code: &str) {
        let mut m = self.oauth_redeemed_codes.lock().unwrap();
        Self::reap_redeemed(&mut m);
        m.insert(crate::api_key::sha256_hex(code), std::time::Instant::now());
    }

    /// True iff this daemon already redeemed `code` — a re-exchange would be a
    /// no-win `invalid_grant`, so the connect machine skips it.
    pub fn was_code_redeemed(&self, code: &str) -> bool {
        let mut m = self.oauth_redeemed_codes.lock().unwrap();
        Self::reap_redeemed(&mut m);
        m.contains_key(&crate::api_key::sha256_hex(code))
    }

    fn reap_redeemed(m: &mut HashMap<String, std::time::Instant>) {
        let now = std::time::Instant::now();
        m.retain(|_, t| now.duration_since(*t) < Self::REDEEMED_CODE_TTL);
    }

    /// Ceiling on how long a loopback connect stays matchable while awaiting its
    /// redirect. The primary driver is "there's an unfinished connect"; this 2h
    /// cap is the backstop so an abandoned consent never keeps the entry alive
    /// forever. Generous on purpose — the listener is benign (`auth::loopback`).
    const LOOPBACK_PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(2 * 60 * 60);

    /// Register (or refresh) a loopback connect awaiting its `?code&state`
    /// redirect. Idempotent — a repeated sync tick re-inserts the same mapping
    /// harmlessly (and refreshes its 2h clock).
    pub fn note_loopback_pending(&self, state: &str, vault_id: &str, conn_id: &str, port: u16) {
        if state.is_empty() {
            return;
        }
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.insert(
            state.to_string(),
            PendingLoopback {
                vault_id: vault_id.to_string(),
                conn_id: conn_id.to_string(),
                port,
                inserted_at: std::time::Instant::now(),
            },
        );
    }

    /// Resolve + REMOVE the (vault, connection) for a caught `state`, or `None`
    /// if unknown/expired. Removal makes the match single-use: a replayed
    /// redirect finds nothing (and gets the bland 404).
    pub fn take_loopback_pending(&self, state: &str) -> Option<PendingLoopback> {
        if state.is_empty() {
            return None;
        }
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.remove(state)
    }

    /// True iff some loopback connect is awaiting a redirect on `port` (reaps
    /// expired entries first). Drives that port's on-demand listener: non-empty
    /// ⇒ keep (or open) its window; empty ⇒ let it self-close.
    pub fn has_loopback_pending_on(&self, port: u16) -> bool {
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        m.values().any(|p| p.port == port)
    }

    /// The distinct ports with a connect currently awaiting a redirect — one
    /// on-demand listener per entry (`auth::loopback::ensure_running`).
    pub fn pending_loopback_ports(&self) -> Vec<u16> {
        let mut m = self.oauth_pending.lock().unwrap();
        Self::reap_loopback(&mut m);
        let mut ports: Vec<u16> = m.values().map(|p| p.port).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Drop any pending-loopback entries for a (vault, connection) that reached a
    /// terminal state (completed / failed), so the on-demand listener can close
    /// promptly instead of lingering to the 2h cap. The auto-catch path already
    /// took its entry out; this covers the paste-fallback path, whose pre-seal
    /// registered an entry no redirect ever consumed.
    pub fn clear_loopback_for_conn(&self, vault_id: &str, conn_id: &str) {
        let mut m = self.oauth_pending.lock().unwrap();
        m.retain(|_, p| !(p.vault_id == vault_id && p.conn_id == conn_id));
    }

    fn reap_loopback(m: &mut HashMap<String, PendingLoopback>) {
        let now = std::time::Instant::now();
        m.retain(|_, p| now.duration_since(p.inserted_at) < Self::LOOPBACK_PENDING_TTL);
    }

    /// Emit an event into the broadcast channel. Silently swallows the "no
    /// active subscribers" case (it's normal — happens before any /try tab is
    /// connected).
    pub fn emit_event(&self, ev: ApprovalEvent) {
        let _ = self.events.send(ev);
    }

    /// True iff this vault is currently Locked (including "never unlocked
    /// since process boot").
    pub fn is_vault_locked(&self, vault_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        !matches!(states.get(vault_id), Some(VaultState::Unlocked { .. }))
    }

    /// True when at least one vault is currently unlocked.
    pub fn has_unlocked_vault(&self) -> bool {
        let states = self.vault_states.lock().unwrap();
        states
            .values()
            .any(|state| matches!(state, VaultState::Unlocked { .. }))
    }

    /// Transition a vault to Unlocked with the given bootstrap cache and the
    /// retained state key `K`. Overwrites any prior state (a fresh unlock
    /// invalidates the previous cache + key).
    pub fn unlock_vault(
        &self,
        vault_id: String,
        cache: SecretsCache,
        state_key: zeroize::Zeroizing<Vec<u8>>,
    ) {
        // Hold the latch through the state insertion. Teardown takes this same
        // mutex before locking the vault, so an unlock either linearizes before
        // revocation (and is immediately locked) or refuses after it.
        let revoked = self.revoked_vaults.lock().unwrap();
        if revoked.contains(&vault_id) {
            tracing::warn!(vault = %vault_id, "unlock refused: vault access was revoked");
            return;
        }
        // A parked or locked device holds no K (I3): a refresh or apply that
        // cloned K before the park must not write it back.
        if self.ledger.lock().unwrap().device != crate::principal_ledger::DeviceGate::Open {
            tracing::warn!(vault = %vault_id, "unlock refused: this device is not admitted to serve");
            return;
        }
        // Team lease clock starts at unlock (a human was just present).
        self.record_cloud_contact(&vault_id);
        let unlocked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Background external-key enumeration: one list() per store so the
        // registry/entries surfaces see the flat namespace without a network
        // call on their read path. The task holds only the shared adapters
        // and the cache's keys slot — never AppState — so a re-unlock that
        // replaces the cache simply orphans this task's slot harmlessly.
        // Handle::try_current keeps plain #[test] callers (no runtime) safe.
        if !cache.external_stores.is_empty() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let adapters: Vec<(String, Arc<crate::store::Adapter>)> = cache
                    .external_stores
                    .iter()
                    .map(|(id, (_, a))| (id.clone(), a.clone()))
                    .collect();
                let slot = cache.external_keys.clone();
                let vid = vault_id.clone();
                rt.spawn(async move {
                    let mut all = std::collections::HashSet::new();
                    for (store_id, adapter) in adapters {
                        match adapter.list().await {
                            Ok(names) => all.extend(names),
                            // Accessor-only SAs can't list — resolution still
                            // works (lazy fill amends the slot on first use).
                            Err(e) => tracing::warn!(vault = %vid, store = %store_id, "external key enumeration failed: {}", e),
                        }
                    }
                    if !all.is_empty() {
                        tracing::info!(vault = %vid, keys = all.len(), "external store keys enumerated");
                        *slot.lock().unwrap() = all;
                    }
                });
            }
        }
        let mut states = self.vault_states.lock().unwrap();
        states.insert(
            vault_id,
            VaultState::Unlocked {
                cache,
                state_key,
                unlocked_at,
            },
        );
        drop(revoked);
    }

    /// Clone the retained state key `K` for an Unlocked vault, or `None` when
    /// the vault is Locked. Used by the cloud-sync refresh to re-decrypt a
    /// freshly-pulled sealed blob without a passkey.
    pub fn cloned_state_key(&self, vault_id: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { state_key, .. }) => Some(state_key.clone()),
            _ => None,
        }
    }

    /// Transition a vault to Locked, zeroing any cached secrets.
    pub fn lock_vault(&self, vault_id: &str) {
        let mut states = self.vault_states.lock().unwrap();
        states.insert(vault_id.to_string(), VaultState::Locked);
    }

    /// Retention setting for this vault's audit log. `None` when the vault
    /// is locked (so the daemon has no view into aux) OR when the user
    /// hasn't configured a retention (keep-forever default). The audit
    /// list handler treats both cases the same: skip prune.
    pub fn audit_retention_days(&self, vault_id: &str) -> Option<u32> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.audit_retention_days,
            _ => None,
        }
    }

    /// Resolve a `connection_id` to its service for an Unlocked vault
    /// (CONNECTION_SCHEMA.md §6). An explicit `aux.connections` entry names its
    /// `service`; otherwise the connection IS its own default — `conn == service`
    /// — which keeps unconnected/API-key services and the default OAuth
    /// connection resolvable. Locked vault → falls back to `conn`
    /// (the caller's locked-gate rejects before any real use).
    pub fn resolve_connection_service(&self, vault_id: &str, conn: &str) -> String {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .connections
                .get(conn)
                .and_then(|c| c.service.clone())
                .unwrap_or_else(|| conn.to_string()),
            _ => conn.to_string(),
        }
    }

    /// A custom (per-vault `aux.services`) service definition, cloned out so no
    /// state lock is held across a forward. `None` when the vault is locked or
    /// the id isn't a custom service.
    pub fn custom_service(
        &self,
        vault_id: &str,
        service_id: &str,
    ) -> Option<crate::service::ServiceDef> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                cache.custom_services.get(service_id).cloned()
            }
            _ => None,
        }
    }

    /// True when `service_id` is an installed service of the unlocked vault
    /// that is not loaded because its owner has installed services off.
    pub fn installed_service_off(&self, vault_id: &str, service_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                !cache.policy.allow_installed_services
                    && cache
                        .service_entries
                        .get(service_id)
                        .is_some_and(|e| e.is_installed())
            }
            _ => false,
        }
    }

    /// The names of an unlocked vault's console install requests.
    pub fn service_request_names(&self, vault_id: &str) -> Vec<String> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.service_requests.clone(),
            _ => Vec::new(),
        }
    }

    /// Look up a cached auth value for `(vault, connection)`. Returns None if
    /// the vault is Locked, the connection isn't bootstrapped/cached, the
    /// vault has never been unlocked, OR the entry's `expires_at` is in
    /// the past (lazy eviction).
    pub fn cache_lookup(&self, vault_id: &str, conn_id: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.entries.get(conn_id)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                // Lazy eviction: TTL-expired entries are dropped here so
                // ask connections correctly fall back to the pending-op flow
                // once their cache window closes.
                cache.entries.remove(conn_id);
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Look up the full `{ secret_name → bytes }` map an allow-level service
    /// needs to resolve its phantoms. Returns `None` if the vault is locked
    /// or the service wasn't bootstrapped with a named-secret set (e.g. an
    /// oauth service, or one resolved post-approval). The allow fast-path
    /// falls back to a single-secret map keyed by the primary in that case.
    pub fn cache_lookup_secrets(
        &self,
        vault_id: &str,
        conn_id: &str,
    ) -> Option<HashMap<String, Vec<u8>>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.allow_secrets.get(conn_id).cloned(),
            _ => None,
        }
    }

    /// Hold a connection's credential value (residency, not authorization).
    /// `expires_at = None` means "live until lock" (allow-level
    /// semantics). `Some(t)` is unix-second expiry. An existing entry's
    /// window is never shortened: the value is the same credential, and
    /// another approval's ledger entry may still need it (`None` wins, else
    /// the later expiry). No-op when the vault is locked at the time of the
    /// call (shouldn't happen on the approve-time write path, but defensive:
    /// `approve_op` runs concurrently with locks).
    pub fn cache_insert(
        &self,
        vault_id: &str,
        conn_id: &str,
        value: Vec<u8>,
        expires_at: Option<u64>,
        agent_prefix: Option<String>,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            let expires_at = match (cache.entries.get(conn_id), expires_at) {
                (Some(prev), Some(t)) => prev.expires_at.map(|p| p.max(t)),
                (_, e) => e,
            };
            cache.entries.insert(
                conn_id.to_string(),
                CacheEntry {
                    value,
                    expires_at,
                    from_bootstrap: false,
                    agent_prefix,
                },
            );
        }
    }

    /// Store a request-bound grant for the request tuple the user's passkey
    /// approved, under the tier that minted it. Overwrites a prior grant for
    /// the same tuple and tier (a fresh tap supersedes). No-op when the vault
    /// is locked.
    ///
    /// See [`ASK_ALWAYS_REPLAY_WINDOW_SECS`] for the single-use expiry.
    #[allow(clippy::too_many_arguments)]
    pub fn op_grant_insert(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        conn_id: &str,
        method: &str,
        host: &str,
        path: &str,
        scope_digest: &str,
        tier: &crate::approval::reuse::BoundTier,
        value: Vec<u8>,
        expires_at: u64,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.op_grants.insert(
                OpGrantKey::new(
                    agent_prefix,
                    conn_id,
                    method,
                    host,
                    path,
                    scope_digest,
                    tier,
                ),
                CacheEntry {
                    value,
                    expires_at: Some(expires_at),
                    from_bootstrap: false,
                    agent_prefix: Some(agent_prefix.to_string()),
                },
            );
        }
    }

    /// Redeem the request-bound grant for exactly this request tuple, minted
    /// under `tier` (the tier this request's own decision yields,
    /// [`crate::approval::reuse::BoundTier::of`]). A request whose (method,
    /// host, path, scope_digest) or tier differs from what the user approved
    /// is a miss and re-prompts, without spending the stored grant; there is
    /// NO fallback to the conn-keyed `entries` (allow residency / plain-ask
    /// leftovers are not grants for a bound action). `None` when locked /
    /// absent / expired.
    ///
    /// The tier decides whether the redeem spends the grant:
    ///   - `ask-always` and a single-use ask: removed on redeem (each request
    ///     re-prompts).
    ///   - `exact` (a scoped `ask`): PEEK. The grant is reused for the SAME
    ///     bound action within its window, but a DIFFERENT action (different
    ///     digest) still misses and re-prompts. (An irreversible/spending action
    ///     should be `ask-always`: a peeked window still lets the identical
    ///     spend repeat, which for money is drainage.)
    #[allow(clippy::too_many_arguments)]
    pub fn op_grant_take(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        conn_id: &str,
        method: &str,
        host: &str,
        path: &str,
        scope_digest: &str,
        tier: &crate::approval::reuse::BoundTier,
    ) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let key = OpGrantKey::new(
            agent_prefix,
            conn_id,
            method,
            host,
            path,
            scope_digest,
            tier,
        );
        // Peek first so an expired entry (of any tier) is dropped and a
        // reusable `exact` grant survives a hit.
        let entry = cache.op_grants.get(&key)?;
        if entry.expires_at.is_some_and(|exp| now >= exp) {
            cache.op_grants.remove(&key);
            return None;
        }
        if tier.single_use() {
            cache.op_grants.remove(&key).map(|e| e.value)
        } else {
            Some(entry.value.clone())
        }
    }

    /// Look up a cached OAuth `access_token` by `sha256(refresh_token)` hex (§5).
    /// Returns `None` if locked, never minted, or past its expiry. Lazily evicts
    /// expired entries (same shape as `cache_lookup`).
    /// The per-vault async write lock — serializes anything that reseals the
    /// vault body (connect exchange, oauth refresh-token rotation) so two writers
    /// can't clobber each other. Same map the connect + sync paths use inline.
    fn vault_write_lock(&self, vault_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.vault_write_locks.lock().unwrap();
        Arc::clone(
            locks
                .entry(vault_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Acquire the per-vault persistence lock and then re-check the revocation
    /// latch, closing the race with a writer that was queued before teardown.
    pub async fn vault_write_guard(
        &self,
        vault_id: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, VaultWriteRevoked> {
        let guard = self.vault_write_lock(vault_id).lock_owned().await;
        if self.is_vault_revoked(vault_id) {
            return Err(VaultWriteRevoked);
        }
        Ok(guard)
    }

    pub fn is_vault_revoked(&self, vault_id: &str) -> bool {
        self.revoked_vaults.lock().unwrap().contains(vault_id)
    }

    pub fn oauth_access_lookup(&self, vault_id: &str, refresh_hash: &str) -> Option<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        let cache = match states.get_mut(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let entry = cache.oauth_access.get(refresh_hash)?;
        if let Some(exp) = entry.expires_at {
            if now >= exp {
                cache.oauth_access.remove(refresh_hash);
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Store a freshly-minted OAuth `access_token` under `sha256(refresh_token)`
    /// hex (§5). `expires_at` should be the provider-reported absolute expiry
    /// minus a small safety margin (the broker uses ~60s) so we refresh before
    /// the upstream would reject. No-op when the vault is locked at the time of
    /// the call.
    pub fn oauth_access_insert(
        &self,
        vault_id: &str,
        refresh_hash: &str,
        value: Vec<u8>,
        expires_at: u64,
    ) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.oauth_access.insert(
                refresh_hash.to_string(),
                CacheEntry {
                    value,
                    expires_at: Some(expires_at),
                    // oauth_access has its own lookup path; the flag is unread here.
                    from_bootstrap: false,
                    agent_prefix: None,
                },
            );
        }
    }

    /// Mark an OAuth connection's refresh_token as dead (invalid_grant at /use).
    /// Surfaced via `/registry` as `needs_reauth` so the console prompts reconnect.
    pub fn oauth_mark_reauth(&self, vault_id: &str, conn_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .insert((vault_id.to_string(), conn_id.to_string()));
    }

    /// Clear a connection's reauth flag (a refresh succeeded).
    pub fn oauth_clear_reauth(&self, vault_id: &str, conn_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .remove(&(vault_id.to_string(), conn_id.to_string()));
    }

    /// True iff `(vault, conn)`'s refresh_token was flagged dead.
    pub fn oauth_needs_reauth(&self, vault_id: &str, conn_id: &str) -> bool {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .contains(&(vault_id.to_string(), conn_id.to_string()))
    }

    /// Clear ALL reauth flags for a vault (a fresh connect just landed; any
    /// still-dead token re-marks on the next /use).
    pub fn oauth_clear_reauth_vault(&self, vault_id: &str) {
        self.oauth_reauth_needed
            .lock()
            .unwrap()
            .retain(|(v, _)| v != vault_id);
    }

    /// [`Self::evaluate_request_decision`] as `(level, matched_rule_id, ttl)`.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_request_policy(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        host: &str,
        body: Option<&str>,
        vars: &crate::core::policy::VarMap,
        has_scope_shape: bool,
    ) -> Option<(
        crate::core::policy::AccessLevel,
        Option<String>,
        Option<u64>,
    )> {
        let (level, by, ttl) = self.evaluate_request_decision(
            vault_id,
            agent_prefix,
            connection_id,
            service_id,
            method,
            path,
            host,
            body,
            vars,
            has_scope_shape,
        )?;
        let id = match by {
            crate::core::policy::DecidedBy::Rule { id, .. } => id,
            crate::core::policy::DecidedBy::Floor => None,
        };
        Some((level, id, ttl))
    }

    /// Evaluate the per-request policy decision for `(vault, connection,
    /// service, method, path, body)`. Returns `None` when the vault is Locked
    /// or never unlocked (caller should treat that as "vault locked").
    ///
    /// Returned tuple: `(effective_level, what decided it, ttl_seconds)`.
    ///
    /// Resolution (PROTOCOL.md §6.4):
    ///   - merge the service's built-in rules with this connection's
    ///     user rules (`cache.policy.connections[conn].rules`),
    ///   - most-restrictive matching rule wins (deny-override), each rule's
    ///     decision being its own `level`,
    ///   - else connection / tag / global default floor, else ask-always,
    ///   - a vault (`aux.services`) definition's policy only tightens: its
    ///     tightening parts ([`crate::service::ServicePolicy::tightening`])
    ///     decide alongside, and the stricter of the decision with and
    ///     without them stands ([`crate::core::policy::stricter`]),
    ///   - **the ask-grant ledger**: an unscoped `Ask` whose unit (the matched
    ///     rule's id and the request's read/write class, or the floor's class)
    ///     has a live entry for
    ///     this `(agent, connection, host)` downgrades to `Allow`. Anything
    ///     else asks (`grant_lookup` never authorizes an ask from residency).
    ///
    /// The vault state lock is held only to copy what the decision needs;
    /// rule matching (a body regex included) runs outside it.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_request_decision(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        host: &str,
        body: Option<&str>,
        vars: &crate::core::policy::VarMap,
        // True when the service declares a `[requests]` scope SHAPE for this
        // path (i.e. the proxy resolved a `RequestScope`), regardless of whether
        // this particular request populated any values. A scoped path binds its
        // approval to the exact request through `op_grants`, so it never
        // consults the value-blind ledger below.
        has_scope_shape: bool,
    ) -> Option<(
        crate::core::policy::AccessLevel,
        crate::core::policy::DecidedBy,
        Option<u64>,
    )> {
        use crate::core::policy::{evaluate_decision, merge_levels, merge_rules, stricter};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // The tag/global floors live in `cache.policy` (the user's
        // `aux.policy` overlaid on compiled defaults at refresh), read live
        // here, so a policy edit is realtime on the next request.
        let (conn_policy, floors, vault_policy) = {
            let states = self.vault_states.lock().unwrap();
            let Some(VaultState::Unlocked { cache, .. }) = states.get(vault_id) else {
                return None;
            };
            (
                cache.policy.connections.get(connection_id).cloned(),
                crate::core::policy::Policy {
                    timeout: cache.policy.timeout,
                    default: cache.policy.default.clone(),
                    categories: cache.policy.categories.clone(),
                    connections: HashMap::new(),
                    allow_installed_services: cache.policy.allow_installed_services,
                },
                cache
                    .custom_services
                    .get(service_id)
                    .and_then(|d| d.policy.clone()),
            )
        };
        // Built-in rules come from the connection's *service* definition; the
        // user's per-connection edits/additions (`aux.policy.connections.
        // <id>.rules`) merge on top, and the user's per-connection default
        // overrides the service's field-wise. Per connection, so two
        // connections of the same service can be policed independently.
        let empty_rules = HashMap::new();
        let user_rules = conn_policy
            .as_ref()
            .map(|c| &c.rules)
            .unwrap_or(&empty_rules);
        let user_default = conn_policy.as_ref().and_then(|c| c.default.as_ref());
        let tags = self.services.service_tags(service_id);
        let decide = |built_in: &[crate::core::policy::PolicyRule],
                      recipe: Option<&crate::core::policy::Levels>| {
            let rules = merge_rules(built_in, user_rules);
            let levels = merge_levels(user_default, recipe);
            evaluate_decision(
                method,
                path,
                body,
                vars,
                Some(&rules),
                levels.as_ref(),
                &floors,
                tags,
            )
        };
        let (level, by, ttl) = match &vault_policy {
            Some(p) => stricter(decide(&[], None), decide(&p.rules, p.defaults.as_ref())),
            None => decide(
                self.services
                    .default_policy_rules(service_id)
                    .unwrap_or(&[]),
                self.services.default_policy_levels(service_id).as_ref(),
            ),
        };

        // Ask-grant ledger: a prior approval of the SAME unit (rule id and
        // class, or floor class) for this agent, connection, and host, not yet expired,
        // downgrades this Ask to Allow. The policy above was re-run on this
        // request, so a rule unit matches only when the same rule (its `when`
        // included) decided again. Expired entries are dropped passively.
        if level == crate::core::policy::AccessLevel::Ask && !has_scope_shape {
            if let Some(unit) = crate::approval::reuse::GrantUnit::of(&by, method) {
                let key = (
                    agent_prefix.to_string(),
                    connection_id.to_string(),
                    host.to_ascii_lowercase(),
                    unit,
                );
                let mut states = self.vault_states.lock().unwrap();
                if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
                    if let Some(&exp) = cache.ask_grants.get(&key) {
                        if exp > now {
                            return Some((crate::core::policy::AccessLevel::Allow, by, ttl));
                        }
                        cache.ask_grants.remove(&key);
                    }
                }
            }
        }

        Some((level, by, ttl))
    }

    /// For a scoped request (`rs`: its matched `[requests]` shape), the first
    /// of this connection's own policy edits that cannot be enforced as
    /// written there, with the reason
    /// ([`crate::core::policy::unenforceable_user_rule`]). The proxy refuses
    /// such a request rather than ask under a rule an approval cannot bind.
    /// The policy is sealed and written by the console, so this is where the
    /// daemon holds the line. `None` when locked or nothing is refused.
    #[allow(clippy::too_many_arguments)]
    pub fn connection_rule_problem(
        &self,
        vault_id: &str,
        connection_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        rs: &crate::service::RequestScope,
    ) -> Option<String> {
        let (user_rules, vault_policy) = {
            let states = self.vault_states.lock().unwrap();
            let Some(VaultState::Unlocked { cache, .. }) = states.get(vault_id) else {
                return None;
            };
            (
                cache.policy.connections.get(connection_id)?.rules.clone(),
                cache
                    .custom_services
                    .get(service_id)
                    .and_then(|d| d.policy.clone()),
            )
        };
        // The rules the edits merge onto: the vault definition's (tightening)
        // rules, else the registry definition's.
        let built_in = match &vault_policy {
            Some(p) => p.rules.as_slice(),
            None => self
                .services
                .default_policy_rules(service_id)
                .unwrap_or(&[]),
        };
        crate::core::policy::unenforceable_user_rule(
            built_in,
            &user_rules,
            method,
            path,
            &rs.shape,
            &rs.declared,
            &rs.binds,
        )
    }

    /// Record an approved `ask` in the ask-grant ledger: `(agent, connection,
    /// host, unit)` until now + `ttl_seconds`. Called once the Use op is
    /// approved (`approve.rs` `DeferredGrant::Ledger`). A fresh approval of
    /// the same key replaces the expiry. No-op when the vault is locked at the
    /// moment of the call.
    pub fn record_ask_grant(
        &self,
        vault_id: &str,
        agent_prefix: &str,
        connection_id: &str,
        host: &str,
        unit: crate::approval::reuse::GrantUnit,
        ttl_seconds: u64,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.ask_grants.insert(
                (
                    agent_prefix.to_string(),
                    connection_id.to_string(),
                    host.to_ascii_lowercase(),
                    unit,
                ),
                now + ttl_seconds,
            );
        }
    }

    /// Keep why a change of `item_id` was not applied (see
    /// [`AppState::sync_conflicts`]).
    pub fn note_sync(&self, vault_id: &str, item_id: &str, note: SyncNote) {
        self.sync_conflicts
            .lock()
            .unwrap()
            .entry(vault_id.to_string())
            .or_default()
            .insert(item_id.to_string(), note);
    }

    /// A write or push of `item_id` landed: an earlier note on it is settled.
    pub fn clear_sync_conflict(&self, vault_id: &str, item_id: &str) {
        let mut all = self.sync_conflicts.lock().unwrap();
        if let Some(m) = all.get_mut(vault_id) {
            m.remove(item_id);
            if m.is_empty() {
                all.remove(vault_id);
            }
        }
    }

    /// The records of `vault_id` whose change was set aside because they
    /// changed elsewhere meanwhile, sorted, each once.
    pub fn sync_conflict_records(&self, vault_id: &str) -> Vec<String> {
        let all = self.sync_conflicts.lock().unwrap();
        let set: std::collections::BTreeSet<String> = all
            .get(vault_id)
            .map(|m| {
                m.values()
                    .filter_map(|n| match n {
                        SyncNote::ChangedElsewhere(r) => Some(r.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        set.into_iter().collect()
    }

    /// Every other note of `vault_id` as a sentence, sorted, each once.
    pub fn sync_note_lines(&self, vault_id: &str) -> Vec<String> {
        let all = self.sync_conflicts.lock().unwrap();
        let set: std::collections::BTreeSet<String> = all
            .get(vault_id)
            .map(|m| m.values().filter_map(SyncNote::sentence).collect())
            .unwrap_or_default();
        set.into_iter().collect()
    }

    /// The pull at unlock of `vault_id` failed with `error`; it is retried.
    pub fn note_catch_up(&self, vault_id: &str, error: &str) {
        self.catch_up_failures
            .lock()
            .unwrap()
            .insert(vault_id.to_string(), error.to_string());
    }

    /// A rotated refresh token of `conn_id` (`role`) was not stored (`why`):
    /// kept to store again, and noted for `sc status` / `sc sync`.
    pub fn note_rotation_pending(
        &self,
        vault_id: &str,
        conn_id: &str,
        role: &str,
        token: &str,
        why: &str,
    ) {
        self.pending_rotations
            .lock()
            .unwrap()
            .entry(vault_id.to_string())
            .or_default()
            .insert(
                (conn_id.to_string(), role.to_string()),
                zeroize::Zeroizing::new(token.to_string()),
            );
        self.note_sync(
            vault_id,
            &rotation_note_key(conn_id),
            SyncNote::Refused(format!(
                "connection {}: the provider's new refresh token could not be stored in the vault ({}); this device uses it, and the next sync stores it again",
                conn_id, why
            )),
        );
    }

    /// The rotated refresh tokens of `vault_id` not stored yet, taken.
    pub fn take_pending_rotations(
        &self,
        vault_id: &str,
    ) -> Vec<((String, String), zeroize::Zeroizing<String>)> {
        self.pending_rotations
            .lock()
            .unwrap()
            .remove(vault_id)
            .map(|m| m.into_iter().collect())
            .unwrap_or_default()
    }

    /// A pending rotation of `conn_id` was stored: its note is settled.
    pub fn clear_rotation_note(&self, vault_id: &str, conn_id: &str) {
        self.clear_sync_conflict(vault_id, &rotation_note_key(conn_id));
    }

    /// Replace a connection's cached credential value `old` with `new`
    /// wherever the unlocked session holds it (its entry, its named secrets).
    /// A no-op when locked or not held.
    pub fn cache_replace_value(&self, vault_id: &str, conn_id: &str, old: &[u8], new: &[u8]) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            if let Some(e) = cache.entries.get_mut(conn_id) {
                if e.value.as_slice() == old {
                    e.value = new.to_vec();
                }
            }
            if let Some(secrets) = cache.allow_secrets.get_mut(conn_id) {
                for v in secrets.values_mut() {
                    if v.as_slice() == old {
                        *v = new.to_vec();
                    }
                }
            }
        }
    }

    /// The pull after unlock of `vault_id` landed (or the vault locked).
    pub fn clear_catch_up(&self, vault_id: &str) {
        self.catch_up_failures.lock().unwrap().remove(vault_id);
    }

    /// Why the changes from the cloud since unlock are not pulled yet.
    pub fn catch_up_failure(&self, vault_id: &str) -> Option<String> {
        self.catch_up_failures
            .lock()
            .unwrap()
            .get(vault_id)
            .cloned()
    }

    /// Record a successful cloud contact for this vault (sync pull/push, or
    /// unlock — a human is present). Feeds the shared-vault offline lease.
    pub fn record_cloud_contact(&self, vault_id: &str) {
        self.cloud_contact
            .lock()
            .unwrap()
            .insert(vault_id.to_string(), std::time::Instant::now());
    }

    /// Seconds since the last cloud contact, `None` if never recorded (treated
    /// as fresh by callers — the entry appears at unlock).
    pub fn cloud_contact_age_secs(&self, vault_id: &str) -> Option<u64> {
        self.cloud_contact
            .lock()
            .unwrap()
            .get(vault_id)
            .map(|t| t.elapsed().as_secs())
    }

    /// Is this vault SHARED? Server-authoritative (team §4): the `kind` the
    /// server stamps on the `/blob` sync envelope, cached in `vault_shared`.
    /// An absent entry (never synced, or an old server without the field) is
    /// PRIVATE — the fail-safe default so a personal vault, and any pre-sync
    /// state, is never leased (review H1 is structurally impossible here: a
    /// private vault's `kind` never reads shared). Independent of unlock state,
    /// unlike the old E2E members-map derivation this replaces.
    pub fn vault_is_shared(&self, vault_id: &str) -> bool {
        *self
            .vault_shared
            .lock()
            .unwrap()
            .get(vault_id)
            .unwrap_or(&false)
    }

    /// Record the server-authoritative sharedness (`kind`) for a vault, from the
    /// `/blob` sync envelope. `true` = shared, `false` = private. Called by the
    /// sync path whenever a fresh envelope carries the field; absent-field pulls
    /// leave the last known value untouched (see `sync::apply_vault_kind`).
    pub fn set_vault_shared(&self, vault_id: &str, shared: bool) {
        self.vault_shared
            .lock()
            .unwrap()
            .insert(vault_id.to_string(), shared);
    }

    /// Eagerly seed `vault_shared` from the known-vaults catalog `kind` (server-
    /// authoritative, mirrored on every discovery, available WITHOUT unlocking a
    /// blob). Called at startup and after discovery so `vault_is_shared` is
    /// reliable before the first serve. DENYLIST normalization (shared iff `kind`
    /// is `team`/`shared`; `personal`/`private`/anything else = not shared) so a
    /// vocabulary drift never strips a personal vault. Only vaults with a known
    /// `kind` are seeded; the signed-envelope path still refreshes the live value.
    pub fn hydrate_shared_from_catalog(&self) {
        for kv in crate::cli::active::known_vaults() {
            if kv.kind.is_some() {
                self.set_vault_shared(&kv.vault, Self::kind_str_is_shared(kv.kind.as_deref()));
            }
        }
    }

    /// DENYLIST normalization of a server `kind` string to sharedness: shared iff
    /// `kind` is `team` or `shared` (case-insensitive); `personal` / `private` /
    /// `None` / anything else = NOT shared, so a vocabulary drift or a renamed kind
    /// never strips a personal vault from serving. Bridges the two `kind`
    /// vocabularies (discovery `personal/team/shared`, blob envelope `shared/private`).
    pub fn kind_str_is_shared(kind: Option<&str>) -> bool {
        matches!(
            kind.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
            Some("team") | Some("shared")
        )
    }

    /// Mark (or clear) a vault as needing a daemon upgrade — the cloud returned
    /// `SC_UPGRADE_REQUIRED` for its sync (design 甲). Set by the sync path on that
    /// signal, cleared on a successful sync. The broker reads it to fail loudly with
    /// an actionable "run `sc upgrade`" to the agent.
    pub fn set_vault_upgrade_required(&self, vault_id: &str, required: bool) {
        let mut set = self.vault_upgrade_required.lock().unwrap();
        if required {
            set.insert(vault_id.to_string());
        } else {
            set.remove(vault_id);
        }
    }

    /// Is this vault flagged `SC_UPGRADE_REQUIRED` (daemon too old for its format)?
    pub fn is_vault_upgrade_required(&self, vault_id: &str) -> bool {
        self.vault_upgrade_required
            .lock()
            .unwrap()
            .contains(vault_id)
    }

    /// Does this vault's reach mask let `agent_id` use `connection_id`?
    /// (team §8.1 — ONE pipeline: the proxy deny, the registry annotation and
    /// GET /vaults all read THIS.) The verdict:
    ///   - `Some(false)` — the agent IS in the authorized-agents table and its
    ///     mask denies this connection (the only denial the proxy acts on).
    ///   - `Some(true)` — in the table, mask allows.
    ///   - `None` — vault locked, OR `agent_id` is not in the `ag_`-keyed table.
    ///     The caller treats `None` as "no mask restriction" (allow): this is the
    ///     legacy Basic-auth path (api-key prefix, never in an `ag_`-keyed table)
    ///     during the dual-auth window. True fail-closed ("not in table = deny")
    ///     is enforced by the AIK proxy path once bearers retire (§11.6).
    pub fn agent_mask_allows(
        &self,
        vault_id: &str,
        agent_id: &str,
        connection_id: &str,
    ) -> Option<bool> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .agents
                .get(agent_id)
                .map(|e| e.connections.allows(connection_id)),
            _ => None,
        }
    }

    /// Is `agent_id` present in this vault's authorized-agents table (§11)?
    /// Presence = authorized: the UIK-signed `ag_`-keyed table is the daemon's
    /// only authz source, and dropping a row is the revoke. Used by the hop-A AIK
    /// PoP proxy path to decide whether a crypto-verified `ag_…` may use this
    /// vault at all — distinct from [`agent_mask_allows`], which only restricts
    /// WHICH connections an already-authorized agent may reach. `false` when the
    /// vault is locked or the agent isn't in the table (fail-closed — the AIK path
    /// is opt-in and dual-authed with the legacy api-key, so this never bricks a
    /// legacy agent, whose api-key prefix simply isn't an `ag_` and takes the
    /// hash-set path instead).
    pub fn agent_is_authorized(&self, vault_id: &str, agent_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.agents.contains_key(agent_id),
            _ => false,
        }
    }

    /// Is `agent_id` present in the authorized-agents table of ANY currently
    /// UNLOCKED vault this daemon holds (§11)? The ACCOUNT-scoped check for the
    /// api-face reads (registry / op-poll / `/vaults`) — those aren't tied to a
    /// single vault, so a hop-A AIK PoP that proves possession of `ag_…` is a
    /// valid agent of this account for those cross-vault reads iff it's
    /// authorized on at least one vault. `false` if no unlocked vault authorizes
    /// it (fail-closed; dual-auth with the legacy api-key covers the transition).
    pub fn agent_is_authorized_any(&self, agent_id: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        states.values().any(|s| match s {
            VaultState::Unlocked { cache, .. } => cache.agents.contains_key(agent_id),
            _ => false,
        })
    }

    /// Which of `candidates` this agent is ALLOWED to reach in this vault —
    /// evaluated through `AgentMask::allows` so the blacklist and `All` resolve
    /// identically (team §8.1 ONE pipeline: same verdict as the proxy deny).
    /// `Some(set)` = the subset of `candidates` reachable under this agent's mask;
    /// `None` = vault locked OR `agent_id` is not in the authorized-agents table
    /// (the caller masks nothing — the legacy allow of the dual-auth window, since
    /// a legacy api-key prefix is never in the `ag_`-keyed table). Used by the
    /// registry/vaults surfaces to annotate rows without N lock round-trips.
    pub fn agent_allowed_connections(
        &self,
        vault_id: &str,
        agent_id: &str,
        candidates: &[String],
    ) -> Option<Vec<String>> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.agents.get(agent_id).map(|entry| {
                candidates
                    .iter()
                    .filter(|id| entry.connections.allows(id))
                    .cloned()
                    .collect()
            }),
            _ => None,
        }
    }

    /// The approval-hold window (seconds): how long a pending `ask` op waits
    /// for the passkey gesture before it expires. This is the user's
    /// `aux.policy.timeout` ("Approval timeout" in the console), or a 30-minute
    /// default. THE one approval window (SSOT): op.rs stamps it onto every
    /// ceremony op, the broker ask path mints with it, the op-payload stash
    /// and the relay poll budget derive from it. DISTINCT from the post-approval `ask`-once grant window (the
    /// rule/floor `ttl`) — a long grant window must not stretch the deadline the
    /// user has to actually approve. Falls back to the default when the vault is
    /// locked or sets no timeout.
    pub fn policy_approval_hold(&self, vault_id: &str) -> u64 {
        const DEFAULT_APPROVAL_HOLD: u64 = 1800;
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => {
                cache.policy.timeout.unwrap_or(DEFAULT_APPROVAL_HOLD)
            }
            _ => DEFAULT_APPROVAL_HOLD,
        }
    }

    // ── Proxy-facing accessors (resident phantom-only proxy) ─────────────────

    /// Clone a connection record out of the unlocked routing snapshot. `None`
    /// when the vault is Locked or the connection id is unknown.
    /// All connections of one vault (id → record), empty when locked. Used by
    /// the agent-face `/vaults` index.
    pub fn connections_snapshot(
        &self,
        vault_id: &str,
    ) -> Vec<(String, crate::storage::plaintext::Connection)> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache
                .connections
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn connection_snapshot(
        &self,
        vault_id: &str,
        conn: &str,
    ) -> Option<crate::storage::plaintext::Connection> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.connections.get(conn).cloned(),
            _ => None,
        }
    }

    /// Snapshot this vault's per-vault custom (`aux.services`) definitions from
    /// the unlocked cache. The OAuth connect-finisher resolves a custom service's
    /// exchange config against these — the global `self.services` registry holds
    /// built-ins only. Empty when the vault is Locked or none are authored.
    pub fn custom_services_snapshot(
        &self,
        vault_id: &str,
    ) -> std::collections::HashMap<String, crate::service::ServiceDef> {
        let states = self.vault_states.lock().unwrap();
        match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache.custom_services.clone(),
            _ => Default::default(),
        }
    }

    /// The exact FQDNs a connection's credential may egress to, resolved
    /// through the compiled registry and the vault's custom services. `None`
    /// when the vault is Locked or the connection id is unknown.
    pub fn resolved_hosts_for(&self, vault_id: &str, conn: &str) -> Option<Vec<String>> {
        let states = self.vault_states.lock().unwrap();
        let cache = match states.get(vault_id) {
            Some(VaultState::Unlocked { cache, .. }) => cache,
            _ => return None,
        };
        let conn_rec = cache.connections.get(conn)?;
        let def = conn_rec.service.as_deref().and_then(|s| {
            // custom-FIRST (see proxy::handler)
            cache
                .custom_services
                .get(s)
                .cloned()
                .or_else(|| self.services.get(s).cloned())
        });
        Some(crate::core::host::resolved_hosts(conn_rec, def.as_ref()))
    }

    /// True iff `host` is in the union of `resolved_hosts` over the connections
    /// of all unlocked vaults, OR in a locked vault's remembered union
    /// (`last_host_unions`). Decides MITM-vs-blind-tunnel at CONNECT time: only
    /// hosts a connection anchors are decrypted; everything else is a blind
    /// tunnel. Including locked vaults' last-known anchors means a phantom sent
    /// while locked reaches `pipeline`'s explicit `vault_locked` refusal instead
    /// of tunneling to the upstream literally; phantom-less traffic to those
    /// hosts still forwards untouched. Not vid-scoped on purpose — we MITM (and
    /// can return a precise error) even when the CONNECT's vid userinfo is
    /// wrong or absent.
    pub fn host_in_any_known_union(&self, host: &str) -> bool {
        let states = self.vault_states.lock().unwrap();
        let mut remembered = self.last_host_unions.lock().unwrap();
        let mut hit = false;
        // Unlocked vaults are authoritative; refresh each one's remembered
        // union in the same pass so it is current whenever the vault locks.
        for (vid, st) in states.iter() {
            let VaultState::Unlocked { cache, .. } = st else {
                continue;
            };
            let mut hosts: Vec<String> = Vec::new();
            for conn_rec in cache.connections.values() {
                let def = conn_rec.service.as_deref().and_then(|s| {
                    // custom-FIRST (see proxy::handler)
                    cache
                        .custom_services
                        .get(s)
                        .cloned()
                        .or_else(|| self.services.get(s).cloned())
                });
                for h in crate::core::host::resolved_hosts(conn_rec, def.as_ref()) {
                    hosts.push(h.to_ascii_lowercase());
                }
            }
            hosts.sort_unstable();
            hosts.dedup();
            if hosts
                .iter()
                .any(|h| crate::core::host::host_anchor_matches(host, h))
            {
                hit = true;
            }
            remembered.insert(vid.clone(), hosts);
        }
        // Forget vaults that no longer exist so the durable cache never grows
        // stale/unbounded, then persist (host names only — non-sensitive) so the
        // union survives a daemon restart while a vault stays locked.
        remembered.retain(|vid, _| states.contains_key(vid.as_str()));
        {
            let json = canonical_unions_json(&remembered);
            let mut persisted = self.host_unions_persisted.lock().unwrap();
            if *persisted != json {
                if let Err(e) =
                    std::fs::write(host_anchors_path(&self.config.state_dir), json.as_bytes())
                {
                    tracing::warn!("proxy: persist host-anchors failed: {}", e);
                } else {
                    *persisted = json;
                }
            }
        }
        if hit {
            return true;
        }
        // Locked (or never-unlocked-this-boot) vaults: last-known anchors.
        for (vid, hosts) in remembered.iter() {
            if matches!(states.get(vid.as_str()), Some(VaultState::Unlocked { .. })) {
                continue;
            }
            if hosts
                .iter()
                .any(|h| crate::core::host::host_anchor_matches(host, h))
            {
                return true;
            }
        }
        false
    }

    /// Session-level host widen (component C partial): append an exact FQDN to a
    /// connection's anchored hosts in the unlocked routing snapshot so the
    /// agent's retried request passes the anchor. Durable persistence into
    /// `aux.connections` is a separate write (see BUILD_NOTES). No-op when the
    /// vault is Locked or the connection is unknown.
    pub fn widen_connection_host(&self, vault_id: &str, conn: &str, host: &str) {
        let mut states = self.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            if let Some(conn_rec) = cache.connections.get_mut(conn) {
                let hosts = conn_rec.hosts.get_or_insert_with(Vec::new);
                if !hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                    hosts.push(host.to_string());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    /// The ask-always tier (single-use).
    fn aa() -> crate::approval::reuse::BoundTier {
        crate::approval::reuse::BoundTier::AskAlways
    }

    /// A scoped ask's `exact` tier (peeked), here under the write floor.
    fn ex() -> crate::approval::reuse::BoundTier {
        use crate::approval::reuse::{BoundTier, Class, GrantUnit};
        BoundTier::Exact(GrantUnit::Floor(Class::Write))
    }

    fn test_state() -> AppState {
        let cfg = Config {
            state_dir: PathBuf::from(format!("/tmp/safeclaw-test-{}", std::process::id())),
            port: 0,
            proxy_port: 0,
            listen: "127.0.0.1".into(),
            origin: "http://localhost".into(),
            relying_party: crate::passkey::webauthn::RelyingParty::exact(
                "http://localhost",
                "localhost",
            ),
            admin_key: None,
            relay_url: None,
            body_cap: crate::config::DEFAULT_BODY_CAP,
        };
        {
            let s = AppState::new(cfg);
            s.open_ledger_for_tests(&[]);
            s
        }
    }

    #[test]
    fn a_parked_device_never_gets_k_back() {
        let s = test_state();
        s.set_ledger(crate::principal_ledger::LedgerGate::default()); // parked
        s.unlock_vault(
            "v".into(),
            SecretsCache::default(),
            zeroize::Zeroizing::new(vec![7u8; 32]),
        );
        assert!(
            s.is_vault_locked("v"),
            "a refresh that cloned K before the park must not reinstall it"
        );
        s.open_ledger_for_tests(&[]);
        s.unlock_vault(
            "v".into(),
            SecretsCache::default(),
            zeroize::Zeroizing::new(vec![7u8; 32]),
        );
        assert!(!s.is_vault_locked("v"));
    }

    #[test]
    fn kind_str_is_shared_is_a_denylist() {
        // Shared iff team/shared (case- and space-tolerant).
        assert!(AppState::kind_str_is_shared(Some("team")));
        assert!(AppState::kind_str_is_shared(Some("shared")));
        assert!(AppState::kind_str_is_shared(Some("  TEAM ")));
        // Everything else (incl. unknown / None) is NOT shared, so a personal
        // vault is never stripped from serving by a vocabulary drift.
        assert!(!AppState::kind_str_is_shared(Some("personal")));
        assert!(!AppState::kind_str_is_shared(Some("private")));
        assert!(!AppState::kind_str_is_shared(Some("solo")));
        assert!(!AppState::kind_str_is_shared(None));
    }

    #[test]
    fn default_build_is_personal_edition() {
        // The default build wires NoopHooks: the open-source PERSONAL edition,
        // which does not serve team vaults. The sync path leaves SHARED vaults to
        // the official build (see `build_serves_shared` / `leave_shared_to_official`
        // in sync.rs); the official build's EeHooks override this to `true`.
        assert!(!test_state().team.serves_shared_vaults());
    }

    /// The op-payload stash is single-use and digest-verified: a deposit is
    /// retrievable exactly once by its returned digest, and an unknown digest
    /// (wrong, replayed, or post-restart) fails closed.
    #[test]
    fn op_payload_deposit_is_single_use_and_digest_bound() {
        let state = test_state();
        let mut values = std::collections::BTreeMap::new();
        values.insert("MIMO_API_TOKEN".to_string(), "s3cret".to_string());
        let digest = state
            .op_payload_insert(values.clone(), std::time::Duration::from_secs(300))
            .expect("stash slot");
        // Two deposits of the SAME values must not collide (fresh salt each).
        let digest2 = state
            .op_payload_insert(values.clone(), std::time::Duration::from_secs(300))
            .expect("stash slot");
        assert_ne!(digest, digest2, "salted digests must differ per deposit");
        assert_eq!(state.op_payload_take(&digest), Some(values));
        assert_eq!(state.op_payload_take(&digest), None, "single-use");
        assert_eq!(state.op_payload_take("deadbeef"), None, "unknown digest");
    }

    fn unlock_with_empty_cache(state: &AppState, vault_id: &str) {
        state.unlock_vault(
            vault_id.to_string(),
            SecretsCache::default(),
            zeroize::Zeroizing::new(Vec::new()),
        );
    }

    /// Directly seed a bootstrap-resident entry (what `bootstrap_cache_from_view`
    /// produces for an allow-read connection) — there's no public setter since
    /// only unlock writes these.
    fn insert_bootstrap(state: &AppState, vault_id: &str, conn: &str, value: &[u8]) {
        let mut states = state.vault_states.lock().unwrap();
        if let Some(VaultState::Unlocked { cache, .. }) = states.get_mut(vault_id) {
            cache.entries.insert(
                conn.to_string(),
                CacheEntry {
                    value: value.to_vec(),
                    expires_at: None,
                    from_bootstrap: true,
                    agent_prefix: None,
                },
            );
        }
    }

    #[test]
    fn bootstrap_entry_serves_allow_but_never_ask_paths() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        insert_bootstrap(&state, "v1", "github", b"tok");
        use crate::core::policy::AccessLevel;
        let lookup = |level| {
            crate::proxy::handler::grant_lookup(
                &state,
                "v1",
                "agA",
                "github",
                level,
                &crate::core::policy::DecidedBy::Floor,
                "GET",
                "api.github.com",
                "/user",
                "",
                false,
            )
            .0
        };
        // allow fast-path uses the residency…
        assert_eq!(state.cache_lookup("v1", "github"), Some(b"tok".to_vec()));
        assert_eq!(lookup(AccessLevel::Allow), Some(b"tok".to_vec()));
        // …but ask must NOT: a resident value is not a grant.
        assert_eq!(lookup(AccessLevel::Ask), None);
        // ask-always never reads `entries` at all — the residency (and even a
        // real conn-keyed ask grant) is invisible to op_grant_take.
        state.cache_insert(
            "v1",
            "github",
            b"granted".to_vec(),
            None,
            Some("agA".into()),
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "github",
                "DELETE",
                "api.github.com",
                "/repos/a/b",
                "",
                &aa()
            ),
            None
        );
        // Nor does an approval-held value authorize an ask: only the
        // ask-grant ledger does (it downgrades the decision before lookup).
        assert_eq!(lookup(AccessLevel::Ask), None);
    }

    #[test]
    fn cache_insert_no_expiry_persists_lookups() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        state.cache_insert("v1", "svc", b"secret".to_vec(), None, Some("agA".into()));
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"secret".to_vec()));
        // Multiple lookups still hit (no eviction without expiry).
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"secret".to_vec()));
    }

    #[test]
    fn op_grant_take_consumes_single_use() {
        // The ask-always captive-portal contract: one approval = one replay.
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            "",
            &aa(),
            b"tok".to_vec(),
            far,
        );
        // First take returns the value …
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                &aa()
            ),
            Some(b"tok".to_vec())
        );
        // … and removes it: a second take misses, and nothing leaked into the
        // conn-keyed entries for the allow/ask paths to find.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                &aa()
            ),
            None
        );
        assert_eq!(state.cache_lookup("v1", "svc"), None);
    }

    /// Security regression (the $80/$180 hole): an ask-always grant is bound
    /// to the REQUEST the user approved. A replay whose method, host, or path
    /// differs must miss — and the miss must NOT consume the stored grant, so
    /// the legitimate replay still works afterwards.
    #[test]
    fn op_grant_take_is_request_bound() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            "",
            &aa(),
            b"tok".to_vec(),
            far,
        );
        // Different path / method / host / connection → all miss.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/refund",
                "",
                &aa()
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "DELETE",
                "api.x.com",
                "/v2/purchase",
                "",
                &aa()
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.y.com",
                "/v2/purchase",
                "",
                &aa()
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "other",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                &aa()
            ),
            None
        );
        // Host comparison is case-insensitive (hosts are lowercased at insert).
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "API.X.COM",
                "/v2/purchase",
                "",
                &aa()
            ),
            Some(b"tok".to_vec())
        );
    }

    /// Op-agent binding (team §C1): every grant surface is keyed by the agent
    /// the approval was minted for. Agent B holding a perfectly valid key must
    /// never redeem/ride agent A's approval — and B's miss must not consume
    /// A's grant.
    #[test]
    fn grants_are_agent_bound_across_all_three_surfaces() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;

        // (1) ask-always / scoped op_grants.
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            "",
            &aa(),
            b"tok".to_vec(),
            far,
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agB",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                &aa()
            ),
            None,
            "agent B cannot redeem A's grant"
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                "",
                &aa()
            ),
            Some(b"tok".to_vec()),
            "B's miss must not have consumed A's grant"
        );

        // (2) the ask-grant ledger: recorded for A, B still re-prompts.
        let unit = crate::approval::reuse::GrantUnit::Rule(
            "read".into(),
            crate::approval::reuse::Class::Read,
        );
        state.record_ask_grant("v1", "agA", "gh", "H.com", unit.clone(), 60);
        {
            let states = state.vault_states.lock().unwrap();
            if let Some(VaultState::Unlocked { cache, .. }) = states.get("v1") {
                let key_a = (
                    "agA".to_string(),
                    "gh".to_string(),
                    "h.com".to_string(),
                    unit.clone(),
                );
                let mut key_b = key_a.clone();
                key_b.0 = "agB".to_string();
                assert!(cache.ask_grants.contains_key(&key_a));
                assert!(!cache.ask_grants.contains_key(&key_b));
            } else {
                panic!("vault not unlocked");
            }
        }
    }

    #[test]
    fn op_grant_take_honors_expiry() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/p",
            "",
            &aa(),
            b"stale".to_vec(),
            0,
        );
        // Expired grant is not returned (and is consumed/dropped).
        assert_eq!(
            state.op_grant_take("v1", "agA", "svc", "POST", "api.x.com", "/p", "", &aa()),
            None
        );
    }

    /// Phase 2: the scope digest is part of the key. Approving `amount=80`
    /// (digest_80) means a replay whose fields hash to a DIFFERENT digest (the
    /// $180 request) misses — without consuming — so the honest $80 replay still
    /// works afterwards.
    #[test]
    fn op_grant_take_is_scope_digest_bound() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let d80 = crate::service::scope_digest(&[("amount".into(), "80".into())]);
        let d180 = crate::service::scope_digest(&[("amount".into(), "180".into())]);
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/v2/purchase",
            &d80,
            &aa(),
            b"tok".to_vec(),
            far,
        );
        // The tampered ($180) replay misses and does NOT consume…
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                &d180,
                &aa()
            ),
            None
        );
        // …so the honest ($80) replay still succeeds, exactly once.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                &d80,
                &aa()
            ),
            Some(b"tok".to_vec())
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/v2/purchase",
                &d80,
                &aa()
            ),
            None
        );
    }

    /// A scoped `ask` peeks (reuses within its window for the SAME bound
    /// action), while a DIFFERENT bound value still misses — so the request
    /// consent is never a false promise, but the identical action isn't
    /// re-prompted every time (that's the ask-vs-ask-always distinction).
    #[test]
    fn op_grant_take_peek_reuses_same_action_but_not_a_different_one() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        let far = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let d_read = crate::service::scope_digest(&[("q".into(), "alpha".into())]);
        let d_other = crate::service::scope_digest(&[("q".into(), "beta".into())]);
        state.op_grant_insert(
            "v1",
            "agA",
            "svc",
            "POST",
            "api.x.com",
            "/search",
            &d_read,
            &ex(),
            b"tok".to_vec(),
            far,
        );
        // Peek (consume=false) reuses the SAME action any number of times…
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_read,
                &ex()
            ),
            Some(b"tok".to_vec())
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_read,
                &ex()
            ),
            Some(b"tok".to_vec())
        );
        // …but a DIFFERENT bound value misses (re-prompt), without disturbing the grant.
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_other,
                &ex()
            ),
            None
        );
        assert_eq!(
            state.op_grant_take(
                "v1",
                "agA",
                "svc",
                "POST",
                "api.x.com",
                "/search",
                &d_read,
                &ex()
            ),
            Some(b"tok".to_vec())
        );
    }

    #[test]
    fn cache_lookup_evicts_expired_entry() {
        let state = test_state();
        unlock_with_empty_cache(&state, "v1");
        // Already-expired entry.
        state.cache_insert("v1", "svc", b"secret".to_vec(), Some(0), Some("agA".into()));
        assert_eq!(state.cache_lookup("v1", "svc"), None);
        // Subsequent insert with valid TTL should succeed (lazy eviction
        // dropped the stale entry; nothing leaks across).
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        state.cache_insert(
            "v1",
            "svc",
            b"new".to_vec(),
            Some(future),
            Some("agA".into()),
        );
        assert_eq!(state.cache_lookup("v1", "svc"), Some(b"new".to_vec()));
    }

    #[test]
    fn cache_lookup_returns_none_when_locked() {
        let state = test_state();
        // Never unlocked.
        assert_eq!(state.cache_lookup("v1", "svc"), None);
        // Insert into a locked vault should be a no-op too.
        state.cache_insert("v1", "svc", b"x".to_vec(), None, Some("agA".into()));
        assert_eq!(state.cache_lookup("v1", "svc"), None);
    }

    /// The rule-approval RECORD is keyed by (agent, connection, rule, method,
    /// host): a recorded GET approval downgrades only that key's decision.
    /// This pins the policy layer only; what an approval lets the agent reuse
    /// end to end (the held connection value) is pinned by the
    /// `reuse_*` tests in server/handlers/approve.rs.
    #[test]
    fn ask_grant_is_scoped_to_method_and_rule() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Policy, RuleConfig};

        // Inject the test rules as the connection's user rules (level = ask).
        // "gh" has no service definition, so built-in is empty and these are the only rules.
        let ask_rule = |pat: &str| RuleConfig {
            match_pattern: Some(pat.to_string()),
            level: Some(AccessLevel::Ask),
            ttl: Some(60),
            ..Default::default()
        };
        let mut rules = std::collections::HashMap::new();
        rules.insert("read".to_string(), ask_rule("GET /x"));
        rules.insert("write".to_string(), ask_rule("POST /x"));
        let mut policy = Policy::default();
        policy.connections.insert(
            "gh".to_string(),
            ConnectionPolicy {
                default: None,
                rules,
            },
        );

        let state = test_state();
        let vid = "v-scope";
        let mut cache = SecretsCache::default();
        cache.policy = policy;
        state.unlock_vault(vid.to_string(), cache, zeroize::Zeroizing::new(Vec::new()));

        // Baseline: GET resolves to Ask under the "read" rule. (Default
        // connection: connection_id == service_id == "gh".)
        let (lvl, rule, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "GET",
                "/x",
                "api.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(lvl, AccessLevel::Ask);
        assert_eq!(rule.as_deref(), Some("read"));

        // User approves that GET toward host A (rule "read").
        state.record_ask_grant(
            vid,
            "agA",
            "gh",
            "api.gh.com",
            crate::approval::reuse::GrantUnit::Rule(
                "read".into(),
                crate::approval::reuse::Class::Read,
            ),
            60,
        );

        // The same GET toward the same host now fast-paths (the feature works).
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "GET",
                "/x",
                "api.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(lvl, AccessLevel::Allow, "approved GET should fast-path");

        // Same GET/rule toward a DIFFERENT host must NOT fast-path — the grant
        // is host-scoped (E2E-5 oracle: approve host A → call host B → re-ask).
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "GET",
                "/x",
                "evil.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Ask,
            "approving host A must never fast-path host B"
        );

        // A POST is a DIFFERENT verb/rule — the GET approval must not cover it.
        let (lvl, rule, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "gh",
                "gh",
                "POST",
                "/x",
                "api.gh.com",
                None,
                &crate::core::policy::VarMap::new(),
                false, // unscoped rule: coarse connection-window applies
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Ask,
            "approving a GET must never fast-path a POST"
        );
        assert_eq!(rule.as_deref(), Some("write"));
    }

    /// A rule unit matches only when the policy, re-run on the later request,
    /// lands on the SAME rule (`when` included); a floor unit only for its
    /// own class. Both are bound to the agent, connection and host.
    #[test]
    fn ask_grant_ledger_matches_the_rerun_decision() {
        use crate::approval::reuse::{Class, GrantUnit};
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Levels, Policy, RuleConfig};
        let mut rules = std::collections::HashMap::new();
        rules.insert(
            "big".to_string(),
            RuleConfig {
                match_pattern: Some("POST /pay".into()),
                when: Some("vars.amount > 100".into()),
                level: Some(AccessLevel::AskAlways),
                ..Default::default()
            },
        );
        rules.insert(
            "pay".to_string(),
            RuleConfig {
                match_pattern: Some("POST /pay".into()),
                level: Some(AccessLevel::Ask),
                ttl: Some(60),
                ..Default::default()
            },
        );
        let mut policy = Policy::default();
        policy.connections.insert(
            "shop".to_string(),
            ConnectionPolicy {
                default: Some(Levels {
                    read: Some(AccessLevel::Ask),
                    write: Some(AccessLevel::Ask),
                    ttl: Some(300),
                }),
                rules,
            },
        );
        let state = test_state();
        let vid = "v-ledger";
        let cache = SecretsCache {
            policy,
            ..Default::default()
        };
        state.unlock_vault(vid.to_string(), cache, zeroize::Zeroizing::new(Vec::new()));
        let decide = |method: &str, path: &str, amount: Option<&str>| {
            let mut vars = crate::core::policy::VarMap::new();
            if let Some(a) = amount {
                vars.insert("amount".into(), a.into());
            }
            state
                .evaluate_request_decision(
                    vid,
                    "agA",
                    "shop",
                    "shop",
                    method,
                    path,
                    "api.shop.com",
                    None,
                    &vars,
                    false,
                )
                .unwrap()
                .0
        };
        state.record_ask_grant(
            vid,
            "agA",
            "shop",
            "api.shop.com",
            GrantUnit::Rule("pay".into(), Class::Write),
            60,
        );
        assert_eq!(decide("POST", "/pay", Some("50")), AccessLevel::Allow);
        // Same path, but `when` now picks the stricter rule: it asks.
        assert_eq!(decide("POST", "/pay", Some("150")), AccessLevel::AskAlways);
        // The floor is a different unit.
        assert_eq!(decide("POST", "/other", None), AccessLevel::Ask);

        state.record_ask_grant(
            vid,
            "agA",
            "shop",
            "api.shop.com",
            GrantUnit::Floor(Class::Read),
            300,
        );
        assert_eq!(decide("GET", "/a", None), AccessLevel::Allow);
        assert_eq!(
            decide("DELETE", "/a", None),
            AccessLevel::Ask,
            "read never serves a write"
        );
        assert_eq!(
            decide("PUT", "/a", None),
            AccessLevel::Ask,
            "read never serves a write"
        );
    }

    /// A vault (`aux.services`) definition's policy only tightens: its deny
    /// and ask rules and stricter defaults decide alongside the vault's own
    /// policy, the stricter of the two stands, and an `allow` it declares
    /// changes nothing. The owner's per-connection setting still loosens.
    #[test]
    fn vault_definition_policy_only_tightens() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Levels, Policy};
        let src = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_KEY"]
[policy.levels]
read = "allow"
write = "ask"
[[policy.rules]]
method = "DELETE"
path_exact = "/v1/things"
level = "deny"
[[policy.rules]]
method = "POST"
path_exact = "/v1/pay"
level = "allow"
"#;
        let mut aux = std::collections::BTreeMap::new();
        aux.insert("acme".to_string(), src.into());
        let state = test_state();
        let (custom, skipped) = crate::service::vault_custom_services(&aux, true, &state.services);
        assert!(skipped.is_empty(), "{skipped:?}");
        let unlock = |policy: Policy| {
            let cache = SecretsCache {
                policy,
                custom_services: custom.clone(),
                ..Default::default()
            };
            state.unlock_vault("v1".into(), cache, zeroize::Zeroizing::new(Vec::new()));
        };
        let decide = |m: &str, p: &str| {
            state
                .evaluate_request_policy(
                    "v1",
                    "ag",
                    "acme",
                    "acme",
                    m,
                    p,
                    "api.acme.dev",
                    None,
                    &crate::core::policy::VarMap::new(),
                    false,
                )
                .unwrap()
                .0
        };
        // Global floor allow: the deny rule and the write default tighten;
        // the definition's allow rule and read default change nothing.
        unlock(Policy::default());
        assert_eq!(decide("DELETE", "/v1/things"), AccessLevel::Deny);
        assert_eq!(decide("POST", "/v1/pay"), AccessLevel::Ask);
        assert_eq!(decide("GET", "/v1/things"), AccessLevel::Allow);
        // The owner's stricter floor is never loosened by the definition.
        let mut strict = Policy::default();
        strict.default = Some(Levels {
            read: Some(AccessLevel::AskAlways),
            write: Some(AccessLevel::AskAlways),
            ttl: None,
        });
        unlock(strict);
        assert_eq!(decide("POST", "/v1/pay"), AccessLevel::AskAlways);
        assert_eq!(decide("GET", "/v1/things"), AccessLevel::AskAlways);
        assert_eq!(decide("DELETE", "/v1/things"), AccessLevel::Deny);
        // The owner's own per-connection default is consent to loosen.
        let mut owner = Policy::default();
        owner.connections.insert(
            "acme".to_string(),
            ConnectionPolicy {
                default: Some(Levels {
                    read: None,
                    write: Some(AccessLevel::Allow),
                    ttl: None,
                }),
                rules: Default::default(),
            },
        );
        unlock(owner);
        assert_eq!(decide("POST", "/v1/pay"), AccessLevel::Allow);
        assert_eq!(decide("DELETE", "/v1/things"), AccessLevel::Deny);
    }

    /// A connection's own rule edit that decides a scoped request on a field
    /// its approval does not bind (a declared but unscoped var, or the body)
    /// is reported for that connection only; a rule on a bound field is not.
    #[test]
    fn connection_rule_problem_flags_unbound_deciding_fields() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Policy, RuleConfig};
        let def: crate::service::ServiceDef = crate::service::gate::admit_toml(
            r#"
[service]
id = "shop"
name = "Shop"
hosts = ["api.shop.com"]
secrets = ["SHOP_KEY"]
[requests.purchase]
match = "POST /buy"
vars.amount = "/amount"
vars.force  = { in = "query", at = "force" }
scope = ["amount"]
"#,
        )
        .unwrap();
        let rs = def
            .extract_request_scope("POST", "/buy", Some("force=1"), Some(r#"{"amount":5}"#))
            .expect("shape matches");
        let rule = |when: Option<&str>, body: Option<&str>| RuleConfig {
            match_pattern: Some("POST /buy".into()),
            when: when.map(str::to_string),
            body: body.map(crate::core::policy::BodyPattern::lenient),
            level: Some(AccessLevel::Ask),
            ..Default::default()
        };
        let with_rules = |rules: Vec<(&str, RuleConfig)>| {
            let mut p = Policy::default();
            p.connections.insert(
                "shop".to_string(),
                ConnectionPolicy {
                    default: None,
                    rules: rules.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
                },
            );
            let state = test_state();
            let cache = SecretsCache {
                policy: p,
                ..Default::default()
            };
            state.unlock_vault("v1".into(), cache, zeroize::Zeroizing::new(Vec::new()));
            state
        };
        let state = with_rules(vec![("small", rule(Some("vars.amount < 10"), None))]);
        assert_eq!(
            state.connection_rule_problem("v1", "shop", "shop", "POST", "/buy", &rs),
            None
        );
        let state = with_rules(vec![("forced", rule(Some("vars.force == 1"), None))]);
        let e = state
            .connection_rule_problem("v1", "shop", "shop", "POST", "/buy", &rs)
            .expect("unbound deciding field");
        assert!(e.contains("'forced'") && e.contains("vars.force"), "{e}");
        // Another connection of the vault has no such edit.
        assert_eq!(
            state.connection_rule_problem("v1", "shop_2", "shop", "POST", "/buy", &rs),
            None
        );
        let state = with_rules(vec![("bodyish", rule(None, Some("gift")))]);
        assert!(state
            .connection_rule_problem("v1", "shop", "shop", "POST", "/buy", &rs)
            .is_some());
        // A protective deny on the body mints no approval: not refused.
        let state = with_rules(vec![(
            "no_gifts",
            RuleConfig {
                level: Some(AccessLevel::Deny),
                ..rule(None, Some("gift"))
            },
        )]);
        assert_eq!(
            state.connection_rule_problem("v1", "shop", "shop", "POST", "/buy", &rs),
            None
        );
        // Locked: nothing to report (the request fails as locked anyway).
        assert_eq!(
            state.connection_rule_problem("v-none", "shop", "shop", "POST", "/buy", &rs),
            None
        );
    }

    // A path that declares a `[requests]` scope shape must bind its approval
    // per-value (op_grants) and NEVER ride the coarse connection-window
    // downgrade — otherwise approving one value-less (empty-body) ask would let
    // any later value ride it (approve a blank purchase, then spend anything).
    #[test]
    fn scoped_path_never_rides_the_coarse_window() {
        use crate::core::policy::{AccessLevel, ConnectionPolicy, Policy, RuleConfig};

        let mut rules = std::collections::HashMap::new();
        rules.insert(
            "purchase".to_string(),
            RuleConfig {
                match_pattern: Some("POST /buy".to_string()),
                level: Some(AccessLevel::Ask),
                ttl: Some(60),
                ..Default::default()
            },
        );
        let mut policy = Policy::default();
        policy.connections.insert(
            "shop".to_string(),
            ConnectionPolicy {
                default: None,
                rules,
            },
        );
        let state = test_state();
        let vid = "v-scoped";
        let mut cache = SecretsCache::default();
        cache.policy = policy;
        state.unlock_vault(vid.to_string(), cache, zeroize::Zeroizing::new(Vec::new()));

        // A ledger entry for the rule exists (as an unscoped caller's
        // approval would write).
        state.record_ask_grant(
            vid,
            "agA",
            "shop",
            "api.shop.com",
            crate::approval::reuse::GrantUnit::Rule(
                "purchase".into(),
                crate::approval::reuse::Class::Write,
            ),
            60,
        );

        // A scope-less caller still fast-paths — the legitimate coarse window.
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "shop",
                "shop",
                "POST",
                "/buy",
                "api.shop.com",
                None,
                &crate::core::policy::VarMap::new(),
                false,
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Allow,
            "an unscoped rule still uses the window"
        );

        // A SCOPED path must NOT ride that value-blind window — it re-asks so its
        // per-value op_grant binds the amount/merchant.
        let (lvl, _, _) = state
            .evaluate_request_policy(
                vid,
                "agA",
                "shop",
                "shop",
                "POST",
                "/buy",
                "api.shop.com",
                None,
                &crate::core::policy::VarMap::new(),
                true,
            )
            .unwrap();
        assert_eq!(
            lvl,
            AccessLevel::Ask,
            "a scoped path must never fast-path via the coarse window"
        );
    }
}
