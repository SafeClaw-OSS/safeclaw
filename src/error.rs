use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// THE error-code registry — every error SafeClaw raises on any surface
/// (control-plane JSON, proxy text plane, CLI stderr) names exactly one of
/// these. Codes are snake_case and self-describing (an agent never needs a
/// lookup table); `docs/reference/diagnostics.md` is this enum's rendered table and must
/// change in the same commit. Status/action/cause are pure functions of the
/// code so every surface maps an error identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScCode {
    // ── control plane / API face ─────────────────────────────────────────
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    VaultLocked,
    VaultAccessRevoked,
    VaultDeleted,
    RateLimited,
    Internal,
    CaUnavailable,
    // ── proxy plane (credential pipeline) ────────────────────────────────
    AgentKey,
    /// A cryptographically-VALID agent AIK proof-of-possession whose `ag_` is NOT
    /// in this vault's authorized-agents table (design §11): the agent proved its
    /// identity but the user hasn't authorized it here yet. DISTINCT from
    /// `AgentKey` (no / invalid credential) — the fix is a one-click Console
    /// authorize (Agents tab), not a credential change, so it must NEVER read as
    /// "bad key" (that sends the user debugging the wrong thing).
    AgentNotAuthorized,
    /// A cryptographically-valid agent AIK that this machine's paired account
    /// does not have: set up (`sc agent add`) under another SafeClaw account,
    /// or removed from this one (the daemon can't tell which). Checked
    /// before any vault-level check, so it never reads as `agent_not_authorized`
    /// ("not turned on for this vault"), whose fix is a Console toggle; the fix
    /// here is `sc agent add` on this machine.
    AgentNotInAccount,
    AmbiguousPhantom,
    ApprovalNeeded,
    ApprovalRegister,
    /// A batch-approve grant failed BATCH verification (bounds, unknown
    /// sibling op, root mismatch, r/o inequality) — design/batch-approve.md.
    /// RECOVERABLE by re-approving per-op: the relay client re-registers the
    /// op instead of rejecting it, so this must stay a distinct code (the
    /// client switches on it, never on message text).
    BatchVerifyFailed,
    /// A grant signed by a passkey that may not approve THIS op: on a shared
    /// vault only the requester (the member whose daemon raised it) or a vault
    /// admin may approve. RECOVERABLE: the op stays pending and the relay
    /// client re-registers it so the requester or an admin can still approve
    /// (the client switches on this code, never on message text).
    ApproverNotAuthorized,
    /// A grant carrying an unlock secret (`wk_*` / `wrapping_key`) instead of
    /// the vault key + identity signature (grant v3). The approver's root and
    /// `W_c` never leave their browser, so the daemon refuses the form outright
    /// (fail closed). RECOVERABLE: the op stays pending.
    WkRefusedV2,
    /// A grant v3 identity signature (`id` / `id_sig`) that is missing,
    /// malformed, does not verify under `id`'s key, or names someone other
    /// than the person the approving passkey belongs to. RECOVERABLE: the op
    /// stays pending (a relay must not resolve an op with a forged signer).
    GrantIdInvalid,
    /// This device has no valid owner-signed admit over its `dev_ ‖ sc_pk`
    /// (pairing did not complete, or the server served an admit that does
    /// not verify). Fix: pair again with `sc login`.
    DeviceNotAdmitted,
    /// The account principal ledger does not hash to a validly owner-signed
    /// head (a forged or truncated tail). The daemon keeps its prior decision.
    LedgerHeadInvalid,
    /// The account owner revoked this device (a verified revoke in the
    /// head-checked ledger, contract C6/C5). The daemon latches it.
    LedgerDeviceRevoked,
    /// A verified agent AIK whose `ag_` the account ledger does not admit (never
    /// approved, or revoked): refused on every vault, whatever its table lists.
    AgentNotAdmitted,
    /// No verified ledger pull for 7 days (the lease): vaults are locked until
    /// one succeeds. Data stays on disk.
    LedgerStale,
    BrokerBodyLimit,
    EgressUnreachable,
    ExposesUnsupported,
    HostForbidden,
    /// A team reach mask excludes this connection for the calling agent
    /// (team §8.1: visible-but-locked — the connection exists, this agent
    /// is not enabled for it; the responsible member can enable it).
    MaskNotEnabled,
    /// Shared-vault offline lease expired — the daemon has been cut off from
    /// the cloud (network, or revoked membership parking its sync) beyond the
    /// lease window; team credentials stop serving until contact resumes.
    TeamLeaseExpired,
    HostNotAnchored,
    MultiConnection,
    NoVault,
    OauthMint,
    PhantomPlainHttp,
    PhantomUnresolved,
    PolicyDenied,
    RefreshForbidden,
    SecretEncoding,
    StoreUnavailable,
    VaultKeyChanged,
    UnknownConnection,
    UpstreamBody,
    UpstreamError,
    /// The local daemon is too old for a vault it's brokering — the cloud returned
    /// `SC_UPGRADE_REQUIRED` for this vault's sync (a newer item format). The agent
    /// should tell the user to run `sc upgrade`, NOT retry or work around it (the
    /// unified upgrade-required channel; design/agent-device-identity-mtls.md 甲).
    UpgradeRequired,
}

impl ScCode {
    /// `(status, code, title, action, cause)` — the single row this code owns.
    ///
    /// `action` is what the AGENT should do next: `unlock` (have the user
    /// unlock), `approve` (follow the approve URL in the body), `retry`,
    /// `configure` (a machine/daemon knob, the message names it),
    /// `fix_request` (the request itself is wrong), `none` (explicit refusal —
    /// don't work around it, per P2).
    ///
    /// `cause` attributes the failure: `request`, `auth`, `vault`, `policy`,
    /// `config`, `environment` (this machine's network, NOT SafeClaw),
    /// `upstream` (the service side, NOT SafeClaw), `internal`.
    pub fn row(&self) -> (u16, &'static str, &'static str, &'static str, &'static str) {
        use ScCode::*;
        match self {
            BadRequest => (400, "bad_request", "Bad request", "fix_request", "request"),
            Unauthorized => (401, "unauthorized", "Unauthorized", "configure", "auth"),
            Forbidden => (403, "forbidden", "Forbidden", "none", "auth"),
            NotFound => (404, "not_found", "Not found", "fix_request", "request"),
            MethodNotAllowed => (
                405,
                "method_not_allowed",
                "Method not allowed",
                "fix_request",
                "request",
            ),
            Conflict => (409, "conflict", "Conflict", "fix_request", "request"),
            VaultLocked => (423, "vault_locked", "Vault locked", "unlock", "vault"),
            VaultAccessRevoked => (
                403,
                "vault_access_revoked",
                "Vault access revoked",
                "configure",
                "auth",
            ),
            VaultDeleted => (410, "vault_deleted", "Vault deleted", "none", "vault"),
            RateLimited => (429, "rate_limited", "Rate limited", "retry", "request"),
            Internal => (500, "internal", "Internal error", "retry", "internal"),
            CaUnavailable => (500, "ca_unavailable", "CA unavailable", "retry", "internal"),
            AgentKey => (407, "agent_key", "Agent key invalid", "configure", "auth"),
            AgentNotAuthorized => (
                403,
                "agent_not_authorized",
                "Agent not authorized on this vault",
                "none",
                "auth",
            ),
            AgentNotInAccount => (
                403,
                "agent_not_in_account",
                "Agent not registered to this account",
                "configure",
                "auth",
            ),
            AmbiguousPhantom => (
                400,
                "ambiguous_phantom",
                "Ambiguous phantom",
                "fix_request",
                "request",
            ),
            ApprovalNeeded => (
                401,
                "approval_needed",
                "Approval needed",
                "approve",
                "policy",
            ),
            BatchVerifyFailed => (
                409,
                "batch_verify_failed",
                "Batch approval could not be verified",
                "retry",
                "request",
            ),
            ApproverNotAuthorized => (
                403,
                "approver_not_authorized",
                "Only the requester or a vault admin can approve this",
                "none",
                "auth",
            ),
            WkRefusedV2 => (
                400,
                "wk_refused_v2",
                "Approval must deliver the vault key, not an unlock secret",
                "none",
                "request",
            ),
            GrantIdInvalid => (
                403,
                "grant_id_invalid",
                "Approval signature could not be verified",
                "none",
                "auth",
            ),
            DeviceNotAdmitted => (
                403,
                "device_not_admitted",
                "This device needs to be paired again",
                "configure",
                "auth",
            ),
            LedgerHeadInvalid => (
                403,
                "ledger_head_invalid",
                "Device list signature could not be verified",
                "none",
                "auth",
            ),
            LedgerDeviceRevoked => (
                403,
                "ledger_device_revoked",
                "This device was removed from the account",
                "configure",
                "auth",
            ),
            AgentNotAdmitted => (
                403,
                "agent_not_admitted",
                "Agent not admitted to this account",
                "configure",
                "auth",
            ),
            LedgerStale => (
                423,
                "ledger_stale",
                "Locked: account unreachable for 7 days",
                "retry",
                "environment",
            ),
            ApprovalRegister => (
                503,
                "approval_register",
                "Approval registration failed",
                "retry",
                "internal",
            ),
            BrokerBodyLimit => (
                413,
                "broker_body_limit",
                "Body over broker cap",
                "configure",
                "config",
            ),
            EgressUnreachable => (
                502,
                "egress_unreachable",
                "Egress unreachable",
                "configure",
                "environment",
            ),
            ExposesUnsupported => (
                400,
                "exposes_unsupported",
                "Role not mintable",
                "fix_request",
                "request",
            ),
            HostForbidden => (403, "host_forbidden", "Host forbidden", "none", "policy"),
            MaskNotEnabled => (
                403,
                "mask_not_enabled",
                "Connection not enabled for this agent",
                "none",
                "policy",
            ),
            TeamLeaseExpired => (
                403,
                "team_lease_expired",
                "Shared-vault offline lease expired",
                "retry",
                "policy",
            ),
            HostNotAnchored => (
                403,
                "host_not_anchored",
                "Host not anchored",
                "approve",
                "policy",
            ),
            MultiConnection => (
                400,
                "multi_connection",
                "Multiple connections in one request",
                "fix_request",
                "request",
            ),
            NoVault => (403, "no_vault", "No vault bound", "configure", "config"),
            OauthMint => (502, "oauth_mint", "OAuth mint failed", "retry", "upstream"),
            PhantomPlainHttp => (
                400,
                "phantom_plain_http",
                "Phantom over plain HTTP",
                "fix_request",
                "request",
            ),
            PhantomUnresolved => (
                424,
                "phantom_unresolved",
                "Phantom could not be resolved",
                "fix_request",
                "request",
            ),
            PolicyDenied => (403, "policy_denied", "Blocked by policy", "none", "policy"),
            RefreshForbidden => (
                403,
                "refresh_forbidden",
                "Refresh token never leaves the vault",
                "fix_request",
                "policy",
            ),
            SecretEncoding => (
                500,
                "secret_encoding",
                "Credential encoding error",
                "none",
                "internal",
            ),
            StoreUnavailable => (
                502,
                "store_unavailable",
                "External store unavailable",
                "retry",
                "upstream",
            ),
            VaultKeyChanged => (
                409,
                "vault_key_changed",
                "Vault key changed",
                "unlock",
                "vault",
            ),
            UnknownConnection => (
                400,
                "unknown_connection",
                "Unknown connection",
                "fix_request",
                "request",
            ),
            UpstreamBody => (
                502,
                "upstream_body",
                "Body read failed",
                "retry",
                "upstream",
            ),
            UpstreamError => (
                502,
                "upstream_error",
                "Upstream request failed",
                "retry",
                "upstream",
            ),
            UpgradeRequired => (
                426,
                "upgrade_required",
                "SafeClaw needs an update",
                "configure",
                "config",
            ),
        }
    }

    pub fn status(&self) -> u16 {
        self.row().0
    }

    pub fn as_str(&self) -> &'static str {
        self.row().1
    }
}

/// The ONE canonical remediation line for a locked vault — every surface
/// (control 423, proxy 423, CLI) says exactly this, so the agent sees one
/// consistent state and relays one consistent fix.
pub const VAULT_LOCKED_MSG: &str = "vault locked. Run `sc unlock`, then retry";

pub const VAULT_ACCESS_REVOKED_MSG: &str =
    "This device can no longer use this vault: your account was removed from it. Ask a vault admin to add you back.";

pub const VAULT_KEY_CHANGED_MSG: &str = "This connection may have been added after the vault's members changed and its key was replaced. This device doesn't have the new key yet: ask the user to approve `sc unlock`.";

pub const VAULT_KEY_CHANGED_STATUS_MSG: &str = "key changed: this vault's members changed (someone was removed), so it has a new key. Run `sc unlock` once to see what was added since; existing credentials keep working.";

/// The ONE remediation line for [`ScCode::DeviceNotAdmitted`] (the console
/// says the same sentence).
pub const DEVICE_NOT_ADMITTED_MSG: &str = "This device needs to be paired again: run `sc login`.";

pub const DEVICE_ACCOUNT_MISSING_MSG: &str =
    "This device is no longer paired with a SafeClaw account. Run `sc login` to pair it again.";

/// The ONE remediation line for [`ScCode::AgentNotAdmitted`].
pub const AGENT_NOT_ADMITTED_MSG: &str = "This agent isn't admitted to the SafeClaw account this machine is signed in to (never approved, or removed). Run `sc agent add` to set it up again.";

/// The ONE remediation line for [`ScCode::LedgerStale`].
pub const LEDGER_STALE_MSG: &str = "locked: SafeClaw could not reach your account for 7 days. Check this machine's network; vaults unlock again once it reconnects (`sc up`).";

/// The ONE remediation line for [`ScCode::LedgerDeviceRevoked`].
pub const LEDGER_DEVICE_REVOKED_MSG: &str =
    "This device was removed from your SafeClaw account. Run `sc login` to pair it again.";

/// The remediation line for [`ScCode::AgentNotInAccount`] (raised by the cloud
/// op relay; the daemon answers [`ScCode::AgentNotAdmitted`]).
pub const AGENT_NOT_IN_ACCOUNT_MSG: &str = "This agent isn't registered to the SafeClaw account this machine is signed in to. Run `sc agent add` to set it up.";

/// RFC 9457 `application/problem+json` body for a code + detail message.
/// Extension members: `code` / `action` / `cause` (see [`ScCode::row`]),
/// plus legacy `error` / `message` dual-emitted for one transition window
/// (console + older CLIs parse those; remove after both are migrated).
pub fn problem_body(code: ScCode, detail: &str) -> serde_json::Value {
    let (status, code_s, title, action, cause) = code.row();
    json!({
        "type": format!("https://safeclaw.pro/errors/{}", code_s),
        "title": title,
        "status": status,
        "detail": detail,
        "code": code_s,
        "action": action,
        "cause": cause,
        // legacy shape (pre-9457) — dual-emit, do not add new readers
        "error": code_s,
        "message": detail,
    })
}

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound,
    Conflict(String),
    /// Vault is locked (no in-memory key). Distinct from `Conflict` so the agent
    /// can tell "unlock needed → run `sc unlock`" apart from other 409s. HTTP 423.
    VaultLocked,
    /// The cloud explicitly reported that this account is no longer a member.
    VaultAccessRevoked,
    /// The vault has a verified deletion tombstone.
    VaultDeleted,
    TooManyRequests,
    Internal(String),
    /// Batch-approve verification failure (recoverable; see
    /// `ScCode::BatchVerifyFailed`). Never use for per-op apply failures.
    BatchVerify(String),
    /// The grant's signer may not approve this op (see
    /// `ScCode::ApproverNotAuthorized`). The op stays pending.
    ApproverNotAuthorized(String),
    /// A grant delivered an unlock secret instead of the vault key (see
    /// `ScCode::WkRefusedV2`). The op stays pending.
    WkRefused(String),
    /// A grant's identity signature failed (see `ScCode::GrantIdInvalid`).
    /// The op stays pending.
    GrantIdInvalid(String),
    /// This device has no valid admit (see `ScCode::DeviceNotAdmitted`).
    DeviceNotAdmitted,
    /// The account lookup completed and no account names this device.
    DeviceAccountMissing,
    /// The ledger lease ran out (see `ScCode::LedgerStale`).
    LedgerStale,
    /// This device was revoked (see `ScCode::LedgerDeviceRevoked`).
    LedgerDeviceRevoked,
    /// The agent is not admitted by the ledger (see `ScCode::AgentNotAdmitted`).
    AgentNotAdmitted,
}

impl AppError {
    /// The registry code + detail this error projects to. Shared by the axum
    /// `IntoResponse` below AND the hudsucker 23294 API face
    /// (`proxy::api_face`), so both ports map an error identically.
    pub fn code(&self) -> (ScCode, String) {
        match self {
            AppError::BadRequest(msg) => (ScCode::BadRequest, msg.clone()),
            AppError::Unauthorized(msg) => (ScCode::Unauthorized, msg.clone()),
            AppError::Forbidden(msg) => (ScCode::Forbidden, msg.clone()),
            AppError::NotFound => (ScCode::NotFound, "Not found".to_string()),
            AppError::Conflict(msg) => (ScCode::Conflict, msg.clone()),
            AppError::VaultLocked => (ScCode::VaultLocked, VAULT_LOCKED_MSG.to_string()),
            AppError::VaultAccessRevoked => (
                ScCode::VaultAccessRevoked,
                VAULT_ACCESS_REVOKED_MSG.to_string(),
            ),
            AppError::VaultDeleted => (ScCode::VaultDeleted, "This vault was deleted.".to_string()),
            AppError::TooManyRequests => (ScCode::RateLimited, "Rate limit exceeded".to_string()),
            AppError::BatchVerify(msg) => (ScCode::BatchVerifyFailed, msg.clone()),
            AppError::ApproverNotAuthorized(msg) => (ScCode::ApproverNotAuthorized, msg.clone()),
            AppError::WkRefused(msg) => (ScCode::WkRefusedV2, msg.clone()),
            AppError::GrantIdInvalid(msg) => (ScCode::GrantIdInvalid, msg.clone()),
            AppError::DeviceNotAdmitted => (
                ScCode::DeviceNotAdmitted,
                DEVICE_NOT_ADMITTED_MSG.to_string(),
            ),
            AppError::DeviceAccountMissing => (
                ScCode::DeviceNotAdmitted,
                DEVICE_ACCOUNT_MISSING_MSG.to_string(),
            ),
            AppError::LedgerStale => (ScCode::LedgerStale, LEDGER_STALE_MSG.to_string()),
            AppError::LedgerDeviceRevoked => (
                ScCode::LedgerDeviceRevoked,
                LEDGER_DEVICE_REVOKED_MSG.to_string(),
            ),
            AppError::AgentNotAdmitted => {
                (ScCode::AgentNotAdmitted, AGENT_NOT_ADMITTED_MSG.to_string())
            }
            AppError::Internal(msg) => {
                tracing::error!("internal error: {}", msg);
                (ScCode::Internal, "Internal server error".to_string())
            }
        }
    }

    /// `(http status u16, machine code, human message)` — legacy projection,
    /// kept for callers that only need the tuple.
    pub fn parts(&self) -> (u16, &'static str, String) {
        let (code, detail) = self.code();
        (code.status(), code.as_str(), detail)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, detail) = self.code();
        let status =
            StatusCode::from_u16(code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut res = (status, Json(problem_body(code, &detail))).into_response();
        res.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        res
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::NotFound => write!(f, "Not found"),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::VaultLocked => write!(f, "Vault locked"),
            AppError::VaultAccessRevoked => write!(f, "{}", VAULT_ACCESS_REVOKED_MSG),
            AppError::VaultDeleted => write!(f, "This vault was deleted."),
            AppError::TooManyRequests => write!(f, "Rate limit exceeded"),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
            AppError::BatchVerify(msg) => write!(f, "Batch verification failed: {}", msg),
            AppError::ApproverNotAuthorized(msg) => write!(f, "Approver not authorized: {}", msg),
            AppError::WkRefused(msg) => write!(f, "Grant refused: {}", msg),
            AppError::GrantIdInvalid(msg) => write!(f, "Approval signature invalid: {}", msg),
            AppError::DeviceNotAdmitted => write!(f, "{}", DEVICE_NOT_ADMITTED_MSG),
            AppError::DeviceAccountMissing => write!(f, "{}", DEVICE_ACCOUNT_MISSING_MSG),
            AppError::LedgerStale => write!(f, "{}", LEDGER_STALE_MSG),
            AppError::LedgerDeviceRevoked => write!(f, "{}", LEDGER_DEVICE_REVOKED_MSG),
            AppError::AgentNotAdmitted => write!(f, "{}", AGENT_NOT_ADMITTED_MSG),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(format!("IO error: {}", e))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(format!("JSON error: {}", e))
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(e: base64::DecodeError) -> Self {
        AppError::BadRequest(format!("Base64 decode error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_access_revoked_is_an_explicit_agent_refusal() {
        assert_eq!(ScCode::VaultAccessRevoked.as_str(), "vault_access_revoked");
        assert_eq!(ScCode::VaultAccessRevoked.status(), 403);
        let (code, message) = AppError::VaultAccessRevoked.code();
        assert_eq!(code, ScCode::VaultAccessRevoked);
        assert_eq!(message, VAULT_ACCESS_REVOKED_MSG);
        assert!(message.contains("Ask a vault admin to add you back."));
    }

    #[test]
    fn vault_key_changed_is_an_unlockable_conflict() {
        assert_eq!(ScCode::VaultKeyChanged.as_str(), "vault_key_changed");
        assert_eq!(ScCode::VaultKeyChanged.status(), 409);
        assert_eq!(ScCode::VaultKeyChanged.row().3, "unlock");
        assert_eq!(
            VAULT_KEY_CHANGED_MSG,
            "This connection may have been added after the vault's members changed and its key was replaced. This device doesn't have the new key yet: ask the user to approve `sc unlock`."
        );
    }

    /// Every registry row must be internally consistent: a real HTTP status,
    /// a snake_case code, and a status that matches what `AppError` variants
    /// project (the two surfaces must never disagree on a code's status).
    #[test]
    fn registry_rows_are_consistent() {
        use ScCode::*;
        let all = [
            BadRequest,
            Unauthorized,
            Forbidden,
            NotFound,
            MethodNotAllowed,
            Conflict,
            VaultLocked,
            VaultAccessRevoked,
            VaultDeleted,
            RateLimited,
            Internal,
            CaUnavailable,
            AgentKey,
            AgentNotAuthorized,
            AgentNotInAccount,
            AmbiguousPhantom,
            ApprovalNeeded,
            ApprovalRegister,
            BatchVerifyFailed,
            ApproverNotAuthorized,
            WkRefusedV2,
            GrantIdInvalid,
            DeviceNotAdmitted,
            LedgerHeadInvalid,
            LedgerDeviceRevoked,
            AgentNotAdmitted,
            LedgerStale,
            BrokerBodyLimit,
            EgressUnreachable,
            ExposesUnsupported,
            HostForbidden,
            TeamLeaseExpired,
            HostNotAnchored,
            MultiConnection,
            NoVault,
            OauthMint,
            PhantomPlainHttp,
            PhantomUnresolved,
            PolicyDenied,
            RefreshForbidden,
            SecretEncoding,
            StoreUnavailable,
            VaultKeyChanged,
            UnknownConnection,
            UpstreamBody,
            UpstreamError,
            UpgradeRequired,
            MaskNotEnabled,
        ];
        for c in all {
            let (status, code, title, action, cause) = c.row();
            assert!((400..=599).contains(&status), "{code}: status {status}");
            assert!(
                code.chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
                "{code}: not snake_case"
            );
            assert!(!title.is_empty());
            assert!(
                [
                    "unlock",
                    "approve",
                    "retry",
                    "configure",
                    "fix_request",
                    "none"
                ]
                .contains(&action),
                "{code}: unknown action {action}"
            );
            assert!(
                [
                    "request",
                    "auth",
                    "vault",
                    "policy",
                    "config",
                    "environment",
                    "upstream",
                    "internal"
                ]
                .contains(&cause),
                "{code}: unknown cause {cause}"
            );
        }
    }

    /// The not-admitted refusal is its own code with the `sc agent add` fix,
    /// never the vault-level `agent_not_authorized`.
    #[test]
    fn agent_not_admitted_row() {
        let (code, detail) = AppError::AgentNotAdmitted.code();
        assert_eq!(code.as_str(), "agent_not_admitted");
        assert_eq!(code.status(), 403);
        assert_eq!(code.row().3, "configure");
        assert!(detail.contains("`sc agent add`"));
        assert!(
            !detail.contains('\n') && !detail.contains('\u{2014}'),
            "one line, no em dash"
        );
        let (code, detail) = AppError::LedgerStale.code();
        assert_eq!((code.as_str(), code.status()), ("ledger_stale", 423));
        assert!(detail.starts_with("locked: SafeClaw could not reach your account for 7 days"));
    }

    /// problem_body carries both the 9457 members and the legacy dual-emit.
    #[test]
    fn problem_body_dual_emits() {
        let b = problem_body(ScCode::VaultLocked, VAULT_LOCKED_MSG);
        assert_eq!(b["code"], "vault_locked");
        assert_eq!(b["error"], "vault_locked");
        assert_eq!(b["status"], 423);
        assert_eq!(b["detail"], b["message"]);
        assert_eq!(b["type"], "https://safeclaw.pro/errors/vault_locked");
        assert_eq!(b["action"], "unlock");
    }
}
