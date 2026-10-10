//! SafeClaw identity & signing layer — Ed25519 principals (UIK / AIK),
//! self-certifying ids, and the canonical signing-input builders that config
//! signatures, re-key events, lineage succession, and the server-signed sync
//! envelope are all computed over.
//!
//! ## Boundary — why this lives here and NOT in the `sudp` crate
//!
//! sudp core stays a pure symmetric seal / wrap / grant codec: it knows nothing
//! of UIK, roles, or state signatures (design/sudp-identity-signing-revision.md
//! §0 — "SUDP core 只知道 K + 一把包 K 的 wrapping key + 抽象 authenticator +
//! grant/redeem"). Everything in this module is the SafeClaw-level extension
//! built *on top* of sudp. We reuse sudp's HKDF (so there is exactly one KDF
//! across the system — see [`storage::item`](crate::storage::item)) but keep our
//! own `safeclaw/v1/*` domain labels, pairwise-disjoint from sudp's `sudp/v1/*`
//! set and from the WebAuthn ECDSA-P256 β verification.
//!
//! ## Layering (design/team-shared-vault-security-model.md §5)
//!
//! `custody (passkey PRF / password KDF / HSM) → UIK → K`.
//!
//! - **UIK** = the human principal: signs config / state (no gesture, one per
//!   account, `user_id = derive_id(User, uik_pub)` = the account's cryptographic
//!   primary key). Custody wraps the UIK *private* key; the vault key `K` is
//!   HPKE-sealed to the UIK *public* key. Adding a device = adding one more
//!   custody wrap of the same UIK — it never touches `K`.
//! - **AIK** = an agent principal: one per agent, derived from a single root
//!   seed. The private key is resident in the daemon/`sc` component and NEVER
//!   enters the agent's environment or crosses a machine. `agent_id =
//!   derive_id(Agent, aik_pub)`. There is no agent bearer: the agent proves
//!   possession of the AIK on every request (design D8).
//!
//! This module is the identity half only: keypairs, ids, and the byte-exact
//! signing inputs. The custody→UIK→K wrap graph lives in the vault key layer;
//! the fold/verify *policy* (which pubkeys are owners, when to accept a signed
//! record) lives in the sync/members layer. Those consume the primitives here.
//!
//! ## Cross-language parity
//!
//! Config records are signed in the browser (TS `@sudp-protocol/authorizer` +
//! `lib/vault-grant.ts`) and verified by the daemon (Rust), so [`config_sig_input`]
//! and [`derive_id`] MUST be byte-identical across Rust and TS. The pinned
//! vectors at the bottom of this file are the contract; the TS side pins the
//! same values. Change one side, change both — and never edit an expected value
//! just to make a test pass; find why the two diverged.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};
use zeroize::Zeroizing;

// ── Domain-separation labels (SafeClaw namespace; disjoint from sudp/v1/*) ──

/// Owner UIK signature over a config singleton (policy / stores / store_order /
/// audit_retention_days / services / members). See [`config_sig_input`].
pub const DS_CONFIG_SIG: &[u8] = b"safeclaw/v1/config-sig";

/// Owner-signed re-key event (a `generation` bump). See [`rekey_sig_input`].
pub const DS_REKEY: &[u8] = b"safeclaw/v1/rekey";

/// Creator-signed role grant on a keyset cred (the owner-authority anchor for
/// "who is an owner") — the root-signed CHECKPOINT base of the delegation fold.
/// See [`role_grant_input`].
pub const DS_ROLE_GRANT: &[u8] = b"safeclaw/v1/role-grant";

/// An owner-signed delegation event (add/promote/demote/remove) appended to the
/// keyset's delegation log — the any-owner, issuance-time-authority half of the
/// owner-set fold (design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md
/// §1.1). See [`delegation_event_input`].
pub const DS_DELEGATION: &[u8] = b"safeclaw/v1/delegation-event";

/// A root-succession certificate: the CURRENT root signs the NEXT root's id +
/// pubkey, so the daemon can follow a short chain from the TOFU-pinned genesis
/// root to the current root (creator transfer / offboard). See
/// [`root_succession_input`].
pub const DS_ROOT_SUCCESSION: &[u8] = b"safeclaw/v1/root-succession";

/// Domain tag for a vault-DELETE tombstone (§15 leg A, per-vault drop). The vault
/// OWNER signs this so a daemon destroys local state on OWNER intent, not a server
/// flipping a cleartext `status:"deleted"` field. Verified against the vault's
/// fold-owner set (the same genesis-anchored authority as [`DS_DELEGATION`]). See
/// [`vault_tombstone_input`].
pub const DS_VAULT_TOMBSTONE: &[u8] = b"safeclaw/v1/vault-tombstone";

/// UIK lineage succession certificate (old UIK signs the new UIK). See
/// [`succession_input`].
pub const DS_SUCCESSION: &[u8] = b"safeclaw/v1/uik-succession";

/// A device's per-request proof-of-possession over a daemon→cloud request (the
/// DIK half of mutual mTLS, hop-B). Railway terminates TLS, so hop-B can't be a
/// real client-cert handshake — instead the daemon signs each request with its
/// DIK and the Node backend verifies the signature against the device's
/// registered `dv_` pubkey. See [`device_request_signature_input`].
pub const DS_DEVICE_REQ: &[u8] = b"safeclaw/v1/device-req";

/// A person's UIK self-signature binding their X25519 `enc_pub` to their `us_`
/// (trust-reset contract 1.1, identity Layer 1). See [`enc_bind_input`].
pub const DS_UIK_ENC_BIND: &[u8] = b"safeclaw/v1/uik-enc-bind";

/// A person's UIK-signed ledger v2 event: admit / revoke of a device, passkey or
/// vault pin (trust-reset contract 1.3). See [`ledger_event_input`].
pub const DS_LEDGER_EVENT: &[u8] = b"safeclaw/v1/ledger-event";

/// The full-bundle K commitment carried in the rekey proof (trust-reset contract
/// 1.5). See [`k_commitment`].
pub const DS_K_COMMIT: &[u8] = b"safeclaw/v1/k-commit";

/// An agent's per-CONNECT proof-of-possession over the local forward proxy (the
/// AIK half of mutual mTLS, hop-A). A standard client can't present a client cert
/// to a forward proxy, so the AIK identity rides a signed token in the
/// `Proxy-Authorization` header instead. See [`agent_proxy_pop_input`].
pub const DS_AGENT_PROXY_POP: &[u8] = b"safeclaw/v1/agent-proxy-pop";

/// Domain tag for the **per-record signature** (SUDP extension A1.2/A1.3,
/// `design/sudp-identity-signing-revision.md`). This is the SUDP-protocol-layer
/// record signature — hence the `sudp/v1/*` family (C.4 domain decision) rather
/// than `safeclaw/v1/*` — even though the primitive lives here in core (the sudp
/// crate stays a pure codec, §B). It signs the CIPHERTEXT hash + the plaintext
/// `type`/`status`, so BOTH a blind server (write-gate / clean state) and every
/// reader (the trust wall) can verify without decrypting.
pub const DS_ITEM_SIG: &[u8] = b"sudp/v1/item-sig";

/// HKDF `info` deriving an agent's Ed25519 identity seed from its root seed.
const AIK_IDENTITY_INFO: &[u8] = b"safeclaw/v1/agent-identity";

/// Append a length-prefixed field: `u32_be(len) ‖ bytes`. Identical to
/// [`storage::item`](crate::storage::item)'s `push_lp` and sudp's `record_aad`
/// so all length-prefixed constructions agree byte-for-byte. Length-prefixing
/// removes splicing ambiguity between adjacent variable-length fields. This is
/// the `lp()` of the trust-reset contract (section 0).
pub(crate) fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ── Self-certifying ids ────────────────────────────────────────────────────

/// Which principal an id names. The prefix makes ids self-describing and keeps
/// user and agent id spaces disjoint even at equal hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    /// A human principal (UIK). Prints as `us_…`.
    User,
    /// An agent principal (AIK). Prints as `ag_…`.
    Agent,
    /// A device principal (DIK) — one machine's identity to the cloud. Prints as
    /// `dv_…` (renamed from `dev_` in the trust reset; old audit strings keep
    /// `dev_` as history). Symmetric with AIK (design/agent-device-identity-mtls.md
    /// §0); replaces the bearer device pair token.
    Device,
}

impl IdKind {
    fn prefix(self) -> &'static str {
        match self {
            IdKind::User => "us",
            IdKind::Agent => "ag",
            IdKind::Device => "dv",
        }
    }
}

/// Derive the self-certifying id of a principal from its Ed25519 public key:
/// `"{us|ag|dv}_" ‖ base32_lower_nopad(SHA-256(pubkey)[..20])`.
///
/// The id IS a commitment to the pubkey (ETH-address / SSH-fingerprint style),
/// so a colluding server cannot swap the key behind an id. 20 bytes → 32 base32
/// chars; lower-cased for a friendly, case-insensitive, URL/DNS-safe token.
pub fn derive_id(kind: IdKind, pubkey: &[u8; 32]) -> String {
    let digest = sha256(pubkey);
    let body = BASE32_NOPAD.encode(&digest[..20]).to_lowercase();
    format!("{}_{}", kind.prefix(), body)
}

/// The kind of a well-formed self-certifying id: exactly `us_`/`ag_`/`dv_`
/// followed by 32 lowercase RFC 4648 base32 characters (`[a-z2-7]`). Anything
/// else (the retired `dev_` prefix, upper case, wrong length) is `None`. This is
/// a FORMAT check only; binding an id to a key is `derive_id(kind, pub) == id`.
pub fn parse_id(id: &str) -> Option<IdKind> {
    let (prefix, body) = id.split_once('_')?;
    let kind = match prefix {
        "us" => IdKind::User,
        "ag" => IdKind::Agent,
        "dv" => IdKind::Device,
        _ => return None,
    };
    let well_formed = body.len() == 32
        && body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    well_formed.then_some(kind)
}

// ── Signing principal (UIK, or a resolved AIK) ─────────────────────────────

/// An Ed25519 signing principal: holds the private key, can sign and expose its
/// public key / id. Used for a UIK (from custody-unwrapped bytes) and for a
/// resolved AIK (see [`AgentRoot::identity`]).
pub struct SigningIdentity {
    key: SigningKey,
}

impl SigningIdentity {
    /// Build from a 32-byte Ed25519 seed (the secret key). Deterministic:
    /// identical seed ⇒ identical public key and identical signatures.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Mint a fresh principal from the OS CSPRNG. (Foundation convenience; the
    /// production UIK is minted in the onboarding ceremony, an AIK from its root.)
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self::from_seed(&seed)
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign a message, returning the 64-byte detached signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }

    /// This principal's self-certifying id under `kind`.
    pub fn id(&self, kind: IdKind) -> String {
        derive_id(kind, &self.public_bytes())
    }

    /// Convenience: the account primary key `us_…` for a UIK.
    pub fn user_id(&self) -> String {
        self.id(IdKind::User)
    }

    /// As a UIK, self-sign the binding of this person's X25519 `enc_pub` to their
    /// own `us_` (trust-reset contract 1.1). See [`enc_bind_input`].
    pub fn sign_enc_bind(&self, enc_pub: &[u8; 32]) -> [u8; 64] {
        self.sign(&enc_bind_input(&self.user_id(), enc_pub))
    }
}

/// Verify a detached Ed25519 signature over `msg` by `pubkey`. Uses
/// `verify_strict` (rejects the small-order / malleable edge cases), and treats
/// a malformed public key as a failed verification (never a panic). This is the
/// reader-side wall: every daemon calls it before applying a signed record.
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

// ── Agent root (AIK single-root derivation) ────────────────────────────────

/// An agent's single root seed: its Ed25519 identity keypair (⇒ `agent_id`)
/// derives from it. There is no agent bearer (design D8): the agent proves
/// possession of this identity on every request.
pub struct AgentRoot {
    root: Zeroizing<[u8; 32]>,
}

impl AgentRoot {
    /// Adopt an existing 32-byte root seed.
    pub fn from_seed(root: [u8; 32]) -> Self {
        Self {
            root: Zeroizing::new(root),
        }
    }

    /// Mint a fresh agent root from the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut root = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root);
        Self::from_seed(root)
    }

    fn hkdf(&self, info: &[u8]) -> [u8; 32] {
        <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(&self.root[..], &[], info)
            .expect("HKDF-SHA256 derive_32 is infallible for a 32-byte root")
    }

    /// The agent's Ed25519 identity, derived from the root. The private key
    /// stays in this process.
    pub fn identity(&self) -> SigningIdentity {
        let seed = Zeroizing::new(self.hkdf(AIK_IDENTITY_INFO));
        SigningIdentity::from_seed(&seed)
    }

    /// The agent's self-certifying id `ag_…`.
    pub fn agent_id(&self) -> String {
        self.identity().id(IdKind::Agent)
    }
}

// ── Canonical signing inputs (length-prefixed, domain-separated) ────────────
//
// Fixed-width scalars (version / generation / format / epoch / issued_at) are
// appended as big-endian bytes directly (unambiguous at fixed width); every
// variable-length field is `push_lp`'d.

/// Signing input for a config singleton (UIK-signed; reader-verified).
///
/// ```text
/// lp(DS_CONFIG_SIG) ‖ lp(vault_id) ‖ lp(item_ns) ‖ u64_be(version)
///   ‖ status(1) ‖ lp(SHA-256(body_or_empty)) ‖ lp(signer_id)
/// ```
///
/// `body = Some(canonical_bytes)` for a live record, `None` for a tombstone;
/// `status` = `1` live / `0` tombstone, so a live signature can never be
/// replayed as a tombstone (and vice versa). Hashing the (already-canonical)
/// body keeps the input bounded. `signer_id` (the owner's `us_…`) binds the
/// signature to a specific principal. The caller canonicalizes the body (JCS)
/// before hashing — see the config-signing layer for the body parity vector.
pub fn config_sig_input(
    vault_id: &str,
    item_ns: &str,
    version: u64,
    body: Option<&[u8]>,
    signer_id: &str,
) -> Vec<u8> {
    let status: u8 = if body.is_some() { 1 } else { 0 };
    let body_hash = sha256(body.unwrap_or(&[]));
    let mut out = Vec::new();
    push_lp(&mut out, DS_CONFIG_SIG);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, item_ns.as_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.push(status);
    push_lp(&mut out, &body_hash);
    push_lp(&mut out, signer_id.as_bytes());
    out
}

/// Signing input for a **per-record signature** (SUDP extension A1.2/A1.3,
/// `design/sudp-identity-signing-revision.md`): a principal's signature over one
/// sealed record, binding its plaintext `type`/`status` to the sealed body.
///
/// ```text
/// lp(DS_ITEM_SIG) ‖ lp(record_type) ‖ lp(item_id) ‖ u64_be(version)
///   ‖ lp(vault_id) ‖ status(1) ‖ lp(SHA-256(sealed_body)) ‖ lp(principal_id)
/// ```
///
/// Crucially the hash is over the **sealed body (ciphertext)**, not the plaintext
/// — so a blind server AND every reader can verify the signature WITHOUT the key
/// (the server does the write-gate for clean state; the reader is the trust wall,
/// A1.5). `record_type` is the plaintext ns token (`secret`/`connection`/`policy`/
/// `agent`/…) that the server gates on (A1.4 role×type) and the reader cross-binds
/// to the decrypted record. `status` = `1` live / `0` tombstone (a delete is a
/// signed record state; the signer+type decide who may delete). `item_id` is the
/// blinded HMAC id (unchanged addressing). `principal_id` = the signer's self-id
/// (`us_`/`dv_`/`ag_`) — a UIK for human writes, the DIK/AIK for automatic
/// (daemon/agent) writes (A2). One signature does all three jobs: authorization
/// (role×type), integrity/author identity, and rollback resistance (version is
/// bound + the caller keeps version monotone).
pub fn record_signature_input(
    record_type: &str,
    item_id: &[u8],
    version: u64,
    vault_id: &str,
    sealed_body: &[u8],
    status_live: bool,
    principal_id: &str,
) -> Vec<u8> {
    let body_hash = sha256(sealed_body);
    let mut out = Vec::new();
    push_lp(&mut out, DS_ITEM_SIG);
    push_lp(&mut out, record_type.as_bytes());
    push_lp(&mut out, item_id);
    out.extend_from_slice(&version.to_be_bytes());
    push_lp(&mut out, vault_id.as_bytes());
    out.push(if status_live { 1 } else { 0 });
    push_lp(&mut out, &body_hash);
    push_lp(&mut out, principal_id.as_bytes());
    out
}

/// Signing input for a **device request proof-of-possession** (trust-reset
/// contract 1.4). The daemon signs every cloud request with its DIK so the Node
/// backend can verify "this request really came from an admitted device" WITHOUT
/// a client-cert handshake (Railway terminates TLS before the app ever sees the
/// connection).
///
/// ```text
/// lp(DS_DEVICE_REQ) ‖ lp(method) ‖ lp(path_with_query) ‖ u64_be(timestamp)
///   ‖ lp(SHA-256(body)) ‖ lp(device_id) ‖ lp(canonical_host)
/// ```
///
/// Every field binds so a captured signature can't be replayed onto a different
/// request: `method`+`path` pin the endpoint (pass `path` including the query
/// string, exactly as it appears on the wire, so it matches byte-for-byte at the
/// verifier), `timestamp` (unix seconds) bounds the replay window, the body hash
/// pins the payload (use `&[]` for a bodyless GET — its SHA-256 is a fixed
/// constant both sides compute), `device_id` (the `dv_…` self-id) tells the
/// verifier which registered pubkey to check, and `canonical_host` pins the
/// deployment: it is the CONFIGURED backend host in WHATWG `URL.host` form
/// ([`crate::device_auth::canonical_host`]), never the incoming `Host` header, so a
/// dev capture can't be replayed against prod. This is a SafeClaw transport-auth
/// concern, not part of the SUDP sealed-record protocol, so it lives in the
/// `safeclaw/v1/*` domain (unlike the `sudp/v1/item-sig` record signature).
pub fn device_request_signature_input(
    method: &str,
    path: &str,
    timestamp: u64,
    body: &[u8],
    device_id: &str,
    canonical_host: &str,
) -> Vec<u8> {
    let body_hash = sha256(body);
    let mut out = Vec::new();
    push_lp(&mut out, DS_DEVICE_REQ);
    push_lp(&mut out, method.as_bytes());
    push_lp(&mut out, path.as_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    push_lp(&mut out, &body_hash);
    push_lp(&mut out, device_id.as_bytes());
    push_lp(&mut out, canonical_host.as_bytes());
    out
}

/// Signing input for a person's **`enc_sig`** (trust-reset contract 1.1): the UIK
/// self-signs the binding of its X25519 encryption key to its own id, so no
/// server can swap or fill the `enc_pub` a client seals to.
///
/// ```text
/// lp(DS_UIK_ENC_BIND) ‖ lp(user_id) ‖ lp(enc_pub)
/// ```
pub fn enc_bind_input(user_id: &str, enc_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_UIK_ENC_BIND);
    push_lp(&mut out, user_id.as_bytes());
    push_lp(&mut out, enc_pub);
    out
}

/// Verify a person's `enc_sig`: valid iff `derive_id(User, sig_pub) == user_id`
/// AND the signature verifies over [`enc_bind_input`]. Both checks, always: a
/// valid signature by a key that does not fold to `user_id` is a forgery of
/// someone else's binding.
pub fn verify_enc_sig(
    user_id: &str,
    sig_pub: &[u8; 32],
    enc_pub: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    derive_id(IdKind::User, sig_pub) == user_id
        && verify(sig_pub, &enc_bind_input(user_id, enc_pub), sig)
}

/// Signing input for a **ledger v2 event** (trust-reset contract 1.3), signed by
/// the person's UIK:
///
/// ```text
/// lp(DS_LEDGER_EVENT) ‖ lp(us_) ‖ lp(op) ‖ lp(kind) ‖ lp(principal)
///   ‖ lp(sig_pub) ‖ lp(enc_pub) ‖ lp(label) ‖ u64_be(seq)
/// ```
///
/// `op` ∈ {`admit`, `revoke`}; `kind` ∈ {`device`, `passkey`, `pin`}. Field
/// meaning per kind, the parser and the fold live in [`crate::crypto::ledger`].
#[allow(clippy::too_many_arguments)]
pub fn ledger_event_input(
    us: &str,
    op: &str,
    kind: &str,
    principal: &str,
    sig_pub: &[u8],
    enc_pub: &[u8],
    label: &str,
    seq: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_LEDGER_EVENT);
    push_lp(&mut out, us.as_bytes());
    push_lp(&mut out, op.as_bytes());
    push_lp(&mut out, kind.as_bytes());
    push_lp(&mut out, principal.as_bytes());
    push_lp(&mut out, sig_pub);
    push_lp(&mut out, enc_pub);
    push_lp(&mut out, label.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out
}

/// The **full-bundle K commitment** (trust-reset contract 1.5), carried in the
/// rekey proof (`rekey_sig_input`'s `k_commitment`), generation 0 included:
///
/// ```text
/// SHA-256( lp(DS_K_COMMIT) ‖ lp(vault_id) ‖ u64_be(generation) ‖ lp(bundle64) )
/// ```
///
/// `bundle` is the whole 64-byte K (`id_seed ‖ content`), so a server can't pair
/// a committed content key with a substituted `id_seed`. Console and daemon both
/// check it before using or retaining a bundle.
pub fn k_commitment(vault_id: &str, generation: u64, bundle: &[u8; 64]) -> [u8; 32] {
    let mut buf = Vec::new();
    push_lp(&mut buf, DS_K_COMMIT);
    push_lp(&mut buf, vault_id.as_bytes());
    buf.extend_from_slice(&generation.to_be_bytes());
    push_lp(&mut buf, bundle);
    sha256(&buf)
}

/// Signing input for an **agent proxy-connect proof-of-possession** (hop-A of the
/// mutual-mTLS transport, `design/agent-device-identity-mtls.md` §9.1). An agent
/// reaches the daemon through a standard forward proxy (`HTTP_PROXY`), whose only
/// client-auth channel is the `Proxy-Authorization` header on each `CONNECT` — a
/// standard client cannot present a client cert to a forward proxy, so hop-A (like
/// hop-B under Railway) rides an application-layer signature, not TLS mutual auth.
/// The `sc` transport signs this with the agent's AIK per CONNECT; the daemon
/// verifies it against the vault's authorized-agents table.
///
/// ```text
/// lp(DS_AGENT_PROXY_POP) ‖ lp(vault_id) ‖ lp(target) ‖ u64_be(timestamp) ‖ lp(agent_id)
/// ```
///
/// `vault_id` = the CONNECT's proxy-auth username (which vault the agent is using),
/// `target` = the CONNECT authority `host:port` the tunnel opens to (binds the
/// token to that destination so a captured one can't be replayed elsewhere within
/// the window), `timestamp` = unix seconds (freshness/replay window), `agent_id` =
/// the AIK self-id (`ag_…`). The daemon rebuilds this from the CONNECT context +
/// the token's carried pubkey (deriving `agent_id`) and verifies the signature,
/// then checks `agent_id ∈` the authorized-agents table. Per-CONNECT, not
/// per-request: one CONNECT opens a reused tunnel, and the proxy only sees
/// `Proxy-Authorization` at CONNECT time.
pub fn agent_proxy_pop_input(
    vault_id: &str,
    target: &str,
    timestamp: u64,
    agent_id: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_AGENT_PROXY_POP);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, target.as_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    push_lp(&mut out, agent_id.as_bytes());
    out
}

/// Signing input for an owner-signed re-key event (DP-S1 `generation` bump).
///
/// ```text
/// lp(DS_REKEY) ‖ lp(vault_id) ‖ u64_be(generation) ‖ lp(k_commitment) ‖ lp(signer_id)
///   ‖ u64_be(membership_len) ‖ lp(membership_hash)
/// ```
///
/// `k_commitment` = a one-way commitment to the new content key `K'` (e.g. a
/// KCV) so a signed generation is bound to the specific new key and an old
/// signed event can't be replayed to force a different key. The signature is
/// what makes a `generation` bump trustworthy: an unsigned bump is ignored, so a
/// malicious backend cannot storm fake generations to DoS unlock (SM §3.2 ⚠).
///
/// **Membership anti-rollback (delegation-log-review-findings.md C2, owner-signed).**
/// `membership_len` + `membership_hash` = [`membership_commitment`] over the delegation-log
/// PREFIX current at re-key time (all events at the current role-epoch, sorted).
/// Because a re-key is owner-signed and the daemon RATCHETS `generation` (refuses a
/// lower one), binding the membership head here lets a device REFUSE a keyset that serves
/// the current generation but a rolled-back log (e.g. an omitted `remove`): the
/// prefix would not hash to `membership_hash`. Low-frequency by construction (only on
/// re-key / offboard, not on every add), and the server can't forge it (no owner
/// key). A truly-fresh device against a permanent consistent OLD snapshot is still
/// inherent to cloud-blind — but that bubble is fragile (new content is under the
/// new K it can't open).
pub fn rekey_sig_input(
    vault_id: &str,
    generation: u64,
    k_commitment: &[u8],
    signer_id: &str,
    membership_len: u64,
    membership_hash: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_REKEY);
    push_lp(&mut out, vault_id.as_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    push_lp(&mut out, k_commitment);
    push_lp(&mut out, signer_id.as_bytes());
    out.extend_from_slice(&membership_len.to_be_bytes());
    push_lp(&mut out, membership_hash);
    out
}

/// A one-way commitment to the delegation-log PREFIX for the membership anti-rollback
/// binding in [`rekey_sig_input`]. `sigs` = the Ed25519 signatures of the first
/// `membership_len` delegation events at the current role-epoch, in the SAME
/// deterministic `(seq, sig)` order the fold applies them (each `sig` is a
/// commitment to its event's full content). Byte-identical across daemon / backend /
/// browser:
///
/// ```text
/// SHA-256( "safeclaw/v1/membership-commit" ‖ u64_be(membership_len) ‖ sig_1 ‖ … ‖ sig_N )
/// ```
pub fn membership_commitment(sigs: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"safeclaw/v1/membership-commit");
    buf.extend_from_slice(&(sigs.len() as u64).to_be_bytes());
    for s in sigs {
        buf.extend_from_slice(s);
    }
    sha256(&buf)
}

/// Signing input for a creator-signed role grant on a keyset cred — the
/// owner-authority anchor (design/identity-uik-aik.md §4.3 RESOLVED). Role is an
/// attribute ON the keyset cred, signed by the vault's ROOT owner (the creator);
/// a daemon derives the owner-set by verifying each cred's `role_sig` against the
/// TOFU-pinned `creator_sig_pub`. This roots role in genesis, closing finding #1
/// (single-version self-consistency let any member self-sign `{me: owner}`).
///
/// ```text
/// lp(DS_ROLE_GRANT) ‖ lp(vault_id) ‖ lp(user_id) ‖ lp(role) ‖ u64_be(role_epoch)
/// ```
///
/// `role` is the lowercase serde token of [`crate::storage::plaintext::MemberRole`]
/// (`"owner"` / `"member"`). The variable-length fields are length-prefixed (so a
/// `(vault, user, role)` triple can't be spliced into another); the trailing epoch
/// is appended as a fixed-width big-endian `u64`, EXACTLY as [`rekey_sig_input`]
/// appends `generation`.
///
/// **Role-epoch binding (delegation-log-impl-spec.md §0, design/identity-uik-aik.md
/// §4.3).** This grant is the root-signed CHECKPOINT of the owner-set. It is bound
/// to `role_epoch` — the role-checkpoint epoch, ORTHOGONAL to the K-rotation
/// `generation` (memory: "generation ⊥ chain 正交"). A checkpoint grant signed at
/// `role_epoch = E` is honored only while the keyset's DERIVED epoch is `E` — the
/// epoch is derived from the root-signed succession/compaction chain
/// (`resolve_current_root`), never a stored scalar. Compaction (root-only) is a
/// SELF-succession that advances the epoch to `E+1`, re-signing every surviving owner
/// and dropping demoted/removed ones — so a colluding server that replays a stale
/// grant fails verification at the new epoch (and can't forge the epoch upward
/// without a root signature).
/// Between checkpoints, any-owner add/remove rides the delegation log
/// ([`delegation_event_input`]), not this checkpoint. K-eviction bumps `generation`
/// independently and does NOT invalidate checkpoint grants (they bind `role_epoch`).
pub fn role_grant_input(vault_id: &str, user_id: &str, role: &str, role_epoch: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_ROLE_GRANT);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, user_id.as_bytes());
    push_lp(&mut out, role.as_bytes());
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for an owner-signed delegation event — the any-owner,
/// issuance-time-authority half of the owner-set fold (design/identity-uik-aik.md
/// §4.3, delegation-log-impl-spec.md §1.1).
///
/// ```text
/// lp(DS_DELEGATION) ‖ lp(vault_id) ‖ lp(op) ‖ lp(subject_id) ‖ lp(role)
///   ‖ lp(granter_id) ‖ u64_be(seq) ‖ u64_be(role_epoch)
/// ```
///
/// `op` ∈ {`"set"`, `"remove"`}: `set` inserts `subject_id → role` (add / promote /
/// demote); `remove` drops `subject_id` (NON-CASCADE — touches only the subject).
/// `role` is the lowercase [`crate::storage::plaintext::MemberRole`] token for `set`,
/// empty for `remove`. `granter_id` is the signing owner's `us_…`; the event is
/// honored by the fold iff `granter_id` is an OWNER in the owner-set folded up to
/// this event (so a member can't grant, and issuance-time authority survives the
/// granter's later removal). `seq` is monotone within `role_epoch` (rollback guard);
/// `role_epoch` binds the event to the current checkpoint so a compaction that folds
/// the log invalidates replays of pre-compaction events at the new epoch.
pub fn delegation_event_input(
    vault_id: &str,
    op: &str,
    subject_id: &str,
    role: &str,
    granter_id: &str,
    seq: u64,
    role_epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_DELEGATION);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, op.as_bytes());
    push_lp(&mut out, subject_id.as_bytes());
    push_lp(&mut out, role.as_bytes());
    push_lp(&mut out, granter_id.as_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Canonical bytes a vault OWNER signs to tombstone (delete) a vault (§15 leg A):
///
/// ```text
/// lp(DS_VAULT_TOMBSTONE) ‖ lp(vault_id)
/// ```
///
/// The `vault_id` is a unique, never-reused UUID, so binding it alone is replay-safe
/// (a signed tombstone can only ever name the one vault it deletes; there is no later
/// vault with the same id to replay it onto). A daemon honors the tombstone iff the
/// signer is an owner in the vault's fold-owner set — the same genesis-anchored
/// authority that gates [`delegation_event_input`]. This raises "delete a vault
/// locally" from "the server flips a cleartext status field" to "forge an owner
/// signature".
pub fn vault_tombstone_input(vault_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_VAULT_TOMBSTONE);
    push_lp(&mut out, vault_id.as_bytes());
    out
}

/// Signing input for a root-succession certificate — the CURRENT root signs the
/// NEXT root's id + signing pubkey, so a daemon follows a short chain from the
/// TOFU-pinned genesis root to the current root (creator transfer / offboard;
/// design/identity-uik-aik.md §4.3, delegation-log-impl-spec.md §1.2).
///
/// ```text
/// lp(DS_ROOT_SUCCESSION) ‖ lp(vault_id) ‖ lp(old_root_id) ‖ lp(new_root_id)
///   ‖ lp(new_root_sig_pub) ‖ u64_be(role_epoch)
/// ```
///
/// The `new_root_sig_pub` (raw 32 bytes) is bound in the signature so the server
/// cannot swap in a root pubkey of its choosing; `old_root_id` must equal
/// `derive_id(current root)` at verification; `role_epoch` must strictly increase
/// along the chain (rollback guard). This differs from [`succession_input`], which
/// is a PERSON's key rotation preserving one id — here the root's id CHANGES
/// (ownership moves to a different principal).
pub fn root_succession_input(
    vault_id: &str,
    old_root_id: &str,
    new_root_id: &str,
    new_root_sig_pub: &[u8; 32],
    role_epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_ROOT_SUCCESSION);
    push_lp(&mut out, vault_id.as_bytes());
    push_lp(&mut out, old_root_id.as_bytes());
    push_lp(&mut out, new_root_id.as_bytes());
    push_lp(&mut out, new_root_sig_pub);
    out.extend_from_slice(&role_epoch.to_be_bytes());
    out
}

/// Signing input for a UIK lineage succession certificate: the *old* UIK signs
/// the new UIK's id + public key so verifiers accept the new key under the old
/// identity (id continuity across rotation).
///
/// ```text
/// lp(DS_SUCCESSION) ‖ lp(old_id) ‖ lp(new_id) ‖ lp(new_pubkey)
/// ```
pub fn succession_input(old_id: &str, new_id: &str, new_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_SUCCESSION);
    push_lp(&mut out, old_id.as_bytes());
    push_lp(&mut out, new_id.as_bytes());
    push_lp(&mut out, new_pubkey);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    // ── Correctness (no magic values) ──────────────────────────────────────

    #[test]
    fn id_format_and_stability() {
        let uik = SigningIdentity::from_seed(&[0x42; 32]);
        let id = uik.user_id();
        assert!(id.starts_with("us_"), "user id prefix: {id}");
        assert_eq!(id.len(), 3 + 32, "us_ + 32 base32 chars");
        assert_eq!(id, uik.user_id(), "id is deterministic");
        // Agent and user id spaces are prefix-disjoint for the same key.
        assert_ne!(uik.id(IdKind::User), uik.id(IdKind::Agent));
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let uik = SigningIdentity::from_seed(&[7; 32]);
        let pk = uik.public_bytes();
        let msg = b"the owner signs the policy";
        let sig = uik.sign(msg);
        assert!(verify(&pk, msg, &sig));
        // Tampered message fails.
        assert!(!verify(&pk, b"the owner signs the polici", &sig));
        // Wrong key fails.
        let other = SigningIdentity::from_seed(&[8; 32]).public_bytes();
        assert!(!verify(&other, msg, &sig));
        // Tampered signature fails.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify(&pk, msg, &bad));
    }

    #[test]
    fn signatures_are_deterministic() {
        // Ed25519 is deterministic (RFC 8032): same key + msg ⇒ same signature.
        let uik = SigningIdentity::from_seed(&[0x42; 32]);
        let m = b"deterministic?";
        assert_eq!(uik.sign(m), uik.sign(m));
    }

    #[test]
    fn generate_is_random() {
        assert_ne!(
            SigningIdentity::generate().public_bytes(),
            SigningIdentity::generate().public_bytes()
        );
    }

    #[test]
    fn aik_identity_is_stable_per_root() {
        let root = AgentRoot::from_seed([0x11; 32]);
        let id0 = root.agent_id();
        assert!(id0.starts_with("ag_"));
        assert_eq!(id0, AgentRoot::from_seed([0x11; 32]).agent_id());
        assert_ne!(id0, AgentRoot::from_seed([0x12; 32]).agent_id());
    }

    #[test]
    fn config_sig_input_live_vs_tombstone_differ() {
        let live = config_sig_input("v1", "policy", 3, Some(b"{\"a\":1}"), "us_owner");
        let tomb = config_sig_input("v1", "policy", 3, None, "us_owner");
        assert_ne!(live, tomb, "status byte + body hash separate the two");
    }

    #[test]
    fn config_sig_input_lp_ambiguity_resolved() {
        // Without length prefixes ("ab","c") and ("a","bc") for (vault, ns)
        // would collide; with them the inputs differ.
        let a = config_sig_input("ab", "c", 1, Some(b"x"), "s");
        let b = config_sig_input("a", "bc", 1, Some(b"x"), "s");
        assert_ne!(a, b);
    }

    #[test]
    fn record_signature_input_every_field_binds() {
        let base = record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", true, "us_a");
        assert_ne!(base, record_signature_input("connection", b"\x01\x02", 3, "v1", b"ct", true, "us_a"), "type binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x03", 3, "v1", b"ct", true, "us_a"), "item_id binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 4, "v1", b"ct", true, "us_a"), "version binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v2", b"ct", true, "us_a"), "vault binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", false, "us_a"), "status (live/tombstone) binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"CT", true, "us_a"), "sealed body binds");
        assert_ne!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", true, "dv_a"), "principal binds");
        assert_eq!(base, record_signature_input("secret", b"\x01\x02", 3, "v1", b"ct", true, "us_a"), "deterministic");
    }

    #[test]
    fn record_signature_input_lp_ambiguity_resolved() {
        // ("ab","c") vs ("a","bc") for (type, item_id) would collide without
        // length prefixes; with them the inputs differ.
        let a = record_signature_input("ab", b"c", 1, "v", b"x", true, "s");
        let b = record_signature_input("a", b"bc", 1, "v", b"x", true, "s");
        assert_ne!(a, b);
    }

    #[test]
    fn record_signature_roundtrip_and_type_tamper() {
        // A principal signs a record; the daemon/server verify over the SAME
        // input (built from the plaintext type + the ciphertext hash). Swapping
        // the plaintext type to bypass the write-gate breaks verification —
        // the signature binds type↔sealed content (A1.3, kills type-class 越权).
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        let input = record_signature_input("agent", b"\xaa\xbb\xcc", 2, "vault-x", b"sealed-ct", true, &uik.user_id());
        let sig = uik.sign(&input);
        assert!(verify(&uik.public_bytes(), &input, &sig), "own signature verifies");
        let swapped = record_signature_input("secret", b"\xaa\xbb\xcc", 2, "vault-x", b"sealed-ct", true, &uik.user_id());
        assert!(!verify(&uik.public_bytes(), &swapped, &sig), "a swapped plaintext type must not verify");
    }

    #[test]
    fn device_request_signature_input_every_field_binds() {
        let h = "api.dev.safeclaw.pro";
        let base = device_request_signature_input("GET", "/p", 1, b"body", "dv_a", h);
        assert_ne!(base, device_request_signature_input("PUT", "/p", 1, b"body", "dv_a", h), "method binds");
        assert_ne!(base, device_request_signature_input("GET", "/q", 1, b"body", "dv_a", h), "path binds");
        assert_ne!(base, device_request_signature_input("GET", "/p", 2, b"body", "dv_a", h), "timestamp binds");
        assert_ne!(base, device_request_signature_input("GET", "/p", 1, b"BODY", "dv_a", h), "body binds");
        assert_ne!(base, device_request_signature_input("GET", "/p", 1, b"body", "dv_b", h), "device_id binds");
        assert_ne!(base, device_request_signature_input("GET", "/p", 1, b"body", "dv_a", "api.safeclaw.pro"), "canonical host binds");
        assert_eq!(base, device_request_signature_input("GET", "/p", 1, b"body", "dv_a", h), "deterministic");
    }

    #[test]
    fn device_request_signature_input_lp_ambiguity_resolved() {
        // ("GET","/p") vs ("GE","T/p") for (method, path) would collide without
        // length prefixes; with them the inputs differ.
        let a = device_request_signature_input("GET", "/p", 1, b"", "d", "h");
        let b = device_request_signature_input("GE", "T/p", 1, b"", "d", "h");
        assert_ne!(a, b);
    }

    #[test]
    fn device_request_roundtrip_and_path_tamper() {
        // The daemon signs a request with its DIK; the backend verifies over the
        // SAME input rebuilt from the wire (method/path/ts/body/device_id) plus
        // its configured host. Replaying the signature onto a different path
        // must fail — the DIK signature binds the request, not just the device.
        let dik = SigningIdentity::from_seed(&UIK_SEED);
        let dv_id = derive_id(IdKind::Device, &dik.public_bytes());
        let h = "api.dev.safeclaw.pro";
        let input = device_request_signature_input("PUT", "/device/vaults/x/items", 1_700_000_000, b"{}", &dv_id, h);
        let sig = dik.sign(&input);
        assert!(verify(&dik.public_bytes(), &input, &sig), "own signature verifies");
        let tampered = device_request_signature_input("PUT", "/device/vaults/y/items", 1_700_000_000, b"{}", &dv_id, h);
        assert!(!verify(&dik.public_bytes(), &tampered, &sig), "a swapped path must not verify");
    }

    #[test]
    fn agent_proxy_pop_input_every_field_binds() {
        let base = agent_proxy_pop_input("v1", "api.x.com:443", 1, "ag_a");
        assert_ne!(base, agent_proxy_pop_input("v2", "api.x.com:443", 1, "ag_a"), "vault binds");
        assert_ne!(base, agent_proxy_pop_input("v1", "api.y.com:443", 1, "ag_a"), "target binds");
        assert_ne!(base, agent_proxy_pop_input("v1", "api.x.com:443", 2, "ag_a"), "timestamp binds");
        assert_ne!(base, agent_proxy_pop_input("v1", "api.x.com:443", 1, "ag_b"), "agent_id binds");
        assert_eq!(base, agent_proxy_pop_input("v1", "api.x.com:443", 1, "ag_a"), "deterministic");
    }

    #[test]
    fn agent_proxy_pop_roundtrip_and_target_tamper() {
        // The sc transport signs a CONNECT with the AIK; the daemon rebuilds the
        // input from the CONNECT context (vid + target + ts + derived ag_id) and
        // verifies. Replaying the signature onto a different target must fail —
        // the token binds the destination, not just the agent.
        let aik = SigningIdentity::from_seed(&UIK_SEED);
        let ag = derive_id(IdKind::Agent, &aik.public_bytes());
        let input = agent_proxy_pop_input("vault-x", "api.openai.com:443", 1_700_000_000, &ag);
        let sig = aik.sign(&input);
        assert!(verify(&aik.public_bytes(), &input, &sig), "own signature verifies");
        let elsewhere = agent_proxy_pop_input("vault-x", "evil.example:443", 1_700_000_000, &ag);
        assert!(!verify(&aik.public_bytes(), &elsewhere, &sig), "a swapped target must not verify");
    }

    #[test]
    fn pinned_agent_proxy_pop_input() {
        // K-vector: vault "vault-7", target "api.x:443", ts 1700000000, agent "ag_a".
        let input = agent_proxy_pop_input("vault-7", "api.x:443", 1_700_000_000, "ag_a");
        assert_eq!(hex(&input), "0000001b73616665636c61772f76312f6167656e742d70726f78792d706f70000000077661756c742d37000000096170692e783a343433000000006553f1000000000461675f61");
    }

    #[test]
    fn pinned_record_signature_input() {
        // K-vector: type "secret", id 0x0102, version 7, vault "vault-7",
        // sealed body b"ct", live, principal "us_owner". Mirror pins the same.
        let input = record_signature_input("secret", b"\x01\x02", 7, "vault-7", b"ct", true, "us_owner");
        assert_eq!(hex(&input), "00000010737564702f76312f6974656d2d736967000000067365637265740000000201020000000000000007000000077661756c742d370100000020f8dcb34308e5c69f46a33cafa62bd922476b18c78a114eb144e34a5e374f7d600000000875735f6f776e6572");
    }

    // ── Pinned cross-language vectors ───────────────────────────────────────
    // Established first-party here; the TS `@sudp-protocol/authorizer` mirror
    // pins the same values when config-signing lands there. Do NOT edit an
    // expected value to make a test pass — find why Rust ↔ TS diverged.
    // (Filled from the first `cargo test identity` run.)

    const UIK_SEED: [u8; 32] = [0x42; 32];
    const AIK_ROOT: [u8; 32] = [0x11; 32];

    #[test]
    fn pinned_uik_pubkey_and_id() {
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        assert_eq!(
            hex(&uik.public_bytes()),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        );
        assert_eq!(uik.user_id(), "us_gcl6fxxcznfdjnjyidg3obno24igpq3p");
    }

    #[test]
    fn pinned_config_sig_input() {
        // K-vector: vault "vault-7", ns "policy", version 5, body {"k":"v"},
        // signer "us_owner".
        let input = config_sig_input("vault-7", "policy", 5, Some(b"{\"k\":\"v\"}"), "us_owner");
        assert_eq!(hex(&input), "0000001673616665636c61772f76312f636f6e6669672d736967000000077661756c742d3700000006706f6c69637900000000000000050100000020666c1aa02e8068c6d5cc1d3295009432c16790bec28ec8ce119d0d1a18d613190000000875735f6f776e6572");
    }

    #[test]
    fn pinned_config_signature() {
        let uik = SigningIdentity::from_seed(&UIK_SEED);
        let input = config_sig_input("vault-7", "policy", 5, Some(b"{\"k\":\"v\"}"), "us_owner");
        let sig = uik.sign(&input);
        assert_eq!(hex(&sig), "b6dcc1bd43082cfb16789191d73c65c9213093e2f827ca7e35084cd699668b668b798f97d47c8bb1ca584811f339f3f40430259a192d8c9bcef94a4f4d304304");
        assert!(verify(&uik.public_bytes(), &input, &sig));
    }

    #[test]
    fn pinned_aik_identity() {
        let root = AgentRoot::from_seed(AIK_ROOT);
        assert_eq!(
            hex(&root.identity().public_bytes()),
            "2a25e722dc68abfe33f7d78adc91904ed0c9b7f74b17c52e8338968c87e2357b"
        );
        assert_eq!(root.agent_id(), "ag_n7smudy334mfsttpye6oedc3fqp7pjrf");
    }



    #[test]
    fn pinned_rekey_vectors() {
        // DP-S1 re-key golden vectors (Part 2). FIXED inputs: vault "vault-7",
        // generation 5, signer "us_owner", and a fixed 32-byte commitment (the
        // value a retired content-only commitment produced; the rekey input only
        // carries 32 opaque bytes, and the full-bundle `k_commitment` has its own
        // shared vectors). Do NOT edit an expected value to make a test pass —
        // find why Rust ↔ TS diverged.
        let commit: [u8; 32] = [
            0x9f, 0x3f, 0xe2, 0x0e, 0x99, 0x95, 0xe6, 0x4c, 0x94, 0x03, 0xe7, 0x34, 0xe2, 0xa3,
            0xdc, 0xe8, 0xfd, 0x7a, 0x86, 0x59, 0xcc, 0x05, 0xd9, 0x99, 0x5c, 0xbd, 0x27, 0x7c,
            0x27, 0xd6, 0xf4, 0x99,
        ];
        // Membership anti-rollback commitment over an EMPTY log prefix (membership_len 0).
        let membership = membership_commitment(&[]);
        assert_eq!(
            hex(&membership),
            "2f12a37c5a33eff8fca2c3623090a825c377cd051cf786dddfc5dd3286d631af"
        );
        // Non-empty prefix (two sigs) — exercises the sig-concat path cross-language.
        let sig_a = [0xAAu8; 64];
        let sig_b = [0xBBu8; 64];
        assert_eq!(
            hex(&membership_commitment(&[&sig_a, &sig_b])),
            "b70c763903e84f63d918943fccb98554f1f384e4a42e0d59c44d54eae0feb3ca"
        );
        let input = rekey_sig_input("vault-7", 5, &commit, "us_owner", 0, &membership);
        assert_eq!(
            hex(&input),
            "0000001173616665636c61772f76312f72656b6579000000077661756c742d370000000000000005000000209f3fe20e9995e64c9403e734e2a3dce8fd7a8659cc05d9995cbd277c27d6f4990000000875735f6f776e65720000000000000000000000202f12a37c5a33eff8fca2c3623090a825c377cd051cf786dddfc5dd3286d631af"
        );
    }

    #[test]
    fn pinned_role_grant_input() {
        // Owner-authority role-grant golden vector (design/identity-uik-aik.md
        // §4.3). FIXED inputs: vault "vault-7", user "us_alice", role "member",
        // generation 3. The browser mirror pins the SAME hex when role-grant
        // signing lands there. Do NOT edit an expected value to make a test pass
        // — find why Rust ↔ TS diverged.
        let input = role_grant_input("vault-7", "us_alice", "member", 3);
        assert_eq!(
            hex(&input),
            "0000001673616665636c61772f76312f726f6c652d6772616e74000000077661756c742d370000000875735f616c696365000000066d656d6265720000000000000003"
        );
        // Role is bound: the same (vault, user, generation) under a different role differs.
        let owner = role_grant_input("vault-7", "us_alice", "owner", 3);
        assert_ne!(input, owner, "role token is part of the signed input");
        // F3-b generation-binding: the SAME (vault, user, role) at a different
        // generation differs, so a stale grant can't be replayed after a re-key.
        let next_gen = role_grant_input("vault-7", "us_alice", "member", 4);
        assert_ne!(input, next_gen, "generation is part of the signed input");
    }

    #[test]
    fn pinned_derive_id() {
        // Cross-language derive_id vector (base32-lower of SHA-256(pubkey)[..20]). The
        // backend + browser mirrors pin the SAME strings so the succession-chain id
        // binding (`new_root_id == derive_id(new_pub)`) agrees byte-for-byte.
        assert_eq!(
            derive_id(IdKind::User, &[0x11u8; 32]),
            "us_alketiy7xmthzdzvf2mwrj46hzp4sxa3"
        );
        assert_eq!(
            derive_id(IdKind::User, &[0x22u8; 32]),
            "us_t5zoudhusu3ohrtmpb7xaumg36neg6ai"
        );
        // Trust reset: the device prefix is `dv` (was `dev`).
        assert_eq!(
            derive_id(IdKind::Device, &[0x11u8; 32]),
            "dv_alketiy7xmthzdzvf2mwrj46hzp4sxa3"
        );
        assert_eq!(parse_id("dv_alketiy7xmthzdzvf2mwrj46hzp4sxa3"), Some(IdKind::Device));
        assert_eq!(parse_id("dev_alketiy7xmthzdzvf2mwrj46hzp4sxa3"), None);
    }

    #[test]
    fn pinned_delegation_event_input() {
        // Delegation-event golden vector (delegation-log-impl-spec.md §1.1). FIXED
        // inputs: vault "vault-7", op "set", subject "us_bob", role "owner", granter
        // "us_alice", seq 5, role_epoch 2. The browser + backend mirrors pin the SAME
        // hex. Do NOT edit an expected value to make a test pass — find why the
        // implementations diverged.
        let input = delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2);
        assert_eq!(
            hex(&input),
            "0000001c73616665636c61772f76312f64656c65676174696f6e2d6576656e74000000077661756c742d37000000037365740000000675735f626f62000000056f776e65720000000875735f616c69636500000000000000050000000000000002"
        );
        // A `remove` carries an EMPTY role token (so the same subject can't be spliced
        // between a set and a remove), and the seq / role_epoch are fixed-width tails.
        let remove = delegation_event_input("vault-7", "remove", "us_bob", "", "us_alice", 6, 2);
        assert_eq!(
            hex(&remove),
            "0000001c73616665636c61772f76312f64656c65676174696f6e2d6576656e74000000077661756c742d370000000672656d6f76650000000675735f626f62000000000000000875735f616c69636500000000000000060000000000000002"
        );
        // seq and role_epoch are both part of the signed input (reorder / replay guard).
        assert_ne!(
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2),
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 6, 2),
            "seq is bound"
        );
        assert_ne!(
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 2),
            delegation_event_input("vault-7", "set", "us_bob", "owner", "us_alice", 5, 3),
            "role_epoch is bound"
        );
    }

    #[test]
    fn pinned_root_succession_input() {
        // Root-succession golden vector (delegation-log-impl-spec.md §1.2). FIXED
        // inputs: vault "vault-7", old_root "us_alice", new_root "us_bob",
        // new_root_sig_pub = 32×0x11, role_epoch 4. Mirrors pin the SAME hex.
        let pub_key = [0x11u8; 32];
        let input = root_succession_input("vault-7", "us_alice", "us_bob", &pub_key, 4);
        assert_eq!(
            hex(&input),
            "0000001b73616665636c61772f76312f726f6f742d73756363657373696f6e000000077661756c742d370000000875735f616c6963650000000675735f626f620000002011111111111111111111111111111111111111111111111111111111111111110000000000000004"
        );
        // The new root's pubkey is bound (a colluding server can't swap in a key it
        // controls) and the epoch is a fixed-width tail (rollback guard).
        assert_ne!(
            input,
            root_succession_input("vault-7", "us_alice", "us_bob", &[0x22u8; 32], 4),
            "new_root_sig_pub is bound"
        );
        assert_ne!(
            input,
            root_succession_input("vault-7", "us_alice", "us_bob", &pub_key, 5),
            "role_epoch is bound"
        );
    }





    #[test]
    fn pinned_vault_tombstone_input() {
        // §15 leg-A golden vector. FIXED input: vault "vault-7". The Node (keyset-roles)
        // + TS (uik-crypto) mirrors pin the SAME hex. Do NOT edit an expected value to
        // make a test pass — find why Rust ↔ Node ↔ TS diverged.
        let input = vault_tombstone_input("vault-7");
        assert_eq!(hex(&input), "0000001b73616665636c61772f76312f7661756c742d746f6d6273746f6e65000000077661756c742d37");
    }

    #[test]
    fn vault_tombstone_roundtrip_and_vault_tamper() {
        // The owner signs a tombstone; the daemon rebuilds the input and verifies. A
        // signature over vault A must NOT verify as a tombstone for vault B (vault_id bound).
        let owner = SigningIdentity::from_seed(&UIK_SEED);
        let sig = owner.sign(&vault_tombstone_input("vault-a"));
        assert!(verify(&owner.public_bytes(), &vault_tombstone_input("vault-a"), &sig));
        assert!(!verify(&owner.public_bytes(), &vault_tombstone_input("vault-b"), &sig), "vault_id is bound");
    }
}
