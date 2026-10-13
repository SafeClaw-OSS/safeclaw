//! Agent proxy-connect proof-of-possession (hop-A of the mutual-mTLS transport,
//! `design/agent-device-identity-mtls.md` §9.1).
//!
//! An agent reaches the daemon through a STANDARD forward proxy (`HTTP_PROXY`).
//! A standard client can't present a client cert to a forward proxy — its only
//! client-auth channel is the `Proxy-Authorization` header on each `CONNECT`. So
//! hop-A (like hop-B under Railway) carries the AIK identity as an application-
//! layer proof-of-possession (PoP): a fresh signed credential in the standard
//! auth header. This is a well-trodden pattern — its closest named standard is
//! OAuth **DPoP (RFC 9449, "Demonstrating Proof of Possession")**, which likewise
//! puts a per-request key-signed token in an HTTP header; cf. also RFC 9421 (HTTP
//! Message Signatures) and AWS SigV4. mTLS is the *transport-layer* PoP; this is
//! the *application-layer* one, chosen because a forward proxy exposes no
//! client-cert channel (see the module CONNECT note below). We use a compact
//! bespoke token rather than a DPoP JWT only to reuse hop-B's signing primitive
//! and save bytes; the shape is DPoP-style.
//!
//! The `sc` transport (which holds the AIK, keeping it OUT of the agent's env)
//! signs one token per CONNECT with [`AgentProxyPopSigner`]; the daemon parses +
//! verifies it with [`verify_agent_proxy_pop`] and then checks the resolved
//! `ag_id` against the vault's authorized-agents table. ADDITIVE / dual-auth: a
//! non-PoP password falls back to the legacy api-key hash-set, so nothing bricks.
//!
//! Wire format of the `Proxy-Authorization` password slot:
//! ```text
//! scpop1.<b64url(aik_pubkey[32])>.<unix_ts>.<b64url(sig[64])>
//! ```
//! `.`-separated (b64url has no `.`), and the prefix `scpop1.` is unambiguous vs.
//! an `sc_…` api-key. The pubkey is carried so the token is self-verifying (the
//! daemon derives `ag_id` from it); `vault_id`/`target` are NOT carried — they
//! come from the CONNECT context and the daemon rebuilds the signing input, so a
//! token can't be lifted to a different vault or destination.

use crate::identity::{agent_proxy_pop_input, derive_id, verify, IdKind, SigningIdentity};
use data_encoding::BASE64URL_NOPAD;

/// Token scheme tag — the first `.`-segment. Distinguishes a PoP token from a
/// legacy `sc_…` api-key in the same password slot (dual-auth).
pub const TOKEN_PREFIX: &str = "scpop1";

/// Default freshness window (± seconds) the daemon accepts a token's timestamp
/// within. Generous enough for agent/daemon clock skew, tight enough that a
/// captured token goes stale fast (it's also bound to one vault+target).
pub const DEFAULT_MAX_SKEW_SECS: u64 = 300;

/// Build the hop-A PoP `target` for the daemon's **api-face** (origin-form reads:
/// `/v/{vid}/registry`, `/op/{id}`, `/vaults`). Namespaced by the `apiface:`
/// prefix so a token minted for a read can't be replayed as a CONNECT tunnel
/// (whose target is a raw `host:port`) or a plain-http forward. The shim signs
/// this over the exact request-line target it sends; the daemon rebuilds it from
/// `req.uri().path_and_query()` — the two MUST match byte-for-byte, so both sides
/// go through THIS one builder.
pub fn apiface_target(path_and_query: &str) -> String {
    format!("apiface:{}", path_and_query)
}

/// Request header carrying an agent's PoP token on the daemon's LOCAL op API
/// (`POST /v/{vid}/op`, which the CLI ceremonies use: `sc unlock`, `sc secret
/// get`, `sc connection add`, ...). Same token format as the proxy channel.
pub const OP_POP_HEADER: &str = "x-sc-agent-pop";

/// Build the PoP `target` that binds a token to ONE operation an agent asks
/// the local op API to create: `op:` + base64url(SHA-256(canonical op bytes)),
/// the canonical encoding the approval binding itself hashes
/// (`Operation::canonical_bytes`). The vault id rides the signing input as
/// usual, so a token for one op or vault never verifies for another, and the
/// `op:` namespace keeps it apart from CONNECT (`host:port`) and `apiface:`
/// targets. `None` when the op has no canonical form (a float in its scope),
/// which simply means no attribution.
///
/// Attribution on this loopback API is DISPLAY and consent information (it
/// names the agent on the approval), not a security boundary: any local
/// process can omit the token, and the op then reads as coming from a
/// terminal. Nothing is authorized by it.
pub fn op_target(op: &crate::protocol::operation::Operation) -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = op.canonical_bytes().ok()?;
    Some(format!(
        "op:{}",
        BASE64URL_NOPAD.encode(&Sha256::digest(&bytes))
    ))
}

/// Daemon side of [`op_target`]: the `ag_…` id that proved possession over
/// exactly `op` for `vault_id`, or `None` (absent, malformed, stale, or signed
/// over anything else).
pub fn verify_op_pop(
    token: &str,
    vault_id: &str,
    op: &crate::protocol::operation::Operation,
    now: u64,
) -> Option<String> {
    let target = op_target(op)?;
    verify_agent_proxy_pop(token.trim(), vault_id, &target, now, DEFAULT_MAX_SKEW_SECS)
}

/// The agent's AIK signer from `SAFECLAW_AGENT_IDENTITY` (a PATH to the agent
/// identity file, per the locked naming, NOT a secret). `None` when unset,
/// unreadable, or not an agent identity.
pub fn signer_from_env() -> Option<AgentProxyPopSigner> {
    let path = std::env::var_os("SAFECLAW_AGENT_IDENTITY").filter(|p| !p.is_empty())?;
    let loaded = crate::identity_file::load(std::path::Path::new(&path)).ok()?;
    if loaded.kind != IdKind::Agent {
        return None;
    }
    Some(AgentProxyPopSigner::new(loaded.identity, loaded.id))
}

/// Signs one proxy-connect PoP token per CONNECT. Holds the agent's AIK and its
/// `ag_…` self-id. Lives in the `sc` transport, never in the agent's env.
pub struct AgentProxyPopSigner {
    identity: SigningIdentity,
    agent_id: String,
}

impl AgentProxyPopSigner {
    pub fn new(identity: SigningIdentity, agent_id: String) -> Self {
        Self { identity, agent_id }
    }

    /// This signer's `ag_…` id.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Produce the `Proxy-Authorization` password token for a CONNECT to `target`
    /// (`host:port`) on `vault_id`, stamped `timestamp` (unix seconds; pass the
    /// real clock at the call site — this stays clock-free for deterministic
    /// tests).
    pub fn token(&self, vault_id: &str, target: &str, timestamp: u64) -> String {
        let input = agent_proxy_pop_input(vault_id, target, timestamp, &self.agent_id);
        let sig = self.identity.sign(&input);
        format!(
            "{}.{}.{}.{}",
            TOKEN_PREFIX,
            BASE64URL_NOPAD.encode(&self.identity.public_bytes()),
            timestamp,
            BASE64URL_NOPAD.encode(&sig),
        )
    }

    /// The local-op-API token ([`OP_POP_HEADER`]) proving this agent asks for
    /// exactly `op` on `vault_id` ([`op_target`]). `None` when the op has no
    /// canonical form.
    pub fn op_token(
        &self,
        vault_id: &str,
        op: &crate::protocol::operation::Operation,
        timestamp: u64,
    ) -> Option<String> {
        Some(self.token(vault_id, &op_target(op)?, timestamp))
    }
}

/// Parse + verify a proxy-auth PoP token against the CONNECT context. Returns the
/// resolved `ag_…` id iff the token is well-formed, its signature verifies under
/// the carried pubkey over the rebuilt input (`vault_id`+`target`+`ts`+`ag_id`),
/// and it is fresh (`|now - ts| <= max_skew`). Returns `None` for anything that
/// isn't a valid, fresh PoP token — a legacy api-key, a malformed token, a bad
/// signature, or a stale one — so the caller falls back to the api-key hash-set
/// (dual-auth). Never panics. Does NOT check authorization: the caller must still
/// confirm the returned `ag_id` is in the vault's authorized-agents table.
pub fn verify_agent_proxy_pop(
    token: &str,
    vault_id: &str,
    target: &str,
    now: u64,
    max_skew: u64,
) -> Option<String> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?.strip_prefix('.')?;
    let mut parts = rest.split('.');
    let pub_b64 = parts.next()?;
    let ts_str = parts.next()?;
    let sig_b64 = parts.next()?;
    if parts.next().is_some() {
        return None; // extra segments → malformed
    }

    let pub_vec = BASE64URL_NOPAD.decode(pub_b64.as_bytes()).ok()?;
    let pubkey: [u8; 32] = pub_vec.as_slice().try_into().ok()?;
    let sig_vec = BASE64URL_NOPAD.decode(sig_b64.as_bytes()).ok()?;
    let sig: [u8; 64] = sig_vec.as_slice().try_into().ok()?;
    let ts: u64 = ts_str.parse().ok()?;

    // Freshness (symmetric window, saturating so a clock blip never panics).
    let skew = now.max(ts) - now.min(ts);
    if skew > max_skew {
        return None;
    }

    let agent_id = derive_id(IdKind::Agent, &pubkey);
    let input = agent_proxy_pop_input(vault_id, target, ts, &agent_id);
    if verify(&pubkey, &input, &sig) {
        Some(agent_id)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> AgentProxyPopSigner {
        let seed = [9u8; 32];
        let id = SigningIdentity::from_seed(&seed);
        let ag = derive_id(IdKind::Agent, &id.public_bytes());
        AgentProxyPopSigner::new(id, ag)
    }

    #[test]
    fn token_roundtrips_and_resolves_agent_id() {
        let s = signer();
        let tok = s.token("vault-x", "api.openai.com:443", 1_700_000_000);
        assert!(tok.starts_with("scpop1."));
        let got = verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_000, 300);
        assert_eq!(got.as_deref(), Some(s.agent_id()));
    }

    #[test]
    fn wrong_vault_or_target_fails() {
        let s = signer();
        let tok = s.token("vault-x", "api.openai.com:443", 1_700_000_000);
        assert!(verify_agent_proxy_pop(&tok, "vault-y", "api.openai.com:443", 1_700_000_000, 300).is_none());
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "evil.example:443", 1_700_000_000, 300).is_none());
    }

    #[test]
    fn stale_token_rejected() {
        let s = signer();
        let tok = s.token("vault-x", "api.openai.com:443", 1_700_000_000);
        // 301s in the future → outside the 300s window.
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_301, 300).is_none());
        // within window (299s) → ok.
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_299, 300).is_some());
    }

    #[test]
    fn apiface_token_binds_path_and_cant_replay_as_connect() {
        let s = signer();
        // A token minted for an api-face read (target = apiface:<pq>, account-
        // scoped vault="") verifies only for that exact path…
        let tok = s.token("", &apiface_target("/v/abc/registry"), 1_700_000_000);
        assert_eq!(
            verify_agent_proxy_pop(&tok, "", &apiface_target("/v/abc/registry"), 1_700_000_000, 300).as_deref(),
            Some(s.agent_id())
        );
        // …not another api-face path…
        assert!(verify_agent_proxy_pop(&tok, "", &apiface_target("/v/other/registry"), 1_700_000_000, 300).is_none());
        // …and never as a CONNECT tunnel to some host:port (cross-channel replay).
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_000, 300).is_none());
        assert!(verify_agent_proxy_pop(&tok, "", "/v/abc/registry", 1_700_000_000, 300).is_none());
    }

    fn op(target: &str, scope: serde_json::Value) -> crate::protocol::operation::Operation {
        serde_json::from_value(serde_json::json!({
            "act": { "type": { "custom": "secret-rm" }, "target": target, "scope": scope },
            "bind": { "redeemer": "vault-x" },
            "valid": { "iat": 1_700_000_000u64, "multiplicity": 1 }
        }))
        .unwrap()
    }

    /// An op token binds the exact op (canonical bytes) and vault: any change
    /// to the op, another vault, or another channel fails.
    #[test]
    fn op_token_binds_the_exact_op_and_vault() {
        let s = signer();
        let o = op("GITHUB_TOKEN", serde_json::Value::Null);
        let tok = s.op_token("vault-x", &o, 1_700_000_000).unwrap();
        assert_eq!(
            verify_op_pop(&tok, "vault-x", &o, 1_700_000_000).as_deref(),
            Some(s.agent_id())
        );
        assert!(verify_op_pop(&tok, "vault-y", &o, 1_700_000_000).is_none());
        let other = op("STRIPE_KEY", serde_json::Value::Null);
        assert!(verify_op_pop(&tok, "vault-x", &other, 1_700_000_000).is_none());
        let scoped = op("GITHUB_TOKEN", serde_json::json!({ "agent": "ag_other" }));
        assert!(verify_op_pop(&tok, "vault-x", &scoped, 1_700_000_000).is_none());
        assert!(verify_op_pop(&tok, "vault-x", &o, 1_700_000_301).is_none(), "stale");
        // Not usable as a CONNECT or api-face proof.
        let target = op_target(&o).unwrap();
        assert!(target.starts_with("op:"));
        assert!(verify_agent_proxy_pop(&tok, "vault-x", "api.openai.com:443", 1_700_000_000, 300).is_none());
        assert!(verify_agent_proxy_pop(&tok, "", &apiface_target("/op/x"), 1_700_000_000, 300).is_none());
        // A CONNECT token is not an op proof.
        let connect = s.token("vault-x", "api.openai.com:443", 1_700_000_000);
        assert!(verify_op_pop(&connect, "vault-x", &o, 1_700_000_000).is_none());
    }

    #[test]
    fn legacy_api_key_is_not_a_pop_token() {
        // A non-PoP password (an api-key) → None, so the caller falls back to the
        // api-key hash-set (dual-auth, nothing bricks).
        assert!(verify_agent_proxy_pop("sc_agent_alice", "vault-x", "api.x:443", 1_700_000_000, 300).is_none());
        assert!(verify_agent_proxy_pop("scpop1.garbage", "vault-x", "api.x:443", 1_700_000_000, 300).is_none());
    }
}
