//! Pairing by PAKE short code (grant-v3 contract C2; the Magic Wormhole
//! pattern): a nameplate the backend allocates (routing only) plus an 8-digit
//! secret `sc` generates and never sends, run through SPAKE2 (RustCrypto
//! `spake2` 0.4, `Ed25519Group`, symmetric) over the untrusted backend relay.
//! The shared key authenticates this machine's keys to the approving browser
//! (`keys_mac`) and the approving owner back to this machine (`owner_mac`).
//!
//! This module is the byte-exact construction (the console runs the same crate
//! as WebAssembly and mirrors the MACs); the HTTP flow lives in
//! `cli::pair_flow`.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

/// SPAKE2 identity prefix; the pinned console origin follows it.
pub const DS_PAIR: &[u8] = b"safeclaw/v1/pair";
/// HKDF info of `k_keys` and the `keys_mac` domain.
pub const DS_PAIR_KEYS: &[u8] = b"safeclaw/v1/pair/keys";
/// Domain of the ordered principal-set MAC input.
pub const DS_PAIR_KEYS_SET: &[u8] = b"safeclaw/v1/pair/keys-set";
/// HKDF info of `k_owner` and the `owner_mac` domain.
pub const DS_PAIR_OWNER: &[u8] = b"safeclaw/v1/pair/owner";

/// A SPAKE2 0.4 symmetric message: side byte `0x53` ‖ 32-byte element.
pub const MSG_LEN: usize = 33;

fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// The 8 random decimal digits of the code (CSPRNG). Never leaves `sc`.
pub fn gen_secret() -> Zeroizing<String> {
    use rand::Rng;
    let n: u32 = rand::rngs::OsRng.gen_range(0..100_000_000);
    Zeroizing::new(format!("{:08}", n))
}

/// SPAKE2 password: UTF-8 `"NNNN-SSSSSSSS"`.
pub fn password(nameplate: &str, secret: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(format!("{}-{}", nameplate, secret).into_bytes())
}

/// SPAKE2 identity: `"safeclaw/v1/pair" ‖ console origin` (dev and prod
/// transcripts never cross).
pub fn identity(origin: &str) -> Vec<u8> {
    let mut v = DS_PAIR.to_vec();
    v.extend_from_slice(origin.trim_end_matches('/').as_bytes());
    v
}

/// The code `sc` shows: `NNNN-SSSS-SSSS`.
pub fn display_code(nameplate: &str, secret: &str) -> String {
    format!("{}-{}-{}", nameplate, &secret[..4], &secret[4..])
}

/// The two 32-byte subkeys of the SPAKE2 output `K`.
pub struct Subkeys {
    pub k_keys: Zeroizing<[u8; 32]>,
    pub k_owner: Zeroizing<[u8; 32]>,
}

/// `k_keys` / `k_owner` = HKDF-SHA256(ikm = K, salt = empty, info = domain).
pub fn subkeys(k: &[u8]) -> Subkeys {
    let hk = Hkdf::<Sha256>::new(Some(&[]), k);
    let mut k_keys = Zeroizing::new([0u8; 32]);
    let mut k_owner = Zeroizing::new([0u8; 32]);
    hk.expand(DS_PAIR_KEYS, &mut k_keys[..])
        .expect("32 bytes is a valid HKDF-SHA256 length");
    hk.expand(DS_PAIR_OWNER, &mut k_owner[..])
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Subkeys { k_keys, k_owner }
}

/// One entry in the ordered principal set authenticated by [`keys_mac`].
#[derive(Debug, Clone, Copy)]
pub struct PairEntry<'a> {
    pub kind: &'a str,
    pub id: &'a str,
    pub name: &'a str,
    pub id_pub: &'a [u8],
    /// Raw X25519 public key for a device, empty for an agent.
    pub sc_pk: &'a [u8],
}

/// `lp("safeclaw/v1/pair/keys-set") ‖ u32_be(n) ‖` each ordered entry as
/// `lp(kind) ‖ lp(id) ‖ lp(name) ‖ lp(id_pub) ‖ lp(sc_pk | empty)`.
pub fn keys_mac_set_input(entries: &[PairEntry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_PAIR_KEYS_SET);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        push_lp(&mut out, entry.kind.as_bytes());
        push_lp(&mut out, entry.id.as_bytes());
        push_lp(&mut out, entry.name.as_bytes());
        push_lp(&mut out, entry.id_pub);
        push_lp(&mut out, entry.sc_pk);
    }
    out
}

/// `lp("safeclaw/v1/pair/owner") ‖ lp(uik_id) ‖ lp(uik_pub)`.
pub fn owner_mac_input(uik_id: &str, uik_pub: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, DS_PAIR_OWNER);
    push_lp(&mut out, uik_id.as_bytes());
    push_lp(&mut out, uik_pub);
    out
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// `keys_mac = HMAC-SHA256(k_keys, keys_mac_set_input(entries))`: this
/// command's complete ordered principal set, authenticated to the browser that
/// holds the same code.
pub fn keys_mac(k_keys: &[u8], entries: &[PairEntry<'_>]) -> [u8; 32] {
    hmac(k_keys, &keys_mac_set_input(entries))
}

/// `owner_mac = HMAC-SHA256(k_owner, owner_mac_input(..))`: the approving owner,
/// authenticated back to `sc`.
pub fn owner_mac(k_owner: &[u8], uik_id: &str, uik_pub: &[u8]) -> [u8; 32] {
    hmac(k_owner, &owner_mac_input(uik_id, uik_pub))
}

/// Why a SPAKE2 run ended without a key. Every failure kills the code: the
/// caller discards the secret and the user starts a new pairing.
#[derive(Debug, PartialEq, Eq)]
pub enum PakeError {
    /// The peer's message is our own message bounced back.
    Reflected,
    /// Wrong length / side / not a group element.
    Malformed,
}

/// One SPAKE2 run for one secret. `finish` CONSUMES it, so a secret is
/// finished at most once.
pub struct PakeSession {
    state: Spake2<Ed25519Group>,
    msg: Vec<u8>,
}

impl PakeSession {
    /// Start with the OS CSPRNG.
    pub fn start(nameplate: &str, secret: &str, origin: &str) -> Self {
        Self::start_with_rng(nameplate, secret, origin, rand::rngs::OsRng)
    }

    /// Start with a caller RNG (deterministic vectors use a seeded one).
    pub fn start_with_rng(
        nameplate: &str,
        secret: &str,
        origin: &str,
        rng: impl rand::CryptoRng + rand::RngCore,
    ) -> Self {
        let pw = password(nameplate, secret);
        let (state, msg) = Spake2::<Ed25519Group>::start_symmetric_with_rng(
            &Password::new(&pw[..]),
            &Identity::new(&identity(origin)),
            rng,
        );
        Self { state, msg }
    }

    /// Our message (`msg_sc`).
    pub fn msg(&self) -> &[u8] {
        &self.msg
    }

    /// Finish against the peer's message: refuses a reflected or malformed one.
    pub fn finish(self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, PakeError> {
        if peer == self.msg.as_slice() {
            return Err(PakeError::Reflected);
        }
        if peer.len() != MSG_LEN {
            return Err(PakeError::Malformed);
        }
        self.state
            .finish(peer)
            .map(Zeroizing::new)
            .map_err(|_| PakeError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    const ORIGIN: &str = "https://app.dev.safeclaw.pro";

    #[test]
    fn both_sides_agree_and_macs_bind() {
        let a = PakeSession::start("0421", "12345678", ORIGIN);
        let b = PakeSession::start("0421", "12345678", ORIGIN);
        let (ma, mb) = (a.msg().to_vec(), b.msg().to_vec());
        let ka = a.finish(&mb).unwrap();
        let kb = b.finish(&ma).unwrap();
        assert_eq!(&ka[..], &kb[..]);
        let s = subkeys(&ka);
        assert_ne!(&s.k_keys[..], &s.k_owner[..]);
        let id_pub = [1u8; 32];
        let sc_pk = [2u8; 32];
        let changed_sc_pk = [3u8; 32];
        let entry = PairEntry {
            kind: "device",
            id: "dev_x",
            name: "box",
            id_pub: &id_pub,
            sc_pk: &sc_pk,
        };
        let m = keys_mac(&s.k_keys[..], &[entry]);
        assert_ne!(
            m,
            keys_mac(
                &s.k_keys[..],
                &[PairEntry {
                    sc_pk: &changed_sc_pk,
                    ..entry
                }]
            )
        );
    }

    fn entry<'a>(
        kind: &'a str,
        id: &'a str,
        name: &'a str,
        id_pub: &'a [u8],
        sc_pk: &'a [u8],
    ) -> PairEntry<'a> {
        PairEntry {
            kind,
            id,
            name,
            id_pub,
            sc_pk,
        }
    }

    #[test]
    fn set_mac_input_binds_order_and_every_field() {
        let device_pub = [1u8; 32];
        let agent_pub = [2u8; 32];
        let device_sc = [3u8; 32];
        let changed_pub = [4u8; 32];
        let changed_sc = [5u8; 32];
        let device = entry("device", "dev_a", "box", &device_pub, &device_sc);
        let agent = entry("agent", "ag_a", "codex", &agent_pub, &[]);
        let input = keys_mac_set_input(&[device, agent]);

        assert_ne!(input, keys_mac_set_input(&[agent, device]), "order");
        assert_ne!(
            input,
            keys_mac_set_input(&[
                entry("agent", "dev_a", "box", &device_pub, &device_sc),
                agent
            ]),
            "kind"
        );
        assert_ne!(
            input,
            keys_mac_set_input(&[
                entry("device", "dev_b", "box", &device_pub, &device_sc),
                agent
            ]),
            "id"
        );
        assert_ne!(
            input,
            keys_mac_set_input(&[
                entry("device", "dev_a", "laptop", &device_pub, &device_sc),
                agent
            ]),
            "name"
        );
        assert_ne!(
            input,
            keys_mac_set_input(&[
                entry("device", "dev_a", "box", &changed_pub, &device_sc),
                agent
            ]),
            "id_pub"
        );
        assert_ne!(
            input,
            keys_mac_set_input(&[
                entry("device", "dev_a", "box", &device_pub, &changed_sc),
                agent
            ]),
            "sc_pk"
        );
    }

    #[test]
    fn set_mac_input_binds_count_and_domain() {
        let id_pub = [1u8; 32];
        let sc_pk = [2u8; 32];
        let device = entry("device", "dev_a", "box", &id_pub, &sc_pk);
        assert_ne!(
            keys_mac_set_input(&[device]),
            keys_mac_set_input(&[device, device]),
            "n"
        );
        assert_ne!(
            keys_mac_set_input(&[device]),
            keys_mac_set_input(&[]),
            "set versus no entries"
        );
        assert!(keys_mac_set_input(&[device]).starts_with(&[
            0,
            0,
            0,
            DS_PAIR_KEYS_SET.len() as u8
        ]));
    }

    #[test]
    fn a_wrong_secret_or_origin_yields_another_key() {
        let run = |sa: &str, oa: &str| {
            let a = PakeSession::start("0421", sa, oa);
            let b = PakeSession::start("0421", "12345678", ORIGIN);
            let (ma, mb) = (a.msg().to_vec(), b.msg().to_vec());
            (a.finish(&mb).unwrap(), b.finish(&ma).unwrap())
        };
        let (x, y) = run("12345679", ORIGIN);
        assert_ne!(&x[..], &y[..], "wrong secret");
        let (x, y) = run("12345678", "https://app.safeclaw.pro");
        assert_ne!(&x[..], &y[..], "dev and prod never cross");
    }

    #[test]
    fn reflection_and_garbage_are_refused() {
        let a = PakeSession::start("0421", "12345678", ORIGIN);
        let own = a.msg().to_vec();
        assert_eq!(a.finish(&own).unwrap_err(), PakeError::Reflected);
        let a = PakeSession::start("0421", "12345678", ORIGIN);
        assert_eq!(a.finish(&[0x53; 5]).unwrap_err(), PakeError::Malformed);
    }

    #[test]
    fn seeded_runs_are_deterministic() {
        let a1 =
            PakeSession::start_with_rng("0421", "12345678", ORIGIN, StdRng::from_seed([1; 32]));
        let a2 =
            PakeSession::start_with_rng("0421", "12345678", ORIGIN, StdRng::from_seed([1; 32]));
        assert_eq!(a1.msg(), a2.msg());
        assert_eq!(a1.msg().len(), MSG_LEN);
        assert_eq!(a1.msg()[0], 0x53);
    }

    #[test]
    fn code_shape() {
        assert_eq!(display_code("0421", "12345678"), "0421-1234-5678");
        let s = gen_secret();
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }
}
