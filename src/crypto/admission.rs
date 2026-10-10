//! Admit-by-code (trust-reset design D2/D3, contract 1.2): the ONE admission
//! ceremony for devices, agents and passkeys.
//!
//! The new side generates its keys and a secret code `s` (10 random bytes, shown
//! as 16 Crockford base32 characters) and posts `{kind, sig_pub, enc_pub?, label,
//! extra?, lookup, commit}`. `s` is never sent anywhere. The approving console
//! has the human TYPE `s`, recomputes `commit` from the served fields and refuses
//! on mismatch; after the passkey ceremony it returns `mac` over the signed
//! effect. The new side verifies `mac` and that the effect covers its own keys.
//! A server that doesn't know `s` can neither re-home an admission (mac) nor
//! swap a key in it (commit).
//!
//! ```text
//! lookup     = hex(HKDF(s, "safeclaw/v1/admit-lookup")[..16])
//! commit_key = HKDF(s, "safeclaw/v1/admit-commit")
//! commit     = HMAC(commit_key, lp(kind) ‖ lp(sig_pub) ‖ lp(enc_pub) ‖ lp(label) ‖ lp(extra))
//! mac_key    = HKDF(s, "safeclaw/v1/admit-mac")
//! mac        = HMAC(mac_key, lp(effect) ‖ lp(uik_sign_pub32) ‖ lp(us_) ‖ lp(email))
//! ```
//!
//! HKDF is HKDF-SHA256 with an empty salt and the label as info; HMAC is
//! HMAC-SHA256. Cross-language vectors: `trust_reset_vectors.json` (`admit_code`).

use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sudp::primitives::{Kdf, PrimitiveSuite, StdPrimitives};
use zeroize::Zeroizing;

use crate::crypto::ledger::{LedgerEventFields, KIND_DEVICE, KIND_PASSKEY, OP_ADMIT};
use crate::identity::{derive_id, push_lp, IdKind};

/// Bytes of entropy in an admit code (80 bits).
pub const ADMIT_CODE_BYTES: usize = 10;
/// Characters in a normalized admit code (80 bits / 5).
pub const ADMIT_CODE_CHARS: usize = 16;
/// Crockford base32 alphabet (no I, L, O, U).
pub const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// HKDF label for the public lookup key.
pub const LABEL_ADMIT_LOOKUP: &[u8] = b"safeclaw/v1/admit-lookup";
/// HKDF label for the commit HMAC key.
pub const LABEL_ADMIT_COMMIT: &[u8] = b"safeclaw/v1/admit-commit";
/// HKDF label for the result-mac HMAC key.
pub const LABEL_ADMIT_MAC: &[u8] = b"safeclaw/v1/admit-mac";

fn hkdf32(ikm: &[u8], label: &[u8]) -> [u8; 32] {
    <StdPrimitives as PrimitiveSuite>::Kdf::derive_32(ikm, &[], label)
        .expect("HKDF-SHA256 derive_32 is infallible for a 32-byte output")
}

fn hmac256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

fn hmac256_verify(key: &[u8; 32], msg: &[u8], tag: &[u8]) -> bool {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.verify_slice(tag).is_ok()
}

/// Normalize a typed admit code (contract 1.2): drop `-` and spaces, ASCII
/// upper-case, map `O→0` and `I`/`L→1`, then require exactly 16 characters of the
/// Crockford alphabet. Any other character — including non-ASCII ones whose
/// Unicode upper-case is ASCII (`ı`, `ſ`) and other whitespace — is rejected.
pub fn normalize_admit_code(input: &str) -> Option<String> {
    let mut out = String::with_capacity(ADMIT_CODE_CHARS);
    for ch in input.chars() {
        if ch == '-' || ch == ' ' {
            continue;
        }
        if !ch.is_ascii() {
            return None;
        }
        let c = match ch.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !CROCKFORD_ALPHABET.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == ADMIT_CODE_CHARS).then_some(out)
}

/// The secret admit code `s`. Zeroized on drop; never serialized, never sent.
pub struct AdmitCode(Zeroizing<[u8; ADMIT_CODE_BYTES]>);

impl AdmitCode {
    /// Mint a fresh code from the OS CSPRNG (the new side).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut s = Zeroizing::new([0u8; ADMIT_CODE_BYTES]);
        rand::rngs::OsRng.fill_bytes(&mut *s);
        Self(s)
    }

    /// Adopt raw code bytes.
    pub fn from_bytes(s: [u8; ADMIT_CODE_BYTES]) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Parse a typed code (see [`normalize_admit_code`]).
    pub fn parse(input: &str) -> Option<Self> {
        let norm = normalize_admit_code(input)?;
        let mut acc: u128 = 0;
        for c in norm.bytes() {
            let v = CROCKFORD_ALPHABET.iter().position(|&a| a == c)? as u128;
            acc = (acc << 5) | v;
        }
        let mut s = Zeroizing::new([0u8; ADMIT_CODE_BYTES]);
        s.copy_from_slice(&acc.to_be_bytes()[16 - ADMIT_CODE_BYTES..]);
        Some(Self(s))
    }

    /// The raw 10 code bytes.
    pub fn as_bytes(&self) -> &[u8; ADMIT_CODE_BYTES] {
        &self.0
    }

    /// The display form `XXXX-XXXX-XXXX-XXXX` (Crockford, MSB-first).
    pub fn display(&self) -> String {
        let mut buf = [0u8; 16];
        buf[16 - ADMIT_CODE_BYTES..].copy_from_slice(&self.0[..]);
        let n = u128::from_be_bytes(buf);
        let mut out = String::with_capacity(ADMIT_CODE_CHARS + 3);
        for i in 0..ADMIT_CODE_CHARS {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            let v = ((n >> (75 - 5 * i)) & 31) as usize;
            out.push(CROCKFORD_ALPHABET[v] as char);
        }
        out
    }

    /// The three HKDF-split values (contract 1.2).
    pub fn keys(&self) -> AdmitKeys {
        let lookup_full = hkdf32(&self.0[..], LABEL_ADMIT_LOOKUP);
        let lookup = lookup_full[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        AdmitKeys {
            lookup,
            commit_key: Zeroizing::new(hkdf32(&self.0[..], LABEL_ADMIT_COMMIT)),
            mac_key: Zeroizing::new(hkdf32(&self.0[..], LABEL_ADMIT_MAC)),
        }
    }
}

/// The values derived from an admit code. `lookup` is public (it addresses the
/// pending admission); the two keys are secret.
pub struct AdmitKeys {
    /// 32 lowercase hex characters.
    pub lookup: String,
    pub commit_key: Zeroizing<[u8; 32]>,
    pub mac_key: Zeroizing<[u8; 32]>,
}

/// What is being admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitKind {
    Device,
    Agent,
    Passkey,
}

impl AdmitKind {
    /// The wire / commit token.
    pub fn as_str(self) -> &'static str {
        match self {
            AdmitKind::Device => "device",
            AdmitKind::Agent => "agent",
            AdmitKind::Passkey => "passkey",
        }
    }

    /// Parse the wire token.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "device" => Some(AdmitKind::Device),
            "agent" => Some(AdmitKind::Agent),
            "passkey" => Some(AdmitKind::Passkey),
            _ => None,
        }
    }
}

/// The committed fields of an admission (contract 1.2 "Field values by kind").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionFields {
    pub kind: AdmitKind,
    /// device: DIK pub (32) · agent: AIK pub (32) · passkey: COSE `x‖y` (64).
    pub sig_pub: Vec<u8>,
    /// device: device enc pub (32) · agent: empty · passkey: ephemeral X25519 pub (32).
    pub enc_pub: Vec<u8>,
    pub label: String,
    /// passkey: raw credential id (non-empty) · otherwise empty.
    pub extra: Vec<u8>,
}

impl AdmissionFields {
    /// Field shapes by kind. Check this before computing or trusting a commit.
    pub fn is_well_formed(&self) -> bool {
        match self.kind {
            AdmitKind::Device => {
                self.sig_pub.len() == 32 && self.enc_pub.len() == 32 && self.extra.is_empty()
            }
            AdmitKind::Agent => {
                self.sig_pub.len() == 32 && self.enc_pub.is_empty() && self.extra.is_empty()
            }
            AdmitKind::Passkey => {
                self.sig_pub.len() == 64 && self.enc_pub.len() == 32 && !self.extra.is_empty()
            }
        }
    }

    /// The HMAC message of the commit:
    /// `lp(kind) ‖ lp(sig_pub) ‖ lp(enc_pub) ‖ lp(label) ‖ lp(extra)`.
    pub fn commit_input(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_lp(&mut out, self.kind.as_str().as_bytes());
        push_lp(&mut out, &self.sig_pub);
        push_lp(&mut out, &self.enc_pub);
        push_lp(&mut out, self.label.as_bytes());
        push_lp(&mut out, &self.extra);
        out
    }
}

/// `commit = HMAC(commit_key, commit_input)`.
pub fn admit_commit(commit_key: &[u8; 32], fields: &AdmissionFields) -> [u8; 32] {
    hmac256(commit_key, &fields.commit_input())
}

/// Constant-time check of a served `commit` against the fields and a typed code.
/// Also requires well-formed fields.
pub fn verify_admit_commit(commit_key: &[u8; 32], fields: &AdmissionFields, commit: &[u8]) -> bool {
    fields.is_well_formed() && hmac256_verify(commit_key, &fields.commit_input(), commit)
}

/// The HMAC message of the result mac:
/// `lp(effect) ‖ lp(uik_sign_pub32) ‖ lp(us_) ‖ lp(email)`.
pub fn admit_mac_input(effect: &[u8], uik_sign_pub: &[u8; 32], us: &str, email: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push_lp(&mut out, effect);
    push_lp(&mut out, uik_sign_pub);
    push_lp(&mut out, us.as_bytes());
    push_lp(&mut out, email.as_bytes());
    out
}

/// `mac = HMAC(mac_key, admit_mac_input)` (the approving side).
pub fn admit_mac(
    mac_key: &[u8; 32],
    effect: &[u8],
    uik_sign_pub: &[u8; 32],
    us: &str,
    email: &str,
) -> [u8; 32] {
    hmac256(mac_key, &admit_mac_input(effect, uik_sign_pub, us, email))
}

/// The new side's mac check: `derive_id(User, uik_sign_pub) == us` AND the mac
/// verifies (constant time). `email` is used verbatim, as served.
pub fn verify_admit_mac(
    mac_key: &[u8; 32],
    effect: &[u8],
    uik_sign_pub: &[u8; 32],
    us: &str,
    email: &str,
    mac: &[u8],
) -> bool {
    derive_id(IdKind::User, uik_sign_pub) == us
        && hmac256_verify(
            mac_key,
            &admit_mac_input(effect, uik_sign_pub, us, email),
            mac,
        )
}

/// Does the approved `effect` cover exactly the keys this side committed?
///
/// - agent: `effect == commit`;
/// - device: the effect parses as a ledger v2 `admit{device}` by `us` whose
///   principal is `derive_id(Device, sig_pub)` and whose keys equal ours;
/// - passkey: the effect parses as `admit{passkey}` by `us` with principal =
///   b64url(credential id), `sig_pub = x‖y` and an empty `enc_pub`.
///
/// The label and the seq are the approver's to choose and are not compared.
pub fn admission_effect_covers(
    fields: &AdmissionFields,
    effect: &[u8],
    us: &str,
    commit: &[u8; 32],
) -> bool {
    if fields.kind == AdmitKind::Agent {
        return effect == commit;
    }
    let Some(ev) = LedgerEventFields::parse_signing_input(effect) else {
        return false;
    };
    if ev.op != OP_ADMIT || ev.us != us {
        return false;
    }
    match fields.kind {
        AdmitKind::Device => {
            let Ok(dik) = <[u8; 32]>::try_from(fields.sig_pub.as_slice()) else {
                return false;
            };
            ev.kind == KIND_DEVICE
                && ev.principal == derive_id(IdKind::Device, &dik)
                && ev.sig_pub == fields.sig_pub
                && ev.enc_pub == fields.enc_pub
        }
        AdmitKind::Passkey => {
            ev.kind == KIND_PASSKEY
                && ev.principal == BASE64URL_NOPAD.encode(&fields.extra)
                && ev.sig_pub == fields.sig_pub
                && ev.enc_pub.is_empty()
        }
        AdmitKind::Agent => unreachable!("handled above"),
    }
}

/// Everything the new side checks when its admission comes back approved:
/// well-formed own fields, the mac under its own code (which also checks that
/// `uik_sign_pub` folds to `us`), and that the effect covers its own keys. Only
/// then may it pin `us` as its account anchor.
pub fn verify_admission_result(
    code: &AdmitCode,
    fields: &AdmissionFields,
    effect: &[u8],
    uik_sign_pub: &[u8; 32],
    us: &str,
    email: &str,
    mac: &[u8],
) -> bool {
    let keys = code.keys();
    fields.is_well_formed()
        && verify_admit_mac(&keys.mac_key, effect, uik_sign_pub, us, email, mac)
        && admission_effect_covers(fields, effect, us, &admit_commit(&keys.commit_key, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_parse_roundtrip_random() {
        for _ in 0..64 {
            let c = AdmitCode::generate();
            let d = c.display();
            assert_eq!(d.len(), 19);
            let back = AdmitCode::parse(&d).expect("display form parses");
            assert_eq!(back.as_bytes(), c.as_bytes());
            assert_eq!(c.keys().lookup.len(), 32);
        }
    }

    #[test]
    fn distinct_labels_give_distinct_keys() {
        let k = AdmitCode::from_bytes([7u8; 10]).keys();
        assert_ne!(*k.commit_key, *k.mac_key);
        let commit_prefix: String = k.commit_key[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(k.lookup, commit_prefix);
    }
}
