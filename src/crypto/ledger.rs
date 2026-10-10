//! Person ledger v2 (trust-reset design D4, contract 1.3): a person's UIK-signed,
//! append-only log of their devices, passkeys and vault pins, and the ONE fold
//! that turns it into the live sets every verifier uses.
//!
//! Event signing input: [`crate::identity::ledger_event_input`].
//!
//! | kind      | principal              | sig_pub                  | enc_pub        |
//! |-----------|------------------------|--------------------------|----------------|
//! | `device`  | `dv_` = fold(DIK pub)  | DIK pub (32)             | enc pub (32)   |
//! | `passkey` | credential id (b64url) | COSE `x‖y` (64)          | empty          |
//! | `pin`     | vault id               | anchor sign pub (32)     | empty          |
//!
//! Fold rules, checked per event in this order (the first failure is the error):
//!
//! 1. `seq` equals the event's position (starts at 0, +1 each event):
//!    `seq_duplicate` if lower, `seq_gap` if higher;
//! 2. the event's `us_` is the ledger's person: `wrong_person`;
//! 3. the UIK signature verifies (strict Ed25519): `bad_sig`;
//! 4. `op` ∈ {admit, revoke}: `bad_op`; `kind` ∈ {device, passkey, pin}: `bad_kind`;
//! 5. field shapes per the table (device principal must equal `derive_id(dv,
//!    sig_pub)`; a passkey principal must be canonical unpadded base64url; a pin
//!    principal must be non-empty): `bad_fields`;
//! 6. admit of a revoked device/passkey: `revoked_terminal`; admit of a live
//!    principal is a rename whose keys must be identical: `pin_conflict` for a
//!    pin, `key_change` otherwise;
//! 7. revoke of a principal that is not live: `not_live`; with keys different
//!    from the live ones: `revoke_key_mismatch`; of the last live passkey:
//!    `last_passkey`. A revoked device/passkey is terminal; a revoked pin frees
//!    the vault for a new pin.
//!
//! Before any event: `derive_id(User, uik_pub) == us` else `bad_owner`.

use std::collections::BTreeMap;

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::identity::{derive_id, ledger_event_input, verify, IdKind, DS_LEDGER_EVENT};

pub const OP_ADMIT: &str = "admit";
pub const OP_REVOKE: &str = "revoke";
pub const KIND_DEVICE: &str = "device";
pub const KIND_PASSKEY: &str = "passkey";
pub const KIND_PIN: &str = "pin";

/// The largest seq any parser accepts: 2^53-1 (JS `Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_SEQ: u64 = (1 << 53) - 1;

/// The signed fields of one ledger event (untrusted until folded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEventFields {
    pub us: String,
    pub op: String,
    pub kind: String,
    pub principal: String,
    pub sig_pub: Vec<u8>,
    pub enc_pub: Vec<u8>,
    pub label: String,
    pub seq: u64,
}

impl LedgerEventFields {
    /// The bytes the UIK signs ([`ledger_event_input`]).
    pub fn signing_input(&self) -> Vec<u8> {
        ledger_event_input(
            &self.us,
            &self.op,
            &self.kind,
            &self.principal,
            &self.sig_pub,
            &self.enc_pub,
            &self.label,
            self.seq,
        )
    }

    /// Strictly parse a signing input back into fields: the domain must match,
    /// every length prefix must fit, strings must be UTF-8, and nothing may
    /// trail the 8-byte seq. Used where the input itself travels (the admit
    /// effect).
    pub fn parse_signing_input(bytes: &[u8]) -> Option<Self> {
        let mut rest = bytes;
        let domain = take_lp(&mut rest)?;
        let us = take_lp(&mut rest)?;
        let op = take_lp(&mut rest)?;
        let kind = take_lp(&mut rest)?;
        let principal = take_lp(&mut rest)?;
        let sig_pub = take_lp(&mut rest)?;
        let enc_pub = take_lp(&mut rest)?;
        let label = take_lp(&mut rest)?;
        if domain != DS_LEDGER_EVENT || rest.len() != 8 {
            return None;
        }
        let seq = u64::from_be_bytes(rest.try_into().ok()?);
        // A seq above 2^53-1 is not a safe integer in TS/JS, where the parse
        // returns null; refuse it here too so all three parsers agree (such a
        // seq can never fold anyway).
        if seq > MAX_SAFE_SEQ {
            return None;
        }
        let s = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
        Some(Self {
            us: s(us)?,
            op: s(op)?,
            kind: s(kind)?,
            principal: s(principal)?,
            sig_pub: sig_pub.to_vec(),
            enc_pub: enc_pub.to_vec(),
            label: s(label)?,
            seq,
        })
    }

    /// The event hash a reader latches per seq (design A3):
    /// `SHA-256(signing_input)`.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.signing_input()).into()
    }
}

/// Read one `lp()` field off the front of `rest`.
fn take_lp<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let cur: &'a [u8] = *rest;
    let len: [u8; 4] = cur.get(..4)?.try_into().ok()?;
    let end = 4usize.checked_add(u32::from_be_bytes(len) as usize)?;
    let body = cur.get(4..end)?;
    *rest = &cur[end..];
    Some(body)
}

/// One ledger event as served: the signed fields plus the UIK signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEvent {
    pub fields: LedgerEventFields,
    pub sig: Vec<u8>,
}

/// Why a ledger failed to fold. The string forms are shared with the TS and
/// Node folds and pinned by the vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerErrorCode {
    BadOwner,
    SeqGap,
    SeqDuplicate,
    WrongPerson,
    BadSig,
    BadOp,
    BadKind,
    BadFields,
    RevokedTerminal,
    KeyChange,
    PinConflict,
    NotLive,
    RevokeKeyMismatch,
    LastPasskey,
}

impl LedgerErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadOwner => "bad_owner",
            Self::SeqGap => "seq_gap",
            Self::SeqDuplicate => "seq_duplicate",
            Self::WrongPerson => "wrong_person",
            Self::BadSig => "bad_sig",
            Self::BadOp => "bad_op",
            Self::BadKind => "bad_kind",
            Self::BadFields => "bad_fields",
            Self::RevokedTerminal => "revoked_terminal",
            Self::KeyChange => "key_change",
            Self::PinConflict => "pin_conflict",
            Self::NotLive => "not_live",
            Self::RevokeKeyMismatch => "revoke_key_mismatch",
            Self::LastPasskey => "last_passkey",
        }
    }
}

/// A fold failure: the code and the index of the offending event (`None` for
/// `bad_owner`, which fails before any event).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerError {
    pub code: LedgerErrorCode,
    pub index: Option<usize>,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.index {
            Some(i) => write!(f, "ledger invalid at event {i}: {}", self.code.as_str()),
            None => write!(f, "ledger invalid: {}", self.code.as_str()),
        }
    }
}

impl std::error::Error for LedgerError {}

/// A device admitted by a verified ledger. Constructible only by [`fold_ledger`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDevice {
    id: String,
    sig_pub: [u8; 32],
    enc_pub: [u8; 32],
    label: String,
}

impl LiveDevice {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn sig_pub(&self) -> &[u8; 32] {
        &self.sig_pub
    }
    pub fn enc_pub(&self) -> &[u8; 32] {
        &self.enc_pub
    }
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// A passkey attested by a verified ledger. Constructible only by [`fold_ledger`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePasskey {
    cid: String,
    xy: [u8; 64],
    label: String,
}

impl LivePasskey {
    /// The credential id, unpadded base64url (as in the ledger).
    pub fn cid(&self) -> &str {
        &self.cid
    }
    /// The COSE P-256 public key `x‖y`.
    pub fn xy(&self) -> &[u8; 64] {
        &self.xy
    }
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// A vault pin from a verified ledger. Constructible only by [`fold_ledger`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePin {
    vault: String,
    anchor: [u8; 32],
    label: String,
}

impl LivePin {
    pub fn vault(&self) -> &str {
        &self.vault
    }
    /// The pinned anchor's Ed25519 sign pub.
    pub fn anchor(&self) -> &[u8; 32] {
        &self.anchor
    }
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// The folded state of a verified ledger. Only [`fold_ledger`] constructs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerState {
    us: String,
    next_seq: u64,
    head_hash: Option<[u8; 32]>,
    devices: BTreeMap<String, LiveDevice>,
    passkeys: BTreeMap<String, LivePasskey>,
    pins: BTreeMap<String, LivePin>,
    revoked_devices: BTreeMap<String, u64>,
    revoked_passkeys: BTreeMap<String, u64>,
}

impl LedgerState {
    /// The person this ledger belongs to.
    pub fn us(&self) -> &str {
        &self.us
    }
    /// The seq the next appended event must carry (= number of events).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
    /// [`LedgerEventFields::hash`] of the last event; `None` for an empty ledger.
    pub fn head_hash(&self) -> Option<&[u8; 32]> {
        self.head_hash.as_ref()
    }
    /// Live devices, ordered by id.
    pub fn devices(&self) -> impl Iterator<Item = &LiveDevice> {
        self.devices.values()
    }
    pub fn device(&self, dv: &str) -> Option<&LiveDevice> {
        self.devices.get(dv)
    }
    /// Live passkeys, ordered by credential id.
    pub fn passkeys(&self) -> impl Iterator<Item = &LivePasskey> {
        self.passkeys.values()
    }
    pub fn passkey(&self, cid: &str) -> Option<&LivePasskey> {
        self.passkeys.get(cid)
    }
    /// Live pins, ordered by vault id.
    pub fn pins(&self) -> impl Iterator<Item = &LivePin> {
        self.pins.values()
    }
    pub fn pin(&self, vault: &str) -> Option<&LivePin> {
        self.pins.get(vault)
    }
    /// Revoked devices with the seq of their revoke event, ordered by id.
    pub fn revoked_devices(&self) -> impl Iterator<Item = (&str, u64)> {
        self.revoked_devices.iter().map(|(k, v)| (k.as_str(), *v))
    }
    /// The seq at which `dv` was revoked, if it was.
    pub fn device_revoked_at(&self, dv: &str) -> Option<u64> {
        self.revoked_devices.get(dv).copied()
    }
    /// Revoked passkeys with the seq of their revoke event, ordered by cid.
    pub fn revoked_passkeys(&self) -> impl Iterator<Item = (&str, u64)> {
        self.revoked_passkeys.iter().map(|(k, v)| (k.as_str(), *v))
    }
    pub fn passkey_revoked_at(&self, cid: &str) -> Option<u64> {
        self.revoked_passkeys.get(cid).copied()
    }
}

/// Canonical unpadded base64url: non-empty, URL alphabet only, and re-encoding
/// the decoded bytes gives back the same string (rejects padding, the standard
/// alphabet and non-zero trailing bits), so one credential has one principal.
pub fn is_canonical_b64url(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    match BASE64URL_NOPAD.decode(s.as_bytes()) {
        Ok(raw) => BASE64URL_NOPAD.encode(&raw) == s,
        Err(_) => false,
    }
}

/// Fold a person's ledger (events in seq order) into its live state, verifying
/// every rule in the module doc. The whole ledger is rejected on the first bad
/// event: a verifier never acts on a partially valid ledger.
pub fn fold_ledger(
    us: &str,
    uik_pub: &[u8; 32],
    events: &[LedgerEvent],
) -> Result<LedgerState, LedgerError> {
    let mut st = empty_state(us, uik_pub)?;
    for (i, ev) in events.iter().enumerate() {
        apply(&mut st, uik_pub, ev, i).map_err(|code| LedgerError {
            code,
            index: Some(i),
        })?;
    }
    Ok(st)
}

/// One event as it travels on the wire (`{input, sig}`, contract 8.2/8.4): the
/// raw signing input and the raw signature. Untrusted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedInput {
    pub input: Vec<u8>,
    pub sig: Vec<u8>,
}

/// [`fold_ledger`] over served `{input, sig}` events. Each input must parse
/// strictly ([`LedgerEventFields::parse_signing_input`]); one that does not (a
/// wrong domain, a truncated field, or a string field that is not well-formed
/// UTF-8, e.g. the CESU bytes of a lone surrogate) is `bad_fields` at its index
/// (contract 7: ill-formed strings are `bad_fields` in every fold).
pub fn fold_ledger_inputs(
    us: &str,
    uik_pub: &[u8; 32],
    events: &[SignedInput],
) -> Result<LedgerState, LedgerError> {
    let mut st = empty_state(us, uik_pub)?;
    for (i, ev) in events.iter().enumerate() {
        let at = |code| LedgerError {
            code,
            index: Some(i),
        };
        let fields = LedgerEventFields::parse_signing_input(&ev.input)
            .ok_or_else(|| at(LedgerErrorCode::BadFields))?;
        let ev = LedgerEvent {
            fields,
            sig: ev.sig.clone(),
        };
        apply(&mut st, uik_pub, &ev, i).map_err(at)?;
    }
    Ok(st)
}

fn empty_state(us: &str, uik_pub: &[u8; 32]) -> Result<LedgerState, LedgerError> {
    if derive_id(IdKind::User, uik_pub) != us {
        return Err(LedgerError {
            code: LedgerErrorCode::BadOwner,
            index: None,
        });
    }
    Ok(LedgerState {
        us: us.to_string(),
        next_seq: 0,
        head_hash: None,
        devices: BTreeMap::new(),
        passkeys: BTreeMap::new(),
        pins: BTreeMap::new(),
        revoked_devices: BTreeMap::new(),
        revoked_passkeys: BTreeMap::new(),
    })
}

fn apply(
    st: &mut LedgerState,
    uik_pub: &[u8; 32],
    ev: &LedgerEvent,
    i: usize,
) -> Result<(), LedgerErrorCode> {
    use LedgerErrorCode as E;
    let f = &ev.fields;
    let expected = i as u64;
    if f.seq < expected {
        return Err(E::SeqDuplicate);
    }
    if f.seq > expected {
        return Err(E::SeqGap);
    }
    if f.us != st.us {
        return Err(E::WrongPerson);
    }
    let input = f.signing_input();
    let sig_ok = <[u8; 64]>::try_from(ev.sig.as_slice())
        .map(|sig| verify(uik_pub, &input, &sig))
        .unwrap_or(false);
    if !sig_ok {
        return Err(E::BadSig);
    }
    let admit = match f.op.as_str() {
        OP_ADMIT => true,
        OP_REVOKE => false,
        _ => return Err(E::BadOp),
    };
    match f.kind.as_str() {
        KIND_DEVICE => {
            let sig_pub: [u8; 32] = f.sig_pub.as_slice().try_into().map_err(|_| E::BadFields)?;
            let enc_pub: [u8; 32] = f.enc_pub.as_slice().try_into().map_err(|_| E::BadFields)?;
            if f.principal != derive_id(IdKind::Device, &sig_pub) {
                return Err(E::BadFields);
            }
            if st.revoked_devices.contains_key(&f.principal) {
                return if admit {
                    Err(E::RevokedTerminal)
                } else {
                    Err(E::NotLive)
                };
            }
            let same_keys = |d: &LiveDevice| d.sig_pub == sig_pub && d.enc_pub == enc_pub;
            if admit {
                if let Some(live) = st.devices.get(&f.principal) {
                    if !same_keys(live) {
                        return Err(E::KeyChange);
                    }
                }
                st.devices.insert(
                    f.principal.clone(),
                    LiveDevice {
                        id: f.principal.clone(),
                        sig_pub,
                        enc_pub,
                        label: f.label.clone(),
                    },
                );
            } else {
                let live = st.devices.get(&f.principal).ok_or(E::NotLive)?;
                if !same_keys(live) {
                    return Err(E::RevokeKeyMismatch);
                }
                st.devices.remove(&f.principal);
                st.revoked_devices.insert(f.principal.clone(), f.seq);
            }
        }
        KIND_PASSKEY => {
            let xy: [u8; 64] = f.sig_pub.as_slice().try_into().map_err(|_| E::BadFields)?;
            if !f.enc_pub.is_empty() || !is_canonical_b64url(&f.principal) {
                return Err(E::BadFields);
            }
            if st.revoked_passkeys.contains_key(&f.principal) {
                return if admit {
                    Err(E::RevokedTerminal)
                } else {
                    Err(E::NotLive)
                };
            }
            if admit {
                if let Some(live) = st.passkeys.get(&f.principal) {
                    if live.xy != xy {
                        return Err(E::KeyChange);
                    }
                }
                st.passkeys.insert(
                    f.principal.clone(),
                    LivePasskey {
                        cid: f.principal.clone(),
                        xy,
                        label: f.label.clone(),
                    },
                );
            } else {
                let live = st.passkeys.get(&f.principal).ok_or(E::NotLive)?;
                if live.xy != xy {
                    return Err(E::RevokeKeyMismatch);
                }
                if st.passkeys.len() == 1 {
                    return Err(E::LastPasskey);
                }
                st.passkeys.remove(&f.principal);
                st.revoked_passkeys.insert(f.principal.clone(), f.seq);
            }
        }
        KIND_PIN => {
            let anchor: [u8; 32] = f.sig_pub.as_slice().try_into().map_err(|_| E::BadFields)?;
            if !f.enc_pub.is_empty() || f.principal.is_empty() {
                return Err(E::BadFields);
            }
            if admit {
                if let Some(live) = st.pins.get(&f.principal) {
                    if live.anchor != anchor {
                        return Err(E::PinConflict);
                    }
                }
                st.pins.insert(
                    f.principal.clone(),
                    LivePin {
                        vault: f.principal.clone(),
                        anchor,
                        label: f.label.clone(),
                    },
                );
            } else {
                let live = st.pins.get(&f.principal).ok_or(E::NotLive)?;
                if live.anchor != anchor {
                    return Err(E::RevokeKeyMismatch);
                }
                st.pins.remove(&f.principal);
            }
        }
        _ => return Err(E::BadKind),
    }
    st.next_seq = f.seq + 1;
    st.head_hash = Some(Sha256::digest(&input).into());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningIdentity;

    fn uik() -> SigningIdentity {
        SigningIdentity::from_seed(&[0x31; 32])
    }

    fn device_admit(us: &str, seq: u64, label: &str) -> LedgerEventFields {
        let dik = SigningIdentity::from_seed(&[0x44; 32]);
        LedgerEventFields {
            us: us.into(),
            op: OP_ADMIT.into(),
            kind: KIND_DEVICE.into(),
            principal: dik.id(IdKind::Device),
            sig_pub: dik.public_bytes().to_vec(),
            enc_pub: vec![9; 32],
            label: label.into(),
            seq,
        }
    }

    fn signed(u: &SigningIdentity, f: &LedgerEventFields) -> SignedInput {
        let input = f.signing_input();
        SignedInput {
            sig: u.sign(&input).to_vec(),
            input,
        }
    }

    #[test]
    fn wire_fold_matches_typed_fold() {
        let u = uik();
        let us = u.user_id();
        let evs = [
            device_admit(&us, 0, "laptop"),
            device_admit(&us, 1, "renamed"),
        ];
        let wire: Vec<SignedInput> = evs.iter().map(|f| signed(&u, f)).collect();
        let typed: Vec<LedgerEvent> = wire
            .iter()
            .map(|w| LedgerEvent {
                fields: LedgerEventFields::parse_signing_input(&w.input).unwrap(),
                sig: w.sig.clone(),
            })
            .collect();
        let a = fold_ledger_inputs(&us, &u.public_bytes(), &wire).unwrap();
        let b = fold_ledger(&us, &u.public_bytes(), &typed).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.next_seq(), 2);
        assert_eq!(a.devices().next().unwrap().label(), "renamed");
    }

    /// Contract 7: a string field that is not well-formed Unicode is
    /// `bad_fields`, never a panic. Rust strings cannot hold a lone surrogate,
    /// so it reaches the fold as its CESU-8 bytes (ED A0 80) inside the input.
    #[test]
    fn lone_surrogate_bytes_are_bad_fields() {
        let u = uik();
        let us = u.user_id();
        let good = signed(&u, &device_admit(&us, 0, "ok"));
        let mut f = device_admit(&us, 1, "XYZ");
        f.label = "XYZ".into();
        let mut input = f.signing_input();
        // Replace the 3-byte label with a CESU-8 encoded lone high surrogate.
        let pos = input.windows(3).rposition(|w| w == b"XYZ").unwrap();
        input[pos..pos + 3].copy_from_slice(&[0xED, 0xA0, 0x80]);
        let bad = SignedInput {
            sig: u.sign(&input).to_vec(),
            input,
        };
        let err = fold_ledger_inputs(&us, &u.public_bytes(), &[good, bad]).unwrap_err();
        assert_eq!(err.code, LedgerErrorCode::BadFields);
        assert_eq!(err.index, Some(1));
        // serde_json refuses the same thing at the JSON layer (an error, not a
        // panic), so a served body carrying it never reaches the fold.
        assert!(serde_json::from_str::<serde_json::Value>(r#"{"label":"\ud800"}"#).is_err());
    }

    #[test]
    fn truncated_or_foreign_input_is_bad_fields() {
        let u = uik();
        let us = u.user_id();
        let mut ev = signed(&u, &device_admit(&us, 0, "x"));
        ev.input.truncate(ev.input.len() - 1);
        let err = fold_ledger_inputs(&us, &u.public_bytes(), &[ev]).unwrap_err();
        assert_eq!((err.code, err.index), (LedgerErrorCode::BadFields, Some(0)));
        let foreign = SignedInput {
            input: b"not a ledger event".to_vec(),
            sig: vec![0; 64],
        };
        let err = fold_ledger_inputs(&us, &u.public_bytes(), &[foreign]).unwrap_err();
        assert_eq!((err.code, err.index), (LedgerErrorCode::BadFields, Some(0)));
    }
}
