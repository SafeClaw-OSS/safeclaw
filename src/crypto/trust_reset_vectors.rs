//! Cross-language vectors for the trust-reset primitives
//! (design/trust-reset-contract.md sections 0-1). `trust_reset_vectors.json` is
//! byte-identical in the console (`lib/trust-reset-vectors.json`, checked by
//! `scripts/verify-trust-vectors.mjs`) and the backend
//! (`test/trust-reset-vectors.json`, checked by `test/trust-crypto.test.mjs`).
//! The vectors are the compatibility contract: never regenerate or edit them to
//! make a test pass; find why the implementations diverged.
//!
//! Sections checked here: lp, derive_id, id_kind, enc_sig, admit_code (all but
//! the backend-only lookup format), ledger_parse, ledger_event, ledger_fold,
//! device_request (signing + canonical host; the backend owns the window),
//! k_commitment, rekey_gen0, op_requester. The ES256 section is browser-only
//! (contract 1.8).

use serde_json::Value;

use crate::crypto::admission::{
    admission_effect_covers, admit_commit, admit_mac, admit_mac_input, normalize_admit_code,
    verify_admission_result, AdmissionFields, AdmitCode, AdmitKind, CROCKFORD_ALPHABET,
    LABEL_ADMIT_COMMIT, LABEL_ADMIT_LOOKUP, LABEL_ADMIT_MAC,
};
use crate::crypto::ledger::{fold_ledger, LedgerEvent, LedgerEventFields};
use crate::device_auth::{canonical_host, DeviceRequestSigner};
use crate::identity::{
    derive_id, device_request_signature_input, enc_bind_input, k_commitment,
    membership_commitment, parse_id, push_lp, rekey_sig_input, verify, verify_enc_sig, IdKind,
    SigningIdentity,
};
use crate::protocol::operation::scope_requester;

fn vectors() -> Value {
    serde_json::from_str(include_str!("trust_reset_vectors.json")).expect("vectors parse")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("missing string {k}"))
}

fn h(v: &Value, k: &str) -> Vec<u8> {
    unhex(s(v, k))
}

fn a32(v: &Value, k: &str) -> [u8; 32] {
    h(v, k)
        .try_into()
        .unwrap_or_else(|_| panic!("{k} is not 32 bytes"))
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array()
        .unwrap_or_else(|| panic!("missing array {k}"))
}

fn kind_of(name: &str) -> IdKind {
    match name {
        "user" => IdKind::User,
        "agent" => IdKind::Agent,
        "device" => IdKind::Device,
        other => panic!("kind {other}"),
    }
}

fn kind_name(k: IdKind) -> &'static str {
    match k {
        IdKind::User => "user",
        IdKind::Agent => "agent",
        IdKind::Device => "device",
    }
}

fn fields(v: &Value) -> Option<AdmissionFields> {
    Some(AdmissionFields {
        kind: AdmitKind::parse(s(v, "kind"))?,
        sig_pub: h(v, "sig_pub"),
        enc_pub: h(v, "enc_pub"),
        label: s(v, "label").to_string(),
        extra: h(v, "extra"),
    })
}

fn event(v: &Value) -> LedgerEvent {
    LedgerEvent {
        fields: LedgerEventFields {
            us: s(v, "us").into(),
            op: s(v, "op").into(),
            kind: s(v, "kind").into(),
            principal: s(v, "principal").into(),
            sig_pub: h(v, "sig_pub"),
            enc_pub: h(v, "enc_pub"),
            label: s(v, "label").into(),
            seq: v["seq"].as_u64().unwrap(),
        },
        sig: h(v, "sig"),
    }
}

#[test]
fn lp_and_ids() {
    let v = vectors();
    for c in arr(&v, "lp") {
        let mut out = Vec::new();
        push_lp(&mut out, &h(c, "in"));
        assert_eq!(hex(&out), s(c, "out"));
    }
    for c in arr(&v, "derive_id") {
        assert_eq!(derive_id(kind_of(s(c, "kind")), &a32(c, "pub")), s(c, "id"));
    }
    for c in arr(&v, "id_kind") {
        let want = c["kind"].as_str();
        assert_eq!(
            parse_id(s(c, "id")).map(kind_name),
            want,
            "id_kind {}",
            s(c, "id")
        );
    }
}

#[test]
fn enc_sig() {
    let v = vectors();
    let e = &v["enc_sig"];
    let uik = SigningIdentity::from_seed(&a32(e, "uik_seed"));
    let sign = &e["sign"];
    assert_eq!(uik.user_id(), s(sign, "us"));
    assert_eq!(uik.public_bytes(), a32(sign, "sig_pub"));
    let enc_pub = a32(sign, "enc_pub");
    assert_eq!(
        hex(&enc_bind_input(s(sign, "us"), &enc_pub)),
        s(sign, "input")
    );
    assert_eq!(hex(&uik.sign_enc_bind(&enc_pub)), s(sign, "sig"));
    for c in arr(e, "verify") {
        let enc = h(c, "enc_pub");
        let got = match <[u8; 32]>::try_from(enc.as_slice()) {
            Ok(enc) => {
                let sig: [u8; 64] = h(c, "sig").try_into().unwrap();
                verify_enc_sig(s(c, "us"), &a32(c, "sig_pub"), &enc, &sig)
            }
            Err(_) => false, // a non-32-byte enc_pub can't even be typed
        };
        assert_eq!(
            got,
            c["valid"].as_bool().unwrap(),
            "enc_sig {}",
            s(c, "name")
        );
    }
}

#[test]
fn admit_code() {
    let v = vectors();
    let a = &v["admit_code"];
    assert_eq!(s(a, "alphabet").as_bytes(), CROCKFORD_ALPHABET);
    assert_eq!(s(&a["labels"], "lookup").as_bytes(), LABEL_ADMIT_LOOKUP);
    assert_eq!(s(&a["labels"], "commit").as_bytes(), LABEL_ADMIT_COMMIT);
    assert_eq!(s(&a["labels"], "mac").as_bytes(), LABEL_ADMIT_MAC);

    for c in arr(a, "codes") {
        let code = AdmitCode::from_bytes(h(c, "s").try_into().unwrap());
        assert_eq!(code.display(), s(c, "display"));
        assert_eq!(
            AdmitCode::parse(s(c, "display")).unwrap().as_bytes(),
            code.as_bytes()
        );
        let k = code.keys();
        assert_eq!(k.lookup, s(c, "lookup"));
        assert_eq!(hex(&k.commit_key[..]), s(c, "commit_key"));
        assert_eq!(hex(&k.mac_key[..]), s(c, "mac_key"));
    }
    for c in arr(a, "normalize") {
        let input = s(c, "input");
        assert_eq!(
            normalize_admit_code(input).as_deref(),
            c["normalized"].as_str(),
            "normalize {input:?}"
        );
        let parsed = AdmitCode::parse(input).map(|code| hex(code.as_bytes()));
        assert_eq!(parsed.as_deref(), c["s"].as_str(), "parse {input:?}");
    }
    for c in arr(a, "fields_check") {
        let got = fields(&c["fields"]).is_some_and(|f| f.is_well_formed());
        assert_eq!(
            got,
            c["valid"].as_bool().unwrap(),
            "fields_check {}",
            s(c, "name")
        );
    }
    for c in arr(a, "commit") {
        let f = fields(&c["fields"]).unwrap();
        let keys = AdmitCode::from_bytes(h(c, "s").try_into().unwrap()).keys();
        assert_eq!(hex(&f.commit_input()), s(c, "input"));
        assert_eq!(hex(&admit_commit(&keys.commit_key, &f)), s(c, "commit"));
    }
    for c in arr(a, "mac") {
        let keys = AdmitCode::from_bytes(h(c, "s").try_into().unwrap()).keys();
        let (effect, pub_, us, email) = (
            h(c, "effect"),
            a32(c, "uik_sign_pub"),
            s(c, "us"),
            s(c, "email"),
        );
        assert_eq!(
            hex(&admit_mac_input(&effect, &pub_, us, email)),
            s(c, "input")
        );
        assert_eq!(
            hex(&admit_mac(&keys.mac_key, &effect, &pub_, us, email)),
            s(c, "mac")
        );
    }
    for c in arr(a, "admission_result") {
        let code = AdmitCode::from_bytes(h(c, "s").try_into().unwrap());
        let f = fields(&c["fields"]).unwrap();
        let got = verify_admission_result(
            &code,
            &f,
            &h(c, "effect"),
            &a32(c, "uik_sign_pub"),
            s(c, "us"),
            s(c, "email"),
            &h(c, "mac"),
        );
        assert_eq!(
            got,
            c["valid"].as_bool().unwrap(),
            "admission_result {}",
            s(c, "name")
        );
        if got {
            let commit = admit_commit(&code.keys().commit_key, &f);
            assert!(admission_effect_covers(
                &f,
                &h(c, "effect"),
                s(c, "us"),
                &commit
            ));
        }
    }
}

#[test]
fn ledger_events_and_fold() {
    let v = vectors();
    for c in arr(&v, "ledger_parse") {
        let parsed = LedgerEventFields::parse_signing_input(&h(c, "input"));
        assert_eq!(
            parsed.is_some(),
            c["valid"].as_bool().unwrap(),
            "ledger_parse {}",
            s(c, "name")
        );
        if let Some(p) = parsed {
            assert_eq!(hex(&p.signing_input()), s(c, "input"), "parse roundtrip");
        }
    }
    for c in arr(&v, "ledger_event") {
        let e = event(c);
        let input = e.fields.signing_input();
        assert_eq!(hex(&input), s(c, "input"), "ledger_event {}", s(c, "name"));
        assert_eq!(hex(&e.fields.hash()), s(c, "hash"));
        assert_eq!(
            LedgerEventFields::parse_signing_input(&input).as_ref(),
            Some(&e.fields)
        );
        let signer = SigningIdentity::from_seed(&a32(c, "signer_seed"));
        assert_eq!(signer.public_bytes(), a32(c, "signer_pub"));
        assert_eq!(hex(&signer.sign(&input)), s(c, "sig"));
    }
    for c in arr(&v, "ledger_fold") {
        let name = s(c, "name");
        let events: Vec<LedgerEvent> = arr(c, "events").iter().map(event).collect();
        let got = fold_ledger(s(c, "us"), &a32(c, "uik_pub"), &events);
        let want = &c["expect"];
        match got {
            Err(e) => {
                assert!(
                    !want["ok"].as_bool().unwrap(),
                    "{name}: unexpected error {e}"
                );
                assert_eq!(e.code.as_str(), s(want, "error"), "{name}");
                assert_eq!(e.index.map(|i| i as u64), want["index"].as_u64(), "{name}");
            }
            Ok(st) => {
                assert!(
                    want["ok"].as_bool().unwrap(),
                    "{name}: folded but expected {want}"
                );
                assert_eq!(st.us(), s(c, "us"));
                assert_eq!(st.next_seq(), want["next_seq"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    st.head_hash().map(|x| hex(x)).as_deref(),
                    want["head_hash"].as_str(),
                    "{name}"
                );
                let devices: Vec<Value> = st
                    .devices()
                    .map(|d| {
                        serde_json::json!({"id": d.id(), "sig_pub": hex(d.sig_pub()), "enc_pub": hex(d.enc_pub()), "label": d.label()})
                    })
                    .collect();
                assert_eq!(Value::Array(devices), want["devices"], "{name} devices");
                let passkeys: Vec<Value> = st
                    .passkeys()
                    .map(|p| serde_json::json!({"cid": p.cid(), "xy": hex(p.xy()), "label": p.label()}))
                    .collect();
                assert_eq!(Value::Array(passkeys), want["passkeys"], "{name} passkeys");
                let pins: Vec<Value> = st
                    .pins()
                    .map(|p| serde_json::json!({"vault": p.vault(), "anchor": hex(p.anchor()), "label": p.label()}))
                    .collect();
                assert_eq!(Value::Array(pins), want["pins"], "{name} pins");
                let rd: Vec<Value> = st
                    .revoked_devices()
                    .map(|(id, seq)| serde_json::json!({"id": id, "seq": seq}))
                    .collect();
                assert_eq!(
                    Value::Array(rd),
                    want["revoked_devices"],
                    "{name} revoked_devices"
                );
                let rp: Vec<Value> = st
                    .revoked_passkeys()
                    .map(|(cid, seq)| serde_json::json!({"cid": cid, "seq": seq}))
                    .collect();
                assert_eq!(
                    Value::Array(rp),
                    want["revoked_passkeys"],
                    "{name} revoked_passkeys"
                );
            }
        }
    }
}

#[test]
fn device_request() {
    let v = vectors();
    let d = &v["device_request"];
    for c in arr(d, "sign") {
        let seed = a32(c, "dik_seed");
        let dik = SigningIdentity::from_seed(&seed);
        assert_eq!(dik.public_bytes(), a32(c, "sig_pub"));
        let dv = derive_id(IdKind::Device, &dik.public_bytes());
        assert_eq!(dv, s(c, "device_id"));
        let ts = c["ts"].as_u64().unwrap();
        let body = h(c, "body");
        let input = device_request_signature_input(
            s(c, "method"),
            s(c, "path"),
            ts,
            &body,
            &dv,
            s(c, "canonical_host"),
        );
        assert_eq!(
            hex(&input),
            s(c, "input"),
            "device_request {}",
            s(c, "name")
        );
        assert_eq!(hex(&dik.sign(&input)), s(c, "sig"));
        // The daemon's signer emits exactly these headers.
        let signer = DeviceRequestSigner::new(SigningIdentity::from_seed(&seed), dv.clone());
        let hdrs = signer.headers(
            s(c, "method"),
            s(c, "path"),
            ts,
            &body,
            s(c, "canonical_host"),
        );
        assert_eq!(hdrs[0].1, dv);
        assert_eq!(hdrs[1].1, ts.to_string());
        assert_eq!(hdrs[2].1, s(c, "sig_header"));
        let sig: [u8; 64] = h(c, "sig").try_into().unwrap();
        assert!(verify(&dik.public_bytes(), &input, &sig));
    }
    for c in arr(d, "canonical_host") {
        assert_eq!(
            canonical_host(s(c, "url")).as_deref(),
            c["host"].as_str(),
            "canonical_host {}",
            s(c, "url")
        );
    }
}

#[test]
fn k_commitment_vectors() {
    let v = vectors();
    for c in arr(&v, "k_commitment") {
        let bundle: [u8; 64] = h(c, "bundle").try_into().unwrap();
        let commit = k_commitment(s(c, "vault_id"), c["generation"].as_u64().unwrap(), &bundle);
        assert_eq!(hex(&commit), s(c, "commitment"));
    }
}

/// Contract 1.5: the generation-0 proof is the existing `rekey_sig_input` with
/// `generation = 0` and the membership arguments pinned to the empty log.
#[test]
fn rekey_gen0() {
    let v = vectors();
    let c = &v["rekey_gen0"];
    let vault = s(c, "vault_id");
    let generation = c["generation"].as_u64().unwrap();
    assert_eq!(generation, 0);
    let bundle: [u8; 64] = h(c, "bundle").try_into().unwrap();
    let commit = k_commitment(vault, generation, &bundle);
    assert_eq!(hex(&commit), s(c, "k_commitment"));
    let signer = SigningIdentity::from_seed(&a32(c, "signer_seed"));
    assert_eq!(signer.public_bytes(), a32(c, "signer_pub"));
    assert_eq!(signer.user_id(), s(c, "signer_id"));
    let membership_len = c["membership_len"].as_u64().unwrap();
    assert_eq!(membership_len, 0);
    let membership_hash = membership_commitment(&[]);
    assert_eq!(hex(&membership_hash), s(c, "membership_hash"));
    let input = rekey_sig_input(
        vault,
        generation,
        &commit,
        s(c, "signer_id"),
        membership_len,
        &membership_hash,
    );
    assert_eq!(hex(&input), s(c, "input"));
    assert_eq!(hex(&signer.sign(&input)), s(c, "sig"));
    let sig: [u8; 64] = h(c, "sig").try_into().unwrap();
    assert!(verify(&signer.public_bytes(), &input, &sig));
}

#[test]
fn op_requester() {
    let v = vectors();
    for c in arr(&v, "op_requester") {
        let got = scope_requester(&c["scope"])
            .map(|r| serde_json::json!({"device": r.device, "member": r.member}));
        let want = if c["requester"].is_null() {
            None
        } else {
            Some(c["requester"].clone())
        };
        assert_eq!(got, want, "op_requester {}", s(c, "name"));
    }
}
