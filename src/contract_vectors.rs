//! Golden vectors for the grant-v3 cross-layer contract (C1 admit over device +
//! daemon key, C2 pairing by PAKE short code, C3 grant identity signature, C4
//! signed ledger head). Core is the reference implementation: this test GENERATES the vector
//! file from fixed seeds; the backend (Node) and console (TS) recompute every
//! field and compare byte-for-byte.
//!
//! Regenerate the file:
//!
//! ```text
//! GRANT_V3_VECTORS_OUT=/path/to/contracts/grant-v3.json cargo test contract_vectors
//! ```
//!
//! Without the env var the test only checks determinism and self-consistency,
//! and pins a digest of the generated document so an accidental change to any
//! signing input fails here before it reaches the other two layers.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hpke::{Kem, Serializable};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::crypto::binding::{binding_for_op, DOMAIN_STANDARD};
use crate::crypto::canonical::canonicalize_body;
use crate::crypto::envelope::{grant_k_seal_info, SuiteAead, SuiteKdf, SuiteKem};
use crate::identity::{self, derive_id, AgentRoot, IdKind, SigningIdentity};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn b64u(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

const OWNER_SEED: [u8; 32] = [0x01; 32];
const ADMIN_SEED: [u8; 32] = [0x02; 32];
const DIK_SEED: [u8; 32] = [0x03; 32];
const AGENT_ROOT: [u8; 32] = [0x04; 32];
const SC_SK: [u8; 32] = [0x05; 32];

fn sc_pk() -> [u8; 32] {
    let sk = <<SuiteKem as Kem>::PrivateKey as hpke::Deserializable>::from_bytes(&SC_SK).unwrap();
    <SuiteKem as Kem>::sk_to_pk(&sk).to_bytes().into()
}

/// Deterministic HPKE seal (base mode) of `k` to `sc_pk` under the shipped K-seal
/// info. A seeded RNG makes the bytes reproducible; other layers do not need to
/// reproduce the seal, only hash it (C3) and optionally open it with `sc_sk`.
fn seal_k(pk: &[u8; 32], k: &[u8], op_id: &str, rng_seed: u8) -> (Vec<u8>, Vec<u8>) {
    let pk = <<SuiteKem as Kem>::PublicKey as hpke::Deserializable>::from_bytes(pk).unwrap();
    let mut rng = StdRng::from_seed([rng_seed; 32]);
    let (enc, mut ctx) = hpke::setup_sender::<SuiteAead, SuiteKdf, SuiteKem, _>(
        &hpke::OpModeS::Base,
        &pk,
        &grant_k_seal_info(op_id),
        &mut rng,
    )
    .unwrap();
    let ct = ctx.seal(k, &[]).unwrap();
    (enc.to_bytes().to_vec(), ct)
}

fn c1_case(
    name: &str,
    owner: &SigningIdentity,
    op: &str,
    kind: &str,
    principal_id: &str,
    seq: u64,
    sc_pk: &[u8],
) -> (Value, [u8; 64]) {
    let anchor = owner.user_id();
    let input = identity::principal_event_input(&anchor, op, principal_id, seq, &anchor, sc_pk);
    let sig = owner.sign(&input);
    assert!(identity::verify(&owner.public_bytes(), &input, &sig));
    let mut wire = json!({
        "seq": seq,
        "op": op,
        "principal_id": principal_id,
        "principal_kind": kind,
        "anchor_uik": anchor,
        "owner_id": anchor,
        // The ledger's existing `sig` field stays standard base64 (as shipped);
        // the new `sc_pk` field is base64url per the contract convention.
        "sig": base64::engine::general_purpose::STANDARD.encode(sig),
    });
    if !sc_pk.is_empty() {
        wire["sc_pk"] = json!(b64u(sc_pk));
    }
    let case = json!({
        "name": name,
        "owner_seed": hex(&OWNER_SEED),
        "owner_pub": hex(&owner.public_bytes()),
        "account_id": anchor,
        "op": op,
        "principal_id": principal_id,
        "seq": seq,
        "owner_id": anchor,
        "sc_pk": hex(sc_pk),
        "input": hex(&input),
        "sig": hex(&sig),
        "wire": wire,
    });
    (case, sig)
}

/// C2: one full SPAKE2 run with both sides' RNGs seeded (rand 0.8
/// `StdRng::from_seed`), the subkeys and both MACs.
#[allow(clippy::too_many_arguments)]
fn c2_case(
    name: &str,
    nameplate: &str,
    secret: &str,
    origin: &str,
    principal: &str,
    principal_id: &str,
    id_pub: &[u8],
    sc_pk: &[u8],
    owner: &SigningIdentity,
) -> Value {
    use crate::pairing;
    let (seed_sc, seed_b) = ([0x5c; 32], [0xb0; 32]);
    let sc = pairing::PakeSession::start_with_rng(nameplate, secret, origin, StdRng::from_seed(seed_sc));
    let b = pairing::PakeSession::start_with_rng(nameplate, secret, origin, StdRng::from_seed(seed_b));
    let (msg_sc, msg_b) = (sc.msg().to_vec(), b.msg().to_vec());
    let k = sc.finish(&msg_b).unwrap();
    assert_eq!(&k[..], &b.finish(&msg_sc).unwrap()[..], "both sides agree");
    let sub = pairing::subkeys(&k);
    let keys_input = pairing::keys_mac_input(principal, principal_id, id_pub, sc_pk);
    let keys_mac = pairing::keys_mac(&sub.k_keys[..], principal, principal_id, id_pub, sc_pk);
    let uik_id = owner.user_id();
    let owner_input = pairing::owner_mac_input(&uik_id, &owner.public_bytes());
    let owner_mac = pairing::owner_mac(&sub.k_owner[..], &uik_id, &owner.public_bytes());
    json!({
        "name": name,
        "nameplate": nameplate,
        "secret": secret,
        "code": pairing::display_code(nameplate, secret),
        "link": pairing::link(origin, nameplate, secret),
        "origin": origin,
        "password": hex(&pairing::password(nameplate, secret)),
        "identity": hex(&pairing::identity(origin)),
        "rng": "rand 0.8 StdRng::from_seed (ChaCha12), one per side",
        "rng_seed_sc": hex(&seed_sc),
        "rng_seed_browser": hex(&seed_b),
        "msg_sc": hex(&msg_sc),
        "msg_b": hex(&msg_b),
        "k": hex(&k),
        "k_keys": hex(&sub.k_keys[..]),
        "k_owner": hex(&sub.k_owner[..]),
        "principal": principal,
        "principal_id": principal_id,
        "id_pub": hex(id_pub),
        "sc_pk": hex(sc_pk),
        "keys_mac_input": hex(&keys_input),
        "keys_mac": hex(&keys_mac),
        "uik_id": uik_id,
        "uik_pub": hex(&owner.public_bytes()),
        "owner_mac_input": hex(&owner_input),
        "owner_mac": hex(&owner_mac),
        "wire": {
            "msg_sc": b64u(&msg_sc),
            "msg_b": b64u(&msg_b),
            "keys_mac": b64u(&keys_mac),
            "owner_mac": b64u(&owner_mac),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn c3_case(
    name: &str,
    approver: &SigningIdentity,
    approver_seed: &[u8; 32],
    vault_id: &str,
    op_id: &str,
    r: &[u8],
    op: &Value,
    credential_id: &[u8],
    k: &[u8],
    rng_seed: u8,
) -> Value {
    let pk = sc_pk();
    let beta = binding_for_op(DOMAIN_STANDARD, r, op).unwrap();
    let op_canonical = canonicalize_body(op).unwrap();
    let (k_enc, k_ct) = seal_k(&pk, k, op_id, rng_seed);
    let id = approver.user_id();
    let input = identity::grant_id_input(vault_id, op_id, &beta, credential_id, &k_enc, &k_ct, &pk, &id);
    let sig = approver.sign(&input);
    assert!(identity::verify(&approver.public_bytes(), &input, &sig));
    // The seal opens with sc_sk (sanity: the vector's k_enc/k_ct are a real seal).
    let sc = crate::crypto::envelope::ScKeyPair {
        sk: <<SuiteKem as Kem>::PrivateKey as hpke::Deserializable>::from_bytes(&SC_SK).unwrap(),
        pk: <<SuiteKem as Kem>::PublicKey as hpke::Deserializable>::from_bytes(&pk).unwrap(),
    };
    assert_eq!(sc.open(&k_enc, &k_ct, &grant_k_seal_info(op_id), &[]).unwrap(), k);
    json!({
        "name": name,
        "approver_seed": hex(approver_seed),
        "approver_pub": hex(&approver.public_bytes()),
        "id": id,
        "vault_id": vault_id,
        "op_id": op_id,
        "r": hex(r),
        "op": op,
        "op_canonical": hex(&op_canonical),
        "beta": hex(&beta),
        "credential_id": hex(credential_id),
        "k": hex(k),
        "sc_sk": hex(&SC_SK),
        "sc_pk": hex(&pk),
        "k_seal_info": hex(&grant_k_seal_info(op_id)),
        "k_enc": hex(&k_enc),
        "k_ct": hex(&k_ct),
        "seal_hash": hex(&identity::grant_seal_hash(&k_enc, &k_ct)),
        "input": hex(&input),
        "id_sig": hex(&sig),
        "wire": {
            "id": id,
            "id_sig": b64u(&sig),
            "k_enc": b64u(&k_enc),
            "k_ct": b64u(&k_ct),
        },
    })
}

fn c4_case(name: &str, owner: &SigningIdentity, sigs: &[[u8; 64]]) -> Value {
    let anchor = owner.user_id();
    let max_seq = sigs.len() as u64;
    let events_hash = identity::principal_events_hash(sigs);
    let input = identity::principal_head_input(&anchor, max_seq, &events_hash);
    let sig = owner.sign(&input);
    assert!(identity::verify(&owner.public_bytes(), &input, &sig));
    json!({
        "name": name,
        "owner_seed": hex(&OWNER_SEED),
        "owner_pub": hex(&owner.public_bytes()),
        "anchor": anchor,
        "max_seq": max_seq,
        "event_sigs": sigs.iter().map(|s| hex(s)).collect::<Vec<_>>(),
        "events_hash": hex(&events_hash),
        "input": hex(&input),
        "sig": hex(&sig),
        "wire": {
            "anchor": anchor,
            "max_seq": max_seq,
            "events_hash": b64u(&events_hash),
            "sig": b64u(&sig),
        },
    })
}

fn generate() -> Value {
    let owner = SigningIdentity::from_seed(&OWNER_SEED);
    let admin = SigningIdentity::from_seed(&ADMIN_SEED);
    let dik = SigningIdentity::from_seed(&DIK_SEED);
    let dev_id = derive_id(IdKind::Device, &dik.public_bytes());
    let agent = AgentRoot::from_seed(AGENT_ROOT);
    let aik_pub = agent.identity().public_bytes();
    let ag_id = agent.agent_id();
    let pk = sc_pk();

    // C1: device admit (seq 1, carries sc_pk), agent admit (seq 2, empty), device revoke (seq 3, empty).
    let (c1a, s1) = c1_case("device_admit", &owner, "admit", "device", &dev_id, 1, &pk);
    let (c1b, s2) = c1_case("agent_admit", &owner, "admit", "agent", &ag_id, 2, &[]);
    let (c1c, s3) = c1_case("device_revoke", &owner, "revoke", "device", &dev_id, 3, &[]);

    // C2: a device on dev, an agent on prod.
    let c2a = c2_case(
        "device", "0421", "12345678", "https://app.dev.safeclaw.pro",
        "device", &dev_id, &dik.public_bytes(), &pk, &owner,
    );
    let c2b = c2_case(
        "agent", "9067", "00042517", "https://app.safeclaw.pro",
        "agent", &ag_id, &aik_pub, &[], &owner,
    );

    // C3: the requester approving their own op with the 32-byte K, and an admin
    // approving another member's op with the 64-byte K bundle (batch row shape).
    let op1 = json!({
        "act": { "type": "use", "service": "github", "method": "GET", "path": "/user" },
        "op_id": "op_0001",
        "vault_id": "11111111-2222-3333-4444-555555555555",
    });
    let op2 = json!({
        "act": { "type": "reveal", "path": "OPENAI_API_KEY" },
        "op_id": "op_0002",
        "vault_id": "11111111-2222-3333-4444-555555555555",
    });
    let c3a = c3_case(
        "requester_k32",
        &owner,
        &OWNER_SEED,
        "11111111-2222-3333-4444-555555555555",
        "op_0001",
        &[0x11; 32],
        &op1,
        &[0xc1; 16],
        &[0x6b; 32],
        0x31,
    );
    let k_bundle: Vec<u8> = (0..64u8).collect();
    let c3b = c3_case(
        "admin_bundle64",
        &admin,
        &ADMIN_SEED,
        "11111111-2222-3333-4444-555555555555",
        "op_0002",
        &[0x22; 32],
        &op2,
        &[0xc2; 20],
        &k_bundle,
        0x32,
    );

    // C4: head over the three C1 events, and over the first two (a truncated tail
    // carries a different, separately signed head).
    let c4a = c4_case("head_3", &owner, &[s1, s2, s3]);
    let c4b = c4_case("head_2", &owner, &[s1, s2]);

    json!({
        "contract": "grant-v3",
        "generator": "safeclaw core src/contract_vectors.rs",
        "conventions": {
            "lp": "u32_be(len) || bytes",
            "u64be": "8-byte big-endian",
            "hex": "every byte field outside `wire` is lowercase hex",
            "wire": "bytes inside `wire` are base64url without padding, except the C1 event `sig`, which keeps the ledger's shipped standard base64",
        },
        "keys": {
            "owner_seed": hex(&OWNER_SEED),
            "owner_pub": hex(&owner.public_bytes()),
            "owner_id": owner.user_id(),
            "admin_seed": hex(&ADMIN_SEED),
            "admin_pub": hex(&admin.public_bytes()),
            "admin_id": admin.user_id(),
            "dik_seed": hex(&DIK_SEED),
            "dik_pub": hex(&dik.public_bytes()),
            "dev_id": dev_id,
            "agent_root": hex(&AGENT_ROOT),
            "aik_pub": hex(&aik_pub),
            "ag_id": ag_id,
            "sc_sk": hex(&SC_SK),
            "sc_pk": hex(&pk),
        },
        "c1": [c1a, c1b, c1c],
        "c2": [c2a, c2b],
        "c3": [c3a, c3b],
        "c4": [c4a, c4b],
    })
}

#[test]
fn contract_vectors_grant_v3() {
    let doc = generate();
    let again = generate();
    assert_eq!(doc, again, "vector generation is deterministic");
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if let Ok(out) = std::env::var("GRANT_V3_VECTORS_OUT") {
        std::fs::write(&out, &text).expect("write vectors file");
    }
    // Pin the whole document: any change to a C1-C4 input or construction moves
    // this digest. Do NOT update it to make the test pass without updating the
    // contract and regenerating the shared vectors file.
    let digest = hex(&Sha256::digest(text.as_bytes()));
    assert_eq!(digest, "d8c4692546f150eed7c14845e3494ca34598663ac218b7d3b886caef36c84a9f");
}
