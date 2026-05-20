//! Daemon end-to-end protocol test (no browser).
//!
//! Drives a real P-256 keypair through the full SUDP grant pipeline:
//! setup → reveal. Catches binding/canonicalization/AEAD bugs that unit
//! tests miss (they cover individual primitives but not the full chain).
//!
//! Mirrors what the frontend does in `lib/env-grant.ts` but in Rust:
//!   1. Generate a P-256 "passkey".
//!   2. Build a setup operation; wrapped DEK + sealed body go in `setup_payload`.
//!   3. Issue daemon challenge `r`, compute β = H(domain ‖ 0x00 ‖ r ‖ H(canonical(o))).
//!   4. Construct a synthetic WebAuthn assertion (clientDataJSON.challenge =
//!      base64url(β); authenticatorData with valid rpIdHash + UP flag).
//!   5. Sign with the private key, DER-encode.
//!   6. Submit grant via `dispatch_grant`. Assert `ok: true`.
//!   7. Build a reveal operation, repeat the assertion dance with DOMAIN_STANDARD.
//!   8. Submit grant; assert returned value matches the original plaintext.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use p256::ecdsa::{signature::Signer, DerSignature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use serde_json::json;

use safeclaw::approval::ApprovalStore;
use safeclaw::config::Config;
use safeclaw::crypto::{
    aead::seal as aead_seal,
    binding::{binding_for_op, DOMAIN_SETUP, DOMAIN_STANDARD},
    canonical::canonicalize_body,
    kdf::{derive_kek, WRAP_VERSION},
};
use safeclaw::passkey::challenge::ChallengeStore;
use safeclaw::passkey::webauthn::AssertionData;
use safeclaw::protocol::{
    grant::{Grant, SetupPayload},
    operation::{Act, NewCredential, Operation, Valid, WritePatch},
};
use safeclaw::server::handlers::approve;
use safeclaw::server::handlers::grant::dispatch_grant;
use safeclaw::server::tenant_extractor::TenantId;
use safeclaw::state::AppState;
use safeclaw::storage::TenantDir;

const ORIGIN: &str = "http://localhost:3000";
const RP_ID: &str = "localhost";

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Make a fresh AppState rooted at `tmp_dir`.
fn fresh_state(tmp_dir: &std::path::Path) -> Arc<AppState> {
    let config = Config {
        state_dir: tmp_dir.to_path_buf(),
        port: 0,
        proxy_port: 0,
        bind: "127.0.0.1".into(),
        origin: ORIGIN.into(),
        rp_id: RP_ID.into(),
    };
    std::fs::create_dir_all(config.state_dir.join("tenants")).unwrap();
    let tenants = TenantDir::new(&config.state_dir);
    Arc::new(AppState {
        config,
        tenants,
        challenges: std::sync::Mutex::new(ChallengeStore::new()),
        approvals: std::sync::Mutex::new(ApprovalStore::new()),
    })
}

/// Issue a challenge from the store (bypassing rate-limit so tests are
/// hermetic). Returns base64-encoded `r`.
fn issue_challenge(state: &Arc<AppState>) -> String {
    let mut store = state.challenges.lock().unwrap();
    store
        .issue("127.0.0.1".parse().unwrap())
        .expect("challenge store should accept localhost issuance")
}

/// Build a (synthetic) WebAuthn assertion that signs `β` with `signing_key`.
fn build_assertion(
    signing_key: &SigningKey,
    credential_id_b64: &str,
    beta: &[u8; 32],
    rp_id: &str,
    origin: &str,
) -> AssertionData {
    // clientDataJSON: type, challenge (base64url, no padding), origin.
    // The verifier reads back exactly these bytes; no canonicalization is
    // applied, so the JSON we emit IS what gets hashed.
    let challenge_b64url = URL_SAFE_NO_PAD.encode(beta);
    let client_data = json!({
        "type": "webauthn.get",
        "challenge": challenge_b64url,
        "origin": origin,
    });
    let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
    let client_data_hash = Sha256::digest(&client_data_bytes);

    // authenticatorData = SHA-256(rp_id) ‖ flags=UP(0x01) ‖ signCount=0
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(0x01); // UP flag set
    auth_data.extend_from_slice(&[0u8; 4]);

    // sig = ECDSA-Sign(authenticatorData ‖ SHA-256(clientDataJSON))
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&client_data_hash);
    let der: DerSignature = signing_key.sign(&signed);

    AssertionData {
        credential_id: Some(credential_id_b64.to_string()),
        authenticator_data: STANDARD.encode(&auth_data),
        client_data_json: STANDARD.encode(&client_data_bytes),
        signature: STANDARD.encode(der.to_bytes()),
    }
}

/// Helpers to wrap a fresh DEK + encrypt the canonical KV body using the same
/// AAD constants as `safeclaw::storage::sealed_vault`.
fn wrap_dek_and_body(
    user_key: &[u8],
    prf_salt: &[u8; 32],
    credential_id_raw: &[u8],
    dek: &[u8; 32],
    kv: &serde_json::Value,
) -> (Vec<u8>, Vec<u8>) {
    let kek = derive_kek(user_key, prf_salt, WRAP_VERSION, credential_id_raw).unwrap();
    let wrapped = aead_seal(&kek, dek, b"safeclaw/v1/wrap-dek").unwrap();
    let canonical = canonicalize_body(kv);
    let body = aead_seal(dek, &canonical, b"safeclaw/v1/vault-body").unwrap();
    (wrapped, body)
}

#[tokio::test]
async fn full_setup_then_reveal_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fresh_state(tmp.path());

    let tenant_id = "tenant-a";

    // ── Generate a P-256 "passkey" ─────────────────────────────────────────
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let pk_point = verifying_key.to_encoded_point(false);
    let x = pk_point.x().expect("public key x");
    let y = pk_point.y().expect("public key y");
    let credential_id_raw: [u8; 32] = rand::random();
    let credential_id_b64 = STANDARD.encode(credential_id_raw);

    // ── Client-side material ───────────────────────────────────────────────
    let user_key: [u8; 32] = rand::random();
    let prf_salt: [u8; 32] = rand::random();
    let dek: [u8; 32] = rand::random();
    let initial_kv = json!({
        "env": {
            "api_key": "sk-test-12345",
            "github_token": "ghp_demo_abc",
        }
    });
    let (wrapped_dek, body) =
        wrap_dek_and_body(&user_key, &prf_salt, &credential_id_raw, &dek, &initial_kv);

    // ── Build SETUP operation ──────────────────────────────────────────────
    let setup_op = Operation {
        act: Act::Setup {
            credential: NewCredential {
                credential_id: credential_id_b64.clone(),
                public_key_x: STANDARD.encode(x),
                public_key_y: STANDARD.encode(y),
                prf_salt: STANDARD.encode(prf_salt),
                device_name: "test-device".into(),
            },
        },
        valid: Valid { iat: now_secs(), exp: None },
    };

    let setup_r = issue_challenge(&state);
    let setup_r_raw = STANDARD.decode(&setup_r).unwrap();
    let setup_op_value = serde_json::to_value(&setup_op).unwrap();
    let setup_beta = binding_for_op(DOMAIN_SETUP, &setup_r_raw, &setup_op_value);

    let setup_assertion = build_assertion(
        &signing_key,
        &credential_id_b64,
        &setup_beta,
        RP_ID,
        ORIGIN,
    );

    let setup_grant = Grant {
        o: setup_op,
        r: setup_r,
        credential_id: credential_id_b64.clone(),
        user_key: STANDARD.encode(user_key),
        assertion: setup_assertion,
        setup_payload: Some(SetupPayload {
            wrapped_dek: STANDARD.encode(&wrapped_dek),
            body: STANDARD.encode(&body),
        }),
        opt: None,
    };

    let setup_resp = dispatch_grant(&state, tenant_id, &setup_grant)
        .await
        .expect("setup grant should succeed");
    let setup_body = setup_resp.0;
    assert_eq!(setup_body["ok"], json!(true), "setup body: {:?}", setup_body);
    assert_eq!(setup_body["act"], json!("setup"));

    // Verify vault.dat exists.
    let vault_path = state.tenants.vault_path(tenant_id).unwrap();
    assert!(vault_path.exists(), "vault.dat should exist after setup");

    // ── Build REVEAL operation ─────────────────────────────────────────────
    let reveal_op = Operation {
        act: Act::Reveal { path: "env.api_key".into() },
        valid: Valid { iat: now_secs(), exp: None },
    };
    let reveal_r = issue_challenge(&state);
    let reveal_r_raw = STANDARD.decode(&reveal_r).unwrap();
    let reveal_op_value = serde_json::to_value(&reveal_op).unwrap();
    let reveal_beta = binding_for_op(DOMAIN_STANDARD, &reveal_r_raw, &reveal_op_value);
    let reveal_assertion = build_assertion(
        &signing_key,
        &credential_id_b64,
        &reveal_beta,
        RP_ID,
        ORIGIN,
    );
    let reveal_grant = Grant {
        o: reveal_op,
        r: reveal_r,
        credential_id: credential_id_b64.clone(),
        user_key: STANDARD.encode(user_key),
        assertion: reveal_assertion,
        setup_payload: None,
        opt: None,
    };

    let reveal_resp = dispatch_grant(&state, tenant_id, &reveal_grant)
        .await
        .expect("reveal grant should succeed");
    let reveal_body = reveal_resp.0;
    assert_eq!(reveal_body["ok"], json!(true), "reveal body: {:?}", reveal_body);
    assert_eq!(reveal_body["value"], json!("sk-test-12345"));
}

#[tokio::test]
async fn write_then_reveal_returns_new_value() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fresh_state(tmp.path());
    let tenant_id = "tenant-b";

    // Setup with initial values.
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let pk_point = verifying_key.to_encoded_point(false);
    let x = pk_point.x().unwrap();
    let y = pk_point.y().unwrap();
    let credential_id_raw: [u8; 32] = rand::random();
    let credential_id_b64 = STANDARD.encode(credential_id_raw);

    let user_key: [u8; 32] = rand::random();
    let prf_salt: [u8; 32] = rand::random();
    let dek: [u8; 32] = rand::random();
    let initial_kv = json!({ "env": { "k": "v0" } });
    let (wrapped_dek, body) =
        wrap_dek_and_body(&user_key, &prf_salt, &credential_id_raw, &dek, &initial_kv);

    let setup_op = Operation {
        act: Act::Setup {
            credential: NewCredential {
                credential_id: credential_id_b64.clone(),
                public_key_x: STANDARD.encode(x),
                public_key_y: STANDARD.encode(y),
                prf_salt: STANDARD.encode(prf_salt),
                device_name: "".into(),
            },
        },
        valid: Valid { iat: now_secs(), exp: None },
    };

    let r = issue_challenge(&state);
    let r_raw = STANDARD.decode(&r).unwrap();
    let beta = binding_for_op(DOMAIN_SETUP, &r_raw, &serde_json::to_value(&setup_op).unwrap());
    let assertion = build_assertion(&signing_key, &credential_id_b64, &beta, RP_ID, ORIGIN);
    let setup_grant = Grant {
        o: setup_op,
        r,
        credential_id: credential_id_b64.clone(),
        user_key: STANDARD.encode(user_key),
        assertion,
        setup_payload: Some(SetupPayload {
            wrapped_dek: STANDARD.encode(&wrapped_dek),
            body: STANDARD.encode(&body),
        }),
        opt: None,
    };
    let _ = dispatch_grant(&state, tenant_id, &setup_grant).await.unwrap();

    // ── WRITE: rotate prf_salt, build new wrapped_dek, new body ────────────
    let new_prf_salt: [u8; 32] = rand::random();
    let new_dek: [u8; 32] = rand::random();
    let new_kv = json!({ "env": { "k": "v1" } });
    let (new_wrapped, new_body) =
        wrap_dek_and_body(&user_key, &new_prf_salt, &credential_id_raw, &new_dek, &new_kv);

    let write_op = Operation {
        act: Act::Write {
            patch: WritePatch {
                body: STANDARD.encode(&new_body),
                wrapped_dek: STANDARD.encode(&new_wrapped),
                prf_salt_next: STANDARD.encode(new_prf_salt),
            },
        },
        valid: Valid { iat: now_secs(), exp: None },
    };
    let write_r = issue_challenge(&state);
    let write_r_raw = STANDARD.decode(&write_r).unwrap();
    let write_beta =
        binding_for_op(DOMAIN_STANDARD, &write_r_raw, &serde_json::to_value(&write_op).unwrap());
    let write_assertion =
        build_assertion(&signing_key, &credential_id_b64, &write_beta, RP_ID, ORIGIN);
    let write_grant = Grant {
        o: write_op,
        r: write_r,
        credential_id: credential_id_b64.clone(),
        user_key: STANDARD.encode(user_key),
        assertion: write_assertion,
        setup_payload: None,
        opt: None,
    };
    let write_resp = dispatch_grant(&state, tenant_id, &write_grant).await.unwrap();
    assert_eq!(write_resp.0["ok"], json!(true), "write resp: {:?}", write_resp.0);

    // ── REVEAL: should now read v1 ──────────────────────────────────────────
    let reveal_op = Operation {
        act: Act::Reveal { path: "env.k".into() },
        valid: Valid { iat: now_secs(), exp: None },
    };
    let reveal_r = issue_challenge(&state);
    let reveal_r_raw = STANDARD.decode(&reveal_r).unwrap();
    let reveal_beta = binding_for_op(
        DOMAIN_STANDARD,
        &reveal_r_raw,
        &serde_json::to_value(&reveal_op).unwrap(),
    );
    let reveal_assertion =
        build_assertion(&signing_key, &credential_id_b64, &reveal_beta, RP_ID, ORIGIN);
    let reveal_grant = Grant {
        o: reveal_op,
        r: reveal_r,
        credential_id: credential_id_b64.clone(),
        user_key: STANDARD.encode(user_key),
        assertion: reveal_assertion,
        setup_payload: None,
        opt: None,
    };
    let reveal_resp = dispatch_grant(&state, tenant_id, &reveal_grant).await.unwrap();
    assert_eq!(reveal_resp.0["value"], json!("v1"));
}

#[tokio::test]
async fn cross_tenant_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fresh_state(tmp.path());

    // tenant A sets up.
    let a = setup_tenant(&state, "tenant-A", "alpha-secret").await;

    // tenant B is empty — reveal against B should 409 (vault not initialized).
    let reveal_op = Operation {
        act: Act::Reveal { path: "env.k".into() },
        valid: Valid { iat: now_secs(), exp: None },
    };
    let r = issue_challenge(&state);
    let r_raw = STANDARD.decode(&r).unwrap();
    let beta = binding_for_op(DOMAIN_STANDARD, &r_raw, &serde_json::to_value(&reveal_op).unwrap());
    let assertion = build_assertion(&a.signing_key, &a.credential_id_b64, &beta, RP_ID, ORIGIN);
    let grant = Grant {
        o: reveal_op,
        r,
        credential_id: a.credential_id_b64.clone(),
        user_key: STANDARD.encode(a.user_key),
        assertion,
        setup_payload: None,
        opt: None,
    };
    let err = dispatch_grant(&state, "tenant-B", &grant).await.err();
    assert!(err.is_some(), "reveal against empty tenant should fail");
}

#[tokio::test]
async fn challenge_replay_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = fresh_state(tmp.path());
    let tenant_id = "tenant-replay";
    let a = setup_tenant(&state, tenant_id, "secret").await;

    // First reveal: succeeds.
    let r = issue_challenge(&state);
    let reveal_op = Operation {
        act: Act::Reveal { path: "env.k".into() },
        valid: Valid { iat: now_secs(), exp: None },
    };
    let r_raw = STANDARD.decode(&r).unwrap();
    let beta = binding_for_op(DOMAIN_STANDARD, &r_raw, &serde_json::to_value(&reveal_op).unwrap());
    let assertion = build_assertion(&a.signing_key, &a.credential_id_b64, &beta, RP_ID, ORIGIN);
    let grant1 = Grant {
        o: reveal_op.clone(),
        r: r.clone(),
        credential_id: a.credential_id_b64.clone(),
        user_key: STANDARD.encode(a.user_key),
        assertion,
        setup_payload: None,
        opt: None,
    };
    let _ = dispatch_grant(&state, tenant_id, &grant1).await.unwrap();

    // Second reveal with the SAME `r`: should fail (challenge consumed).
    let assertion2 = build_assertion(&a.signing_key, &a.credential_id_b64, &beta, RP_ID, ORIGIN);
    let grant2 = Grant {
        o: reveal_op,
        r,
        credential_id: a.credential_id_b64.clone(),
        user_key: STANDARD.encode(a.user_key),
        assertion: assertion2,
        setup_payload: None,
        opt: None,
    };
    assert!(
        dispatch_grant(&state, tenant_id, &grant2).await.is_err(),
        "replayed challenge must be rejected"
    );
}

#[tokio::test]
async fn agent_proxy_then_user_confirm_full_flow() {
    use axum::extract::{Path, Query, State};
    use safeclaw::proxy::env::{handle as proxy_handle, poll as proxy_poll, PollQuery};

    let tmp = tempfile::tempdir().unwrap();
    let state = fresh_state(tmp.path());
    let tenant_id = "tenant-agent-flow";
    let a = setup_tenant(&state, tenant_id, "agent-secret-XYZ").await;

    // ── Agent calls proxy port. Daemon creates a pending approval. ─────────
    let (status, body) = proxy_handle(
        State(state.clone()),
        TenantId(tenant_id.into()),
        Path("k".into()),
        Query(PollQuery { approval_id: None }),
    )
    .await
    .expect("proxy create should succeed");
    assert_eq!(status.as_u16(), 202);
    let approval_id = body.0["approval_id"].as_str().unwrap().to_string();
    assert_eq!(body.0["status"], json!("pending_approval"));

    // ── User pulls the canonical op back via /details. ─────────────────────
    let details = approve::details(State(state.clone()), Path(approval_id.clone()))
        .await
        .expect("details should succeed");
    let pending_op_value = &details.0["op"];
    assert_eq!(details.0["status"], json!("pending"));
    assert_eq!(details.0["act"], json!("reveal"));
    assert_eq!(details.0["path"], json!("env.k"));

    // ── User builds a grant over the canonical op and confirms. ────────────
    let pending_op: Operation = serde_json::from_value(pending_op_value.clone()).unwrap();
    let r = issue_challenge(&state);
    let r_raw = STANDARD.decode(&r).unwrap();
    let pending_op_serialized = serde_json::to_value(&pending_op).unwrap();
    let beta = binding_for_op(DOMAIN_STANDARD, &r_raw, &pending_op_serialized);
    let assertion = build_assertion(&a.signing_key, &a.credential_id_b64, &beta, RP_ID, ORIGIN);
    let confirm_grant = Grant {
        o: pending_op,
        r,
        credential_id: a.credential_id_b64.clone(),
        user_key: STANDARD.encode(a.user_key),
        assertion,
        setup_payload: None,
        opt: None,
    };
    let confirm_resp = approve::confirm(
        State(state.clone()),
        Path(approval_id.clone()),
        axum::Json(confirm_grant),
    )
    .await
    .expect("confirm should succeed");
    assert_eq!(confirm_resp.0["status"], json!("approved"));

    // ── Agent polls. First poll consumes the cached value. ────────────────
    let (status, poll_body) = proxy_poll(
        State(state.clone()),
        Path("k".into()),
        Query(PollQuery {
            approval_id: Some(approval_id.clone()),
        }),
    )
    .await
    .expect("poll should succeed");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(poll_body.0["status"], json!("ok"));
    assert_eq!(poll_body.0["value"], json!("agent-secret-XYZ"));

    // ── A second poll on the same approval id is consumed. ────────────────
    let (status2, _) = proxy_poll(
        State(state.clone()),
        Path("k".into()),
        Query(PollQuery {
            approval_id: Some(approval_id.clone()),
        }),
    )
    .await
    .expect("second poll resolves");
    assert_eq!(status2.as_u16(), 410, "consumed approval should return 410");
}

#[tokio::test]
async fn user_rejects_approval() {
    use axum::extract::{Path, Query, State};
    use safeclaw::proxy::env::{handle as proxy_handle, poll as proxy_poll, PollQuery};

    let tmp = tempfile::tempdir().unwrap();
    let state = fresh_state(tmp.path());
    let tenant_id = "tenant-reject";
    let _a = setup_tenant(&state, tenant_id, "secret").await;

    let (_status, body) = proxy_handle(
        State(state.clone()),
        TenantId(tenant_id.into()),
        Path("k".into()),
        Query(PollQuery { approval_id: None }),
    )
    .await
    .unwrap();
    let approval_id = body.0["approval_id"].as_str().unwrap().to_string();

    // User rejects.
    let resp = approve::reject(State(state.clone()), Path(approval_id.clone()))
        .await
        .unwrap();
    assert_eq!(resp.0["status"], json!("rejected"));

    // Agent poll → 403.
    let (status, body) = proxy_poll(
        State(state.clone()),
        Path("k".into()),
        Query(PollQuery {
            approval_id: Some(approval_id),
        }),
    )
    .await
    .unwrap();
    assert_eq!(status.as_u16(), 403);
    assert_eq!(body.0["status"], json!("rejected"));
}

// ─── Helpers ───────────────────────────────────────────────────────────────

struct TenantSetup {
    signing_key: SigningKey,
    credential_id_b64: String,
    user_key: [u8; 32],
}

async fn setup_tenant(state: &Arc<AppState>, tenant_id: &str, value: &str) -> TenantSetup {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let pk_point = verifying_key.to_encoded_point(false);
    let x = pk_point.x().unwrap();
    let y = pk_point.y().unwrap();
    let credential_id_raw: [u8; 32] = rand::random();
    let credential_id_b64 = STANDARD.encode(credential_id_raw);

    let user_key: [u8; 32] = rand::random();
    let prf_salt: [u8; 32] = rand::random();
    let dek: [u8; 32] = rand::random();
    let initial_kv = json!({ "env": { "k": value } });
    let (wrapped_dek, body) =
        wrap_dek_and_body(&user_key, &prf_salt, &credential_id_raw, &dek, &initial_kv);

    let setup_op = Operation {
        act: Act::Setup {
            credential: NewCredential {
                credential_id: credential_id_b64.clone(),
                public_key_x: STANDARD.encode(x),
                public_key_y: STANDARD.encode(y),
                prf_salt: STANDARD.encode(prf_salt),
                device_name: "".into(),
            },
        },
        valid: Valid { iat: now_secs(), exp: None },
    };
    let r = issue_challenge(state);
    let r_raw = STANDARD.decode(&r).unwrap();
    let beta = binding_for_op(DOMAIN_SETUP, &r_raw, &serde_json::to_value(&setup_op).unwrap());
    let assertion = build_assertion(&signing_key, &credential_id_b64, &beta, RP_ID, ORIGIN);
    let setup_grant = Grant {
        o: setup_op,
        r,
        credential_id: credential_id_b64.clone(),
        user_key: STANDARD.encode(user_key),
        assertion,
        setup_payload: Some(SetupPayload {
            wrapped_dek: STANDARD.encode(&wrapped_dek),
            body: STANDARD.encode(&body),
        }),
        opt: None,
    };
    let _ = dispatch_grant(state, tenant_id, &setup_grant).await.unwrap();

    TenantSetup { signing_key, credential_id_b64, user_key }
}
