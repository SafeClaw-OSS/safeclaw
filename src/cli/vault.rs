//! `safeclaw vault ...` — vault lifecycle ops.

use std::io::{self, Write as _};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::json;

use crate::cli::webauthn::*;
use crate::cli::profile::resolve_active;
use crate::config::{ProfileSelectArgs, VaultCreateArgs, VaultDeleteArgs, VaultSubcommand};

pub async fn run(sub: VaultSubcommand) -> Result<(), String> {
    match sub {
        VaultSubcommand::Ls(a) => run_ls(a).await,
        VaultSubcommand::Create(a) => run_create(a).await,
        VaultSubcommand::Delete(a) => run_delete(a).await,
    }
}

async fn run_ls(args: ProfileSelectArgs) -> Result<(), String> {
    let custodian = match args.custodian.as_deref() {
        Some(c) => c.to_string(),
        None => resolve_active(None, args.vault.as_deref())
            .map(|(c, _)| c)
            .unwrap_or_else(|_| "http://127.0.0.1:23294".to_string()),
    };
    let admin_key = std::env::var("SAFECLAW_ADMIN_KEY").map_err(|_| {
        "vault ls needs $SAFECLAW_ADMIN_KEY".to_string()
    })?;
    let url = format!("{}/admin/vaults", custodian.trim_end_matches('/'));
    let client = http_client()?;
    let resp = client.get(&url).header("X-Admin-Key", admin_key)
        .send().await.map_err(|e| format!("reach custodian: {}", e))?;
    let status = resp.status();
    if status.as_u16() == 403 {
        return Err("403 — admin key mismatch or admin endpoints disabled".into());
    }
    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status, resp.text().await.unwrap_or_default()));
    }
    #[derive(serde::Deserialize)]
    struct Body { vaults: Vec<String> }
    let body: Body = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    if body.vaults.is_empty() {
        println!("(no vaults on {})", custodian);
        return Ok(());
    }
    let active = match args.vault.as_deref() {
        Some(v) => Some(v.to_string()),
        None => resolve_active(Some(&custodian), None).ok().map(|(_, v)| v),
    };
    println!("vaults on {}", custodian);
    for v in &body.vaults {
        let m = if active.as_deref() == Some(v.as_str()) { "*" } else { " " };
        println!("  {} {}", m, v);
    }
    Ok(())
}

async fn run_create(args: VaultCreateArgs) -> Result<(), String> {
    use crate::crypto::kdf::WRAP_VERSION;

    let custodian = args.custodian.as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            resolve_active(None, None)
                .map(|(c, _)| c)
                .unwrap_or_else(|_| "http://127.0.0.1:23294".to_string())
        });
    let vault_id = uuid::Uuid::new_v4().to_string();
    eprintln!("safeclaw vault create — new vault {} on {}", vault_id, custodian);

    // ── Step 1: register passkey (WebAuthn create()) ───────────────────
    // PRF eval salt for the create ceremony. Some authenticators support
    // PRF on create; others need a separate get(). We try PRF here and
    // fall back to a second get() below if needed.
    let prf_eval_salt_js = b"safeclaw-prf-v1";
    eprintln!("  step 1/3: register a passkey in your browser…");
    let create_result = do_browser_gesture(
        &custodian, &vault_id, &[0u8; 32],
        Some(prf_eval_salt_js), "",
        "Create vault (register passkey)",
        args.no_browser, args.timeout, true,
    ).await?;

    let cred_id = create_result.credential_id.clone()
        .ok_or("browser didn't return credential_id")?;
    let pub_x = create_result.public_key_x.clone()
        .ok_or("browser didn't return public_key_x")?;
    let pub_y = create_result.public_key_y.clone()
        .ok_or("browser didn't return public_key_y")?;
    let cred_id_raw = URL_SAFE_NO_PAD.decode(&cred_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;

    // ── Step 2: get PRF output (from create if available, else second gesture) ─
    let prf_first_b64 = if let Some(ref pf) = create_result.prf_first {
        pf.clone()
    } else {
        eprintln!("  step 2/3: PRF not available on create — doing a second passkey gesture…");
        let dummy_beta = [0u8; 32];
        let get_result = do_browser_gesture(
            &custodian, &vault_id, &dummy_beta,
            Some(prf_eval_salt_js), &cred_id,
            "Vault setup (PRF)",
            args.no_browser, args.timeout, false,
        ).await?;
        get_result.prf_first.ok_or("PRF still unavailable — authenticator may not support PRF extension")?
    };
    let prf_first_bytes = URL_SAFE_NO_PAD.decode(&prf_first_b64)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;

    // ── Step 3: seal initial vault state ──────────────────────────────
    eprintln!("  step 3/3: sealing initial vault state…");
    let prf_salt = random_bytes(32);
    let state_key = random_bytes(32); // K
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key, &prf_salt, &cred_id_raw, WRAP_VERSION,
    ).map_err(|e| format!("derive wrapping key: {}", e))?;

    let binding = sudp::primitives::WrapBinding { credential_id: &cred_id_raw, version: WRAP_VERSION };
    let wrapped_key = <sudp::primitives::AeadWrap<sudp::primitives::ChaCha20Poly1305>
        as sudp::primitives::KeyWrap>::wrap(&wrapping_key, &state_key, &binding)
        .map_err(|e| format!("wrap K: {}", e))?;

    let empty_state = json!({
        "targets": {},
        "peers": { &cred_id: STANDARD.encode(&wrapping_key) },
        "aux": null
    });
    let canonical_m = sudp::canonical::canonicalize_strict(&empty_state)
        .map_err(|e| format!("canonicalize: {}", e))?;
    let seal_ad = {
        let mut ad = Vec::with_capacity(b"sudp/v1/seal".len() + 2);
        ad.extend_from_slice(b"sudp/v1/seal");
        ad.extend_from_slice(&WRAP_VERSION.to_be_bytes());
        ad
    };
    let ciphertext = <sudp::primitives::ChaCha20Poly1305 as sudp::primitives::Aead>::seal(
        &state_key, &canonical_m, &seal_ad,
    ).map_err(|e| format!("seal M: {}", e))?;

    // ── Build Enroll op + create on daemon ────────────────────────────
    let enroll_op = json!({
        "act": {
            "type": "enroll",
            "target": cred_id,
            "scope": {
                "public_key_x": pub_x,
                "public_key_y": pub_y,
                "prf_salt": STANDARD.encode(&prf_salt),
                "device_name": "CLI",
            }
        },
        "bind": { "redeemer": vault_id },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(&custodian, &vault_id, &enroll_op).await?;
    let r_bytes = STANDARD.decode(&r).map_err(|e| format!("decode r: {}", e))?;
    // Enroll uses DOMAIN_SETUP for β, not DOMAIN_STANDARD.
    let canonical_op = sudp::canonical::canonicalize_strict(&enroll_op)
        .map_err(|e| format!("canonicalize op: {}", e))?;
    let domain_setup = b"safeclaw/v1/binding-setup";
    let beta = sudp::beta::compute_beta_from_canonical::<sudp::primitives::Sha256>(
        domain_setup, &r_bytes, &canonical_op,
    );

    // ── Assertion gesture (sign β) ────────────────────────────────────
    eprintln!("  signing enrollment grant — touch passkey again…");
    let assert_result = do_browser_gesture(
        &custodian, &op_id, &beta,
        None, &cred_id,
        "Confirm vault creation",
        args.no_browser, args.timeout, false,
    ).await?;

    // ── Submit Enroll grant ───────────────────────────────────────────
    let grant = json!({
        "o": enroll_op,
        "r": r,
        "credential_id": cred_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(
            &assert_result.credential_id,
            &assert_result.authenticator_data,
            &assert_result.client_data_json,
            &assert_result.signature,
        ),
        "setup_payload": {
            "wrapped_key": STANDARD.encode(&wrapped_key),
            "ciphertext": STANDARD.encode(&ciphertext),
        }
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&op_id)))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("approve HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }

    // ── Save to config ────────────────────────────────────────────────
    crate::cli::profile::put_active(&custodian, &vault_id)
        .map_err(|e| format!("save config: {}", e))?;
    eprintln!("safeclaw vault create — done!");
    eprintln!("  vault:     {}", vault_id);
    eprintln!("  custodian: {}", custodian);
    eprintln!("  config saved to ~/.config/safeclaw/config.toml");
    Ok(())
}

async fn run_delete(args: VaultDeleteArgs) -> Result<(), String> {
    if !args.yes_i_mean_it {
        return Err("destructive — pass --yes-i-mean-it to confirm vault deletion".into());
    }
    let (custodian, _) = resolve_active(args.custodian.as_deref(), Some(args.vault.as_str()))?;
    let vault = args.vault.trim().to_string();
    if vault.is_empty() {
        return Err("vault id cannot be empty".into());
    }

    if atty_isatty_stdin() {
        eprint!("Type vault id `{}` to confirm permanent deletion: ", vault);
        io::stderr().flush().ok();
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
        if buf.trim() != vault {
            return Err("confirmation mismatch — aborted".into());
        }
    }

    let meta = fetch_passkey_meta(&custodian, &vault).await?;

    let op = json!({
        "act": { "type": { "custom": "vault-delete" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(&custodian, &vault, &op).await?;
    let r_bytes = STANDARD.decode(&r).map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &op)?;

    let prf_salt_bytes = STANDARD.decode(&meta.prf_salt)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&meta.prf_salt))
        .map_err(|e| format!("decode prf_salt: {}", e))?;

    eprintln!("safeclaw vault delete {} — touch passkey…", vault);
    let result = do_browser_gesture(
        &custodian, &op_id, &beta,
        Some(&prf_salt_bytes), &meta.credential_id,
        "Delete vault (irreversible)",
        args.no_browser, args.timeout, false,
    ).await?;

    let prf_first = result.prf_first.ok_or("gesture didn't return prf_first")?;
    let prf_first_bytes = URL_SAFE_NO_PAD.decode(&prf_first)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;
    let cred_id_raw = URL_SAFE_NO_PAD.decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key, &prf_salt_bytes, &cred_id_raw, crate::crypto::kdf::WRAP_VERSION,
    ).map_err(|e| format!("derive wrapping key: {}", e))?;

    let grant = json!({
        "o": op,
        "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(&result.credential_id, &result.authenticator_data, &result.client_data_json, &result.signature),
    });
    let client = http_client()?;
    let resp = client
        .post(format!("{}/op/{}/approve", custodian.trim_end_matches('/'), urlencoding::encode(&op_id)))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("approve HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    eprintln!("safeclaw vault delete — ok (vault {} wiped)", vault);
    Ok(())
}

fn atty_isatty_stdin() -> bool {
    unsafe { libc_isatty(0) != 0 }
}

#[link(name = "c")]
extern "C" {
    #[link_name = "isatty"]
    fn libc_isatty(fd: i32) -> i32;
}
