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
    let custodian = args.custodian.as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            resolve_active(None, None)
                .map(|(c, _)| c)
                .unwrap_or_else(|_| "http://127.0.0.1:23294".to_string())
        });

    eprintln!("safeclaw vault create — bootstrapping new vault on {}…", custodian);

    let client = http_client()?;
    let resp = client
        .post(format!("{}/v/new", custodian.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| format!("POST /v/new: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("/v/new HTTP {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let vault_id = body["vault_id"].as_str().ok_or("no vault_id")?.to_string();
    let op_id = body["op_id"].as_str().ok_or("no op_id")?.to_string();
    let r = body["r"].as_str().ok_or("no r")?.to_string();

    eprintln!("  vault id: {}", vault_id);
    eprintln!("  op id:    {}", op_id);

    let r_bytes = STANDARD.decode(&r).map_err(|e| format!("decode r: {}", e))?;
    let enroll_op = json!({
        "act": { "type": "enroll", "target": "", "scope": null },
        "bind": { "redeemer": vault_id },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let beta = compute_beta(&r_bytes, &enroll_op)?;

    eprintln!("safeclaw vault create — register a passkey in your browser…");
    let result = do_browser_gesture(
        &custodian, &op_id, &beta,
        None, "",
        "Create vault (register passkey)",
        args.no_browser, args.timeout, true,
    ).await?;

    let _attestation = result.attestation_object.as_deref()
        .ok_or("browser didn't return attestation_object")?;

    // TODO: CLI builds the initial SealedVault from the attestation +
    // PRF output (if the browser returned one) and submits the Enroll
    // grant. For now, report the vault_id and op_id — the daemon's
    // Enroll handler needs the full grant body (credential pubkey,
    // initial wrapped_key, initial ciphertext) which requires porting
    // the setup ceremony from pro-frontend/lib/vault-grant.ts.
    //
    // This is the LAST piece of Wave 2. The CLI has all the Rust
    // primitives (build_initial, derive_wrapping_key, Aead::seal,
    // KeyWrap::wrap); the missing part is parsing the WebAuthn
    // attestation to extract the credential public key (x, y coords)
    // — which the browser returns in attestationObject.

    eprintln!("safeclaw vault create — passkey registered (vault {})", vault_id);
    eprintln!("  Save this vault id. Run `safeclaw login --custodian {} --vault {}` to set it as active.", custodian, vault_id);
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
