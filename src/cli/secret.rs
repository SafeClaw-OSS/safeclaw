//! `safeclaw set <KEY> <VALUE>` / `safeclaw get <KEY>` / `safeclaw rm <KEY>`
//!
//! Two passkey gestures: unlock (PRF + assertion) for current state,
//! then write (assertion only) to seal + submit. All crypto local.

use std::collections::BTreeMap;
use std::io::IsTerminal;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, ApproveOpts};
use crate::cli::conn::{
    insert_raw_connection, remove_connection, valid_conn_id, valid_role, validate_raw_host,
};
use crate::cli::webauthn::*;
use crate::config::{GetArgs, RmArgs, SetArgs};
use crate::crypto::kdf::WRAP_VERSION;

const DS_SEAL: &[u8] = b"sudp/v1/seal";

/// What `sc set` does with the item's broker binding.
enum BrokerIntent {
    /// Store the value with no host — human-only, invisible to the agent.
    NoBroker,
    /// Create a raw connection anchored to these exact FQDNs.
    Host(Vec<String>),
}

pub async fn run_set(args: SetArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    // §1: secret KEYs are ALWAYS uppercase. Force-uppercase on input (a lowercase
    // key is auto-converted, never stored lowercase) so there is one canonical
    // form. Reject anything that isn't a valid env KEY even after uppercasing.
    let key = args.key.trim().to_ascii_uppercase();
    if !valid_role(&key) {
        return Err(format!(
            "'{}' is not a valid secret key — use UPPERCASE letters, digits and '_' (e.g. STRIPE_KEY)",
            args.key.trim()
        ));
    }

    // Value: explicit arg, else hidden TTY prompt, else (non-TTY) an error.
    let value = match args.value.clone() {
        Some(v) => v,
        None => prompt_secret_value(&key)?,
    };

    // Broker intent: --no-broker | --host <h..> | (TTY) prompt | (non-TTY) error.
    let intent = resolve_broker_intent(&key, &args.host, args.no_broker)?;

    // The single-secret sugar: the connection id is the lowercased key — a plain
    // handle (safe now that `secrets` is stored explicitly, no reverse-index
    // coupling — §9). Validate the id + anchor hosts BEFORE spending a passkey
    // gesture — an invalid --host must not cost the user an unlock touch.
    let conn = key.to_ascii_lowercase();
    if let BrokerIntent::Host(hosts) = &intent {
        if !valid_conn_id(&conn) {
            return Err(format!(
                "can't derive a connection id from '{}' — use `sc connect <name> --host {} --secret {}=<value>` instead",
                key,
                hosts.first().map(String::as_str).unwrap_or("<domain>"),
                key
            ));
        }
        for h in hosts {
            validate_raw_host(h)?;
        }
    }

    eprintln!(
        "safeclaw set {} — two passkey gestures (unlock + write)",
        key
    );
    let meta = fetch_passkey_meta(&custodian, &vault).await?;
    let (kv, mut aux, user_key) = do_unlock(
        &custodian,
        &vault,
        &meta,
        args.no_browser,
        args.timeout,
        args.cb_port,
    )
    .await?;

    let mut new_kv = kv;
    new_kv.insert(key.clone(), value);

    match intent {
        BrokerIntent::NoBroker => {
            // Opting out must actually un-broker: drop any raw connection a prior
            // `sc set <key> --host …` created for this key, else the item stays
            // agent-usable through that stale connection despite --no-broker.
            if remove_connection(&mut aux, &conn) {
                eprintln!("  removed the prior host anchor for '{}'", conn);
            }
            eprintln!("  stored · no host anchored — agent cannot use this item (`sc secret get` reveals it for a human)");
        }
        BrokerIntent::Host(hosts) => {
            // Raw single-secret connection: explicit `secrets = [KEY]`, id = the
            // lowercased key handle, stored bare (§2/§9).
            insert_raw_connection(&mut aux, &conn, &hosts, std::slice::from_ref(&key));
            eprintln!(
                "  connection '{}' → {} · phantom __sc__{}__",
                conn,
                hosts.join(", "),
                conn
            );
        }
    }

    seal_and_submit_write(
        &custodian,
        &vault,
        &meta,
        &user_key,
        &new_kv,
        &aux,
        args.no_browser,
        args.timeout,
        args.cb_port,
    )
    .await?;
    eprintln!("safeclaw set — {} written", key);
    Ok(())
}

/// Decide the broker binding for `sc set`. Host is a REQUIRED answer (spec §11):
/// `--no-broker` / `--host none` opt out explicitly; otherwise `--host` anchors;
/// missing on a TTY → prompt; missing off a TTY → a clear error naming both
/// fixes (never hang, never silently store an unusable item).
fn resolve_broker_intent(
    key: &str,
    host: &[String],
    no_broker: bool,
) -> Result<BrokerIntent, String> {
    if no_broker {
        return Ok(BrokerIntent::NoBroker);
    }
    // `--host none` is the explicit opt-out sentinel.
    if host.len() == 1 && host[0].eq_ignore_ascii_case("none") {
        eprintln!("  --host none → stored without a host · agent cannot use this item");
        return Ok(BrokerIntent::NoBroker);
    }
    if !host.is_empty() {
        return Ok(BrokerIntent::Host(host.to_vec()));
    }
    if std::io::stdin().is_terminal() {
        let entered = prompt_host(key)?;
        if entered.eq_ignore_ascii_case("none") {
            eprintln!("  stored without a host · agent cannot use this item");
            return Ok(BrokerIntent::NoBroker);
        }
        Ok(BrokerIntent::Host(vec![entered]))
    } else {
        Err(format!(
            "'{}' needs a host so the agent can use it — pass `--host <domain>` (the API's domain, e.g. api.stripe.com), or `--no-broker` to store it for humans only",
            key
        ))
    }
}

/// Hidden value prompt (TTY only — keeps the secret out of shell history / `ps`).
fn prompt_secret_value(key: &str) -> Result<String, String> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "no value given for '{}' — pass it as an argument (non-interactive input isn't a terminal)",
            key
        ));
    }
    let v = rpassword::prompt_password(format!("Value for {} (hidden): ", key))
        .map_err(|e| format!("read value: {}", e))?;
    if v.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(v)
}

/// Required host prompt. Echoes the intent so an arg-order slip is visible.
fn prompt_host(key: &str) -> Result<String, String> {
    use std::io::Write as _;
    eprintln!("'{}' needs an egress host so the agent can use it.", key);
    eprint!("Host (the API's exact domain, e.g. api.stripe.com; 'none' = store for humans only): ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read host: {}", e))?;
    let h = line.trim().to_string();
    if h.is_empty() {
        return Err(
            "a host is required (or `none` / `--no-broker` to store for humans only)".into(),
        );
    }
    Ok(h)
}

pub async fn run_rm(args: RmArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    // §1: secret KEYs are canonical uppercase — normalize on input so `sc rm
    // github_token` finds the stored `GITHUB_TOKEN`.
    let key = args.key.trim().to_ascii_uppercase();
    if key.is_empty() {
        return Err("key required".into());
    }
    // Anti-fat-finger confirm BEFORE the gesture (the grant page also names the
    // op). The referenced-by detail is reported AFTER — the daemon computes it
    // while it holds the open vault. The KEY name rides the op (public); the
    // value never leaves the vault.
    if !args.force && std::io::stdin().is_terminal() {
        let ans = crate::cli::connect::prompt_line(&format!("Remove key '{}'? [y/N]: ", key))?;
        if !matches!(ans.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("aborted");
            return Ok(());
        }
    }
    let op = json!({
        "act": { "type": { "custom": "secret-rm" }, "target": key, "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let opts = ApproveOpts { no_browser: args.no_browser, cb_port: args.cb_port, timeout: args.timeout };
    let body = approve_op(&custodian, &vault, &op, &format!("Remove key {}", key), &opts).await?;

    let refs: Vec<String> = act_result(&body)
        .get("referenced_by")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    if !refs.is_empty() {
        eprintln!(
            "note: {} is referenced by connection(s): {} — they turn unconfigured until the key is re-added",
            key,
            refs.join(", ")
        );
    }
    println!("key '{}' removed", key);
    Ok(())
}

/// Unlock the vault (passkey gesture 1/2) and return `(kv, aux, user_key)` —
/// the current native-secrets map, the raw `aux` value, and the derived user
/// key. Shared by every CLI verb that mutates the vault (`sc set` / `sc rm` /
/// `sc connect` / `sc service add`).
pub(crate) async fn do_unlock(
    custodian: &str,
    vault: &str,
    meta: &PasskeyMeta,
    no_browser: bool,
    timeout: u64,
    cb_port: Option<u16>,
) -> Result<(BTreeMap<String, String>, Value, Vec<u8>), String> {
    let op = json!({
        "act": { "type": { "custom": "vault-unlock" }, "target": "", "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(custodian, vault, &op).await?;
    let r_bytes = STANDARD
        .decode(&r)
        .map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &op)?;
    let prf_salt_bytes = decode_prf_salt(&meta.prf_salt)?;

    eprintln!("  gesture 1/2: unlock — touch passkey…");
    let result = do_browser_gesture(
        custodian,
        &op_id,
        &beta,
        Some(PRF_EVAL_SALT),
        &meta.credential_id,
        "Unlock vault",
        no_browser,
        timeout,
        false,
        cb_port,
    )
    .await?;

    let prf_first = result
        .prf_first
        .as_deref()
        .ok_or("unlock gesture didn't return prf_first")?;
    let prf_first_bytes = URL_SAFE_NO_PAD
        .decode(prf_first)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;
    let cred_id_raw = URL_SAFE_NO_PAD
        .decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key,
        &prf_salt_bytes,
        &cred_id_raw,
        WRAP_VERSION,
    )
    .map_err(|e| format!("derive wrapping key: {}", e))?;

    let grant = json!({
        "o": op, "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(&result.credential_id, &result.authenticator_data, &result.client_data_json, &result.signature),
    });
    let client = http_client()?;
    let resp = client
        .post(format!(
            "{}/op/{}/approve",
            custodian.trim_end_matches('/'),
            urlencoding::encode(&op_id)
        ))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "unlock HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let kv: BTreeMap<String, String> = body["value"]["kv"]
        .as_object()
        .ok_or("unlock missing value.kv")?
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect();
    let aux = body["value"]["aux"].clone();
    Ok((kv, aux, user_key))
}

/// Reseal `(kv, aux)` under a fresh K and submit the write (passkey gesture
/// 2/2). Shared by every CLI verb that mutates the vault.
pub(crate) async fn seal_and_submit_write(
    custodian: &str,
    vault: &str,
    meta: &PasskeyMeta,
    user_key: &[u8],
    kv: &BTreeMap<String, String>,
    aux: &Value,
    no_browser: bool,
    timeout: u64,
    cb_port: Option<u16>,
) -> Result<(), String> {
    let cred_id_raw = URL_SAFE_NO_PAD
        .decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let new_prf_salt = random_bytes(32);
    let new_k = random_bytes(32);
    let new_wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        user_key,
        &new_prf_salt,
        &cred_id_raw,
        WRAP_VERSION,
    )
    .map_err(|e| format!("derive: {}", e))?;

    let binding = sudp::primitives::WrapBinding {
        credential_id: &cred_id_raw,
        version: WRAP_VERSION,
    };
    let new_wrapped_key = <sudp::primitives::AeadWrap<sudp::primitives::ChaCha20Poly1305>
        as sudp::primitives::KeyWrap>::wrap(&new_wrapping_key, &new_k, &binding)
        .map_err(|e| format!("wrap K: {}", e))?;

    let m = build_protected_state(kv, aux, &meta.credential_id, &new_wrapping_key);
    let canonical =
        sudp::canonical::canonicalize_strict(&m).map_err(|e| format!("canonical: {}", e))?;
    let mut ad = Vec::with_capacity(DS_SEAL.len() + 2);
    ad.extend_from_slice(DS_SEAL);
    ad.extend_from_slice(&WRAP_VERSION.to_be_bytes());
    let ct = <sudp::primitives::ChaCha20Poly1305 as sudp::primitives::Aead>::seal(
        &new_k, &canonical, &ad,
    )
    .map_err(|e| format!("seal: {}", e))?;

    let write_op = json!({
        "act": { "type": "write", "target": "env", "scope": {
            "ciphertext": STANDARD.encode(&ct),
            "wrapped_key": STANDARD.encode(&new_wrapped_key),
            "prf_salt_next": STANDARD.encode(&new_prf_salt),
        }},
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(custodian, vault, &write_op).await?;
    let r_bytes = STANDARD
        .decode(&r)
        .map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &write_op)?;

    eprintln!("  gesture 2/2: write — touch passkey…");
    let result = do_browser_gesture(
        custodian,
        &op_id,
        &beta,
        None,
        &meta.credential_id,
        "Write vault",
        no_browser,
        timeout,
        false,
        cb_port,
    )
    .await?;

    let grant = json!({
        "o": write_op, "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&new_wrapping_key),
        "assertion": assertion_json(&result.credential_id, &result.authenticator_data, &result.client_data_json, &result.signature),
    });
    let client = http_client()?;
    let resp = client
        .post(format!(
            "{}/op/{}/approve",
            custodian.trim_end_matches('/'),
            urlencoding::encode(&op_id)
        ))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "write HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

fn build_protected_state(
    kv: &BTreeMap<String, String>,
    aux: &Value,
    cred_id_b64: &str,
    wrapping_key: &[u8],
) -> Value {
    let mut targets = serde_json::Map::new();
    for (k, v) in kv {
        targets.insert(k.clone(), Value::String(STANDARD.encode(v.as_bytes())));
    }
    let mut peers = serde_json::Map::new();
    peers.insert(
        cred_id_b64.to_string(),
        Value::String(STANDARD.encode(wrapping_key)),
    );
    json!({ "targets": targets, "peers": peers, "aux": aux })
}

fn decode_prf_salt(s: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| format!("decode prf_salt: {}", e))
}

pub async fn run_get(args: GetArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(args.vault.as_deref())?;
    // §1: secret KEYs are canonical uppercase — normalize on input so a human
    // `sc get github_token` resolves the stored `GITHUB_TOKEN`.
    let key = args.key.trim().to_ascii_uppercase();
    if key.is_empty() {
        return Err("key cannot be empty".into());
    }

    let meta = fetch_passkey_meta(&custodian, &vault).await?;

    let op = json!({
        "act": { "type": "export", "target": key, "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": "one" }
    });
    let (op_id, r) = create_op(&custodian, &vault, &op).await?;
    let r_bytes = STANDARD
        .decode(&r)
        .map_err(|e| format!("decode r: {}", e))?;
    let beta = compute_beta(&r_bytes, &op)?;
    let prf_salt_bytes = decode_prf_salt(&meta.prf_salt)?;

    eprintln!("safeclaw get {} — touch passkey…", key);
    let result = do_browser_gesture(
        &custodian,
        &op_id,
        &beta,
        Some(PRF_EVAL_SALT),
        &meta.credential_id,
        &format!("Reveal {}", key),
        args.no_browser,
        args.timeout,
        false,
        args.cb_port,
    )
    .await?;

    let prf_first = result
        .prf_first
        .as_deref()
        .ok_or("gesture didn't return prf_first")?;
    let prf_first_bytes = URL_SAFE_NO_PAD
        .decode(prf_first)
        .map_err(|e| format!("decode prf_first: {}", e))?;
    let user_key = prf_to_user_key(&prf_first_bytes)?;
    let cred_id_raw = URL_SAFE_NO_PAD
        .decode(&meta.credential_id)
        .map_err(|e| format!("decode cred_id: {}", e))?;
    let wrapping_key = crate::crypto::kdf::derive_wrapping_key(
        &user_key,
        &prf_salt_bytes,
        &cred_id_raw,
        WRAP_VERSION,
    )
    .map_err(|e| format!("derive wrapping key: {}", e))?;

    let grant = json!({
        "o": op, "r": r,
        "credential_id": meta.credential_id,
        "wrapping_key": STANDARD.encode(&wrapping_key),
        "assertion": assertion_json(&result.credential_id, &result.authenticator_data, &result.client_data_json, &result.signature),
    });
    let client = http_client()?;
    let resp = client
        .post(format!(
            "{}/op/{}/approve",
            custodian.trim_end_matches('/'),
            urlencoding::encode(&op_id)
        ))
        .json(&grant)
        .send()
        .await
        .map_err(|e| format!("approve: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "approve HTTP {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or("no value in response — op may have been consumed")?;
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(value.as_bytes())
        .map_err(|e| format!("stdout: {}", e))?;
    out.write_all(b"\n").ok();
    Ok(())
}
