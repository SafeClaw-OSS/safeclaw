//! The `sc` side of pairing by PAKE short code (grant-v3 contract C2), shared
//! by `sc login` (a device), `sc agent add` (an agent), and `sc setup` (either
//! or both in one ceremony).
//!
//! 1. `POST /api/pair/authorize` with the ordered principal set →
//!    `{nameplate, device_code, interval}`.
//! 2. Generate the 8-digit secret, start SPAKE2 over `NNNN-SSSSSSSS` and the
//!    pinned console origin, `POST /api/pair/start {device_code, pops, msg_sc}`.
//! 3. Print the code `NNNN-SSSS-SSSS` and the pinned console's `/pair` address
//!    (never a server-supplied URL). The code is only ever typed there: a link
//!    carrying it would put someone else's code one click away (RFC 8628 §5.4).
//! 4. Poll; when the browser's `msg_b` arrives, refuse a reflection, finish
//!    SPAKE2 exactly once (any failure kills the code) and
//!    `POST /api/pair/keys {device_code, pops, keys_mac}`.
//! 5. On approval verify `owner_mac` once and every owner-signed admit against
//!    the submitted set before returning any result.

use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::identity::SigningIdentity;
use crate::pairing::{self, PakeSession};

/// One principal in a pairing request.
pub struct PairPrincipal<'a> {
    /// `"device"` or `"agent"`.
    pub kind: &'a str,
    /// Shown in the console (device name / agent name).
    pub name: &'a str,
    /// The self-certifying `dev_…` / `ag_…`.
    pub id: &'a str,
    /// The DIK / AIK, which also signs the proofs of possession.
    pub signer: &'a SigningIdentity,
    /// The daemon's grant-seal key (a device only).
    pub sc_pk: Option<[u8; 32]>,
}

/// What is being paired.
pub struct PairRequest<'a> {
    /// Exactly `[device]`, `[agent]`, or `[device, agent]`.
    pub entries: Vec<PairPrincipal<'a>>,
    /// Cloud backend (API) URL.
    pub cloud: &'a str,
    /// The console origin `sc` pins (never from a server response).
    pub origin: &'a str,
    /// The command to restart with (`sc login` / `sc agent add`).
    pub restart: &'a str,
}

/// A completed pairing: the poll's approval body and the VERIFIED owner.
pub struct Paired {
    pub body: Value,
    /// The approving account's `us_…`, derived from `uik_pub`.
    pub uik_id: String,
    pub uik_pub: [u8; 32],
    /// The owner-signed head position returned with the admits.
    pub head_max_seq: u64,
    /// Every verified admit, in the submitted set order.
    pub entries: Vec<PairedEntry>,
}

/// One verified result from a completed set pairing.
pub struct PairedEntry {
    pub kind: String,
    pub id: String,
    pub admit_seq: u64,
    pub admit: Value,
}

#[derive(Deserialize)]
struct AuthorizeResp {
    nameplate: String,
    device_code: String,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    expires_in: Option<u64>,
}

fn http_detail(status: reqwest::StatusCode, body: &str) -> String {
    let body = body.trim();
    let msg = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("detail")
                .or_else(|| v.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.to_string());
    if msg.is_empty() {
        format!("HTTP {}", status.as_u16())
    } else {
        format!("HTTP {}: {}", status.as_u16(), msg)
    }
}

/// Run the pairing to approval. Every failure after the code is shown ends the
/// code; the user starts again with `req.restart`.
pub async fn pair(client: &reqwest::Client, req: &PairRequest<'_>) -> Result<Paired, String> {
    validate_request(req)?;
    let cloud = req.cloud.trim_end_matches('/');
    let principals: Vec<Value> = req
        .entries
        .iter()
        .map(|entry| {
            let mut value = json!({
                "kind": entry.kind,
                "id": entry.id,
                "name": entry.name,
                // Standard base64, as the backend's self-certification check expects.
                "id_pub": STANDARD.encode(entry.signer.public_bytes()),
            });
            if let Some(pk) = entry.sc_pk {
                value["sc_pk"] = json!(URL_SAFE_NO_PAD.encode(pk));
            }
            value
        })
        .collect();
    let body = json!({ "principals": principals });
    let resp = client
        .post(format!("{}/api/pair/authorize", cloud))
        .json(&body)
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(cloud, &e))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let detail = resp.text().await.unwrap_or_default();
        return Err(format!(
            "could not start pairing ({}). sc may be too old for this server. Run sc upgrade and try again.",
            http_detail(status, &detail)
        ));
    }
    let auth: AuthorizeResp = resp
        .json()
        .await
        .map_err(|e| format!("parse authorize response: {}", e))?;
    if auth.nameplate.len() != 4 || !auth.nameplate.chars().all(|c| c.is_ascii_digit()) {
        return Err("the server returned a malformed pairing code".into());
    }

    // Proofs of possession of every DIK / AIK over the secret device_code.
    let pops: serde_json::Map<String, Value> = req
        .entries
        .iter()
        .map(|entry| {
            (
                entry.id.to_string(),
                json!(STANDARD.encode(entry.signer.sign(auth.device_code.as_bytes()))),
            )
        })
        .collect();

    // SPAKE2 for this one secret. The secret is dropped (zeroized) right after
    // the code is shown; the session finishes at most once.
    let mut session = {
        let secret = pairing::gen_secret();
        let session = PakeSession::start(&auth.nameplate, &secret, req.origin);
        let resp = client
            .post(format!("{}/api/pair/start", cloud))
            .json(&json!({
                "device_code": auth.device_code,
                "pops": pops,
                "msg_sc": URL_SAFE_NO_PAD.encode(session.msg()),
            }))
            .send()
            .await
            .map_err(|e| crate::cli::neterr::reach_failed(cloud, &e))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(format!(
                "could not start pairing ({})",
                http_detail(status, &detail)
            ));
        }
        let pair_url = format!("{}/pair", req.origin.trim_end_matches('/'));
        let display_code = pairing::display_code(&auth.nameplate, &secret);
        eprintln!();
        eprintln!("Open {} and enter this code:", pair_url);
        eprintln!("  {}", display_code);
        eprintln!();
        eprintln!("Waiting for you to approve in the browser…");
        crate::cli::human_action::report(&pair_url, Some(&display_code), auth.expires_in);
        Some(session)
    };
    let own_msg = session
        .as_ref()
        .map(|s| s.msg().to_vec())
        .unwrap_or_default();
    let mut k_owner: Option<zeroize::Zeroizing<[u8; 32]>> = None;
    let id_pubs: Vec<[u8; 32]> = req
        .entries
        .iter()
        .map(|entry| entry.signer.public_bytes())
        .collect();

    let interval = auth.interval.unwrap_or(5).clamp(1, 30);
    // A dropped connection while the person reads the page is not a failed pairing:
    // keep polling through about a minute of consecutive network errors (the code's
    // own expiry still ends it with 410).
    let max_net_errors = (60 / interval).max(3);
    let mut net_errors = 0u64;
    let dead = |why: &str| {
        format!(
            "{} This code can't be used again. Run {} for a new one.",
            why, req.restart
        )
    };
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let presp = match client
            .post(format!("{}/api/pair/poll", cloud))
            .json(&json!({ "device_code": auth.device_code, "pops": pops }))
            .send()
            .await
        {
            Ok(r) => {
                net_errors = 0;
                r
            }
            Err(e) => {
                net_errors += 1;
                if net_errors >= max_net_errors {
                    return Err(crate::cli::neterr::reach_failed(cloud, &e));
                }
                continue;
            }
        };
        let status = presp.status();
        if status.as_u16() == 410 {
            return Err(format!(
                "the pairing code expired before it was approved. Run {} again.",
                req.restart
            ));
        }
        let text = presp.text().await.unwrap_or_default();
        if !status.is_success() {
            if text.contains("pair_code_mismatch") {
                return Err(dead("The code was entered wrong, or entered again (for example after the page reloaded)."));
            }
            return Err(format!("pairing failed ({})", http_detail(status, &text)));
        }
        let poll: Value =
            serde_json::from_str(&text).map_err(|e| format!("parse poll response: {}", e))?;
        let state = poll.get("status").and_then(|v| v.as_str()).unwrap_or("");

        // The browser's SPAKE2 message: finish once, then authenticate our keys.
        if let Some(msg_b) = poll.get("msg_b").and_then(|v| v.as_str()) {
            if let Some(s) = session.take() {
                let peer = URL_SAFE_NO_PAD
                    .decode(msg_b)
                    .map_err(|_| dead("The browser's pairing message was malformed."))?;
                if peer == own_msg {
                    return Err(dead("The pairing message was reflected back."));
                }
                let k = s
                    .finish(&peer)
                    .map_err(|_| dead("The browser's pairing message was malformed."))?;
                crate::cli::human_action::code_consumed();
                let sub = pairing::subkeys(&k);
                let mac_entries: Vec<pairing::PairEntry<'_>> = req
                    .entries
                    .iter()
                    .zip(&id_pubs)
                    .map(|(entry, id_pub)| pairing::PairEntry {
                        kind: entry.kind,
                        id: entry.id,
                        name: entry.name,
                        id_pub,
                        sc_pk: entry.sc_pk.as_ref().map(|pk| &pk[..]).unwrap_or(&[]),
                    })
                    .collect();
                let mac = pairing::keys_mac(&sub.k_keys[..], &mac_entries);
                // Store-once on the server (the same keys_mac again is a no-op), so a
                // send that failed on the wire is safe to repeat.
                let body = json!({
                    "device_code": auth.device_code,
                    "pops": pops,
                    "keys_mac": URL_SAFE_NO_PAD.encode(mac),
                });
                let mut tries = 0;
                let resp = loop {
                    match client
                        .post(format!("{}/api/pair/keys", cloud))
                        .json(&body)
                        .send()
                        .await
                    {
                        Ok(r) => break r,
                        Err(e) => {
                            tries += 1;
                            if tries >= 5 {
                                return Err(crate::cli::neterr::reach_failed(cloud, &e));
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                };
                if !resp.status().is_success() {
                    let st = resp.status();
                    let detail = resp.text().await.unwrap_or_default();
                    return Err(dead(&format!(
                        "Pairing failed ({}).",
                        http_detail(st, &detail)
                    )));
                }
                k_owner = Some(sub.k_owner);
            }
        }

        match state {
            "pending" | "pake" | "" => continue,
            "denied" => return Err("pairing was declined in the browser.".into()),
            "failed" => return Err(dead("The code was entered wrong, or entered again (for example after the page reloaded).")),
            "approved" => {
                let k_owner = k_owner.ok_or_else(|| {
                    dead("The server reported an approval without the code exchange.")
                })?;
                return verify_approval(poll, &k_owner[..], req).map_err(|e| dead(&e));
            }
            other => return Err(format!("unexpected pairing status '{}'", other)),
        }
    }
}

/// Step 5: the approving owner is authenticated by `owner_mac` (only the
/// browser that held the code could compute it) and must have signed every
/// admit in the submitted set. No result is returned until all admits verify.
fn verify_approval(body: Value, k_owner: &[u8], req: &PairRequest<'_>) -> Result<Paired, String> {
    let uik_pub: [u8; 32] = body
        .get("account_uik_pub")
        .and_then(|v| v.as_str())
        .and_then(|s| {
            URL_SAFE_NO_PAD
                .decode(s)
                .or_else(|_| STANDARD.decode(s))
                .ok()
        })
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or("The approval carries no account key.")?;
    let uik_id = crate::identity::derive_id(crate::identity::IdKind::User, &uik_pub);
    if let Some(label) = body.get("account_uik_id").and_then(|v| v.as_str()) {
        if !label.is_empty() && label != uik_id {
            return Err("The approval names an account its key does not match.".into());
        }
    }
    let mac: [u8; 32] = body
        .get("owner_mac")
        .and_then(|v| v.as_str())
        .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or("The approval carries no owner proof.")?;
    let want = pairing::owner_mac(k_owner, &uik_id, &uik_pub);
    if !crate::crypto::binding::constant_time_eq(&mac, &want) {
        return Err("The approving account could not be verified (owner proof mismatch).".into());
    }
    let admits = body
        .get("admits")
        .and_then(Value::as_array)
        .ok_or("The approval carries no owner-signed admits.")?;
    if admits.len() != req.entries.len() {
        return Err("The approval carries another number of admits than requested.".into());
    }
    let mut verified = Vec::with_capacity(req.entries.len());
    for (entry, admit) in req.entries.iter().zip(admits) {
        let sc_pk = entry.sc_pk.as_ref().map(|pk| &pk[..]).unwrap_or(&[]);
        let owner =
            crate::principal_ledger::verify_pairing_admit(admit, &uik_pub, entry.id, sc_pk)?;
        debug_assert_eq!(owner, uik_id);
        let admit_seq = admit
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or("An approved admit carries no seq.")?;
        verified.push(PairedEntry {
            kind: entry.kind.to_string(),
            id: entry.id.to_string(),
            admit_seq,
            admit: admit.clone(),
        });
    }
    let head = body
        .get("head")
        .ok_or("The approval carries no signed ledger head.")?;
    let head_max_seq = crate::principal_ledger::verify_pairing_head(head, &uik_pub)?;
    if verified.iter().any(|entry| entry.admit_seq > head_max_seq) {
        return Err("An approved admit is beyond the signed ledger head.".into());
    }
    Ok(Paired {
        body,
        uik_id,
        uik_pub,
        head_max_seq,
        entries: verified,
    })
}

fn validate_request(req: &PairRequest<'_>) -> Result<(), String> {
    let kinds: Vec<&str> = req.entries.iter().map(|entry| entry.kind).collect();
    if !matches!(
        kinds.as_slice(),
        ["device"] | ["agent"] | ["device", "agent"]
    ) {
        return Err("pairing requires [device], [agent], or [device, agent]".into());
    }
    for entry in &req.entries {
        match (entry.kind, entry.sc_pk) {
            ("device", Some(_)) | ("agent", None) => {}
            ("device", None) => return Err("a device pairing entry requires sc_pk".into()),
            ("agent", Some(_)) => return Err("an agent pairing entry cannot carry sc_pk".into()),
            _ => unreachable!("the set shape checked supported kinds"),
        }
    }
    if req.entries.len() == 2 && req.entries[0].id == req.entries[1].id {
        return Err("pairing entry ids must be unique".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The approval checks the owner proof and every admit before returning.
    #[test]
    fn approval_needs_owner_mac_and_all_our_admits() {
        let owner = SigningIdentity::from_seed(&[7u8; 32]);
        let acct = owner.user_id();
        let dik = SigningIdentity::from_seed(&[8u8; 32]);
        let dev = dik.id(crate::identity::IdKind::Device);
        let aik = SigningIdentity::from_seed(&[9u8; 32]);
        let agent = aik.id(crate::identity::IdKind::Agent);
        let pk = [5u8; 32];
        let req = PairRequest {
            entries: vec![
                PairPrincipal {
                    kind: "device",
                    name: "box",
                    id: &dev,
                    signer: &dik,
                    sc_pk: Some(pk),
                },
                PairPrincipal {
                    kind: "agent",
                    name: "codex",
                    id: &agent,
                    signer: &aik,
                    sc_pk: None,
                },
            ],
            cloud: "https://x",
            origin: "https://app.x",
            restart: "sc setup",
        };
        let k_owner = [3u8; 32];
        let device_input =
            crate::identity::principal_event_input(&acct, "admit", &dev, 2, &acct, &pk);
        let agent_input =
            crate::identity::principal_event_input(&acct, "admit", &agent, 3, &acct, &[]);
        let events_hash = [6u8; 32];
        let head_input = crate::identity::principal_head_input(&acct, 3, &events_hash);
        let body = |mac: [u8; 32], device_sc: &[u8], agent_id: &str| {
            json!({
                "status": "approved",
                "account_uik_id": acct,
                "account_uik_pub": URL_SAFE_NO_PAD.encode(owner.public_bytes()),
                "owner_mac": URL_SAFE_NO_PAD.encode(mac),
                "admits": [{
                    "seq": 2, "op": "admit", "principal_id": dev, "anchor_uik": acct,
                    "owner_id": acct, "sc_pk": URL_SAFE_NO_PAD.encode(device_sc),
                    "sig": STANDARD.encode(owner.sign(&device_input)),
                }, {
                    "seq": 3, "op": "admit", "principal_id": agent_id, "anchor_uik": acct,
                    "owner_id": acct,
                    "sig": STANDARD.encode(owner.sign(&agent_input)),
                }],
                "head": {
                    "anchor": acct,
                    "max_seq": 3,
                    "events_hash": URL_SAFE_NO_PAD.encode(events_hash),
                    "sig": URL_SAFE_NO_PAD.encode(owner.sign(&head_input)),
                },
            })
        };
        let good = pairing::owner_mac(&k_owner, &acct, &owner.public_bytes());
        let p = verify_approval(body(good, &pk, &agent), &k_owner, &req).unwrap();
        assert_eq!(p.uik_id, acct);
        assert_eq!(p.head_max_seq, 3);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[0].id, dev);
        assert_eq!(p.entries[1].id, agent);
        assert!(
            verify_approval(body([0u8; 32], &pk, &agent), &k_owner, &req).is_err(),
            "owner_mac"
        );
        assert!(
            verify_approval(body(good, &[6u8; 32], &agent), &k_owner, &req).is_err(),
            "sc_pk"
        );
        assert!(
            verify_approval(body(good, &pk, "ag_other"), &k_owner, &req).is_err(),
            "every admit is checked"
        );
        let mut b = body(good, &pk, &agent);
        b["account_uik_id"] = json!("us_someoneelse");
        assert!(verify_approval(b, &k_owner, &req).is_err(), "label");
    }

    #[test]
    fn request_shape_is_exact() {
        let dik = SigningIdentity::from_seed(&[8u8; 32]);
        let dev = dik.id(crate::identity::IdKind::Device);
        let base = |entries| PairRequest {
            entries,
            cloud: "https://x",
            origin: "https://app.x",
            restart: "sc setup",
        };
        assert!(validate_request(&base(vec![PairPrincipal {
            kind: "device",
            name: "box",
            id: &dev,
            signer: &dik,
            sc_pk: Some([5u8; 32]),
        }]))
        .is_ok());
        assert!(validate_request(&base(Vec::new())).is_err());
        assert!(validate_request(&base(vec![PairPrincipal {
            kind: "agent",
            name: "codex",
            id: &dev,
            signer: &dik,
            sc_pk: Some([5u8; 32]),
        }]))
        .is_err());
    }
}
