//! The `sc` side of pairing by PAKE short code (grant-v3 contract C2), shared
//! by `sc login` (a device) and `sc agent add` (an agent).
//!
//! 1. `POST /api/pair/authorize` with this principal's public keys →
//!    `{nameplate, device_code, interval}`.
//! 2. Generate the 8-digit secret, start SPAKE2 over `NNNN-SSSSSSSS` and the
//!    pinned console origin, `POST /api/pair/start {device_code, pop, msg_sc}`.
//! 3. Print the code `NNNN-SSSS-SSSS` and the pinned console's `/pair` address
//!    (never a server-supplied URL). The code is only ever typed there: a link
//!    carrying it would put someone else's code one click away (RFC 8628 §5.4).
//! 4. Poll; when the browser's `msg_b` arrives, refuse a reflection, finish
//!    SPAKE2 exactly once (any failure kills the code) and
//!    `POST /api/pair/keys {device_code, pop, keys_mac}`.
//! 5. On approval verify `owner_mac` and the owner-signed admit of this
//!    principal's own keys under the served owner key; return that VERIFIED
//!    owner for the caller to pin.

use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::identity::SigningIdentity;
use crate::pairing::{self, PakeSession};

/// What is being paired.
pub struct PairRequest<'a> {
    /// `"device"` or `"agent"`.
    pub principal: &'a str,
    /// Shown in the console (device name / agent name).
    pub name: &'a str,
    /// The self-certifying `dev_…` / `ag_…`.
    pub principal_id: &'a str,
    /// The DIK / AIK, which also signs the proofs of possession.
    pub signer: &'a SigningIdentity,
    /// The daemon's grant-seal key (a device only).
    pub sc_pk: Option<[u8; 32]>,
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
}

#[derive(Deserialize)]
struct AuthorizeResp {
    nameplate: String,
    device_code: String,
    #[serde(default)]
    interval: Option<u64>,
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
    let cloud = req.cloud.trim_end_matches('/');
    let mut body = json!({
        "principal": req.principal,
        "device_name": req.name,
        "device_id": req.principal_id,
        // Standard base64, as the backend's self-certification check expects.
        "device_pubkey": STANDARD.encode(req.signer.public_bytes()),
    });
    if let Some(pk) = req.sc_pk {
        body["sc_pk"] = json!(URL_SAFE_NO_PAD.encode(pk));
    }
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
            "could not start pairing ({}). Your `sc` may be too old for this server: run \
             `sc upgrade` and try again.",
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

    // Proof of possession of the DIK / AIK over the secret device_code.
    let pop = STANDARD.encode(req.signer.sign(auth.device_code.as_bytes()));

    // SPAKE2 for this one secret. The secret is dropped (zeroized) right after
    // the code is shown; the session finishes at most once.
    let mut session = {
        let secret = pairing::gen_secret();
        let session = PakeSession::start(&auth.nameplate, &secret, req.origin);
        let resp = client
            .post(format!("{}/api/pair/start", cloud))
            .json(&json!({
                "device_code": auth.device_code,
                "pop": pop,
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
        eprintln!();
        eprintln!(
            "Open {}/pair and enter this code:",
            req.origin.trim_end_matches('/')
        );
        eprintln!("  {}", pairing::display_code(&auth.nameplate, &secret));
        eprintln!();
        eprintln!("Waiting for you to approve in the browser…");
        Some(session)
    };
    let own_msg = session
        .as_ref()
        .map(|s| s.msg().to_vec())
        .unwrap_or_default();
    let mut k_owner: Option<zeroize::Zeroizing<[u8; 32]>> = None;
    let id_pub = req.signer.public_bytes();
    let sc_pk: &[u8] = req.sc_pk.as_ref().map(|k| &k[..]).unwrap_or(&[]);

    let interval = auth.interval.unwrap_or(5).clamp(1, 30);
    // A dropped connection while the person reads the page is not a failed pairing:
    // keep polling through about a minute of consecutive network errors (the code's
    // own expiry still ends it with 410).
    let max_net_errors = (60 / interval).max(3);
    let mut net_errors = 0u64;
    let dead = |why: &str| {
        format!(
            "{} This code can't be used again: run `{}` for a new one.",
            why, req.restart
        )
    };
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let presp = match client
            .post(format!("{}/api/pair/poll", cloud))
            .json(&json!({ "device_code": auth.device_code, "pop": pop }))
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
                "the pairing code expired before it was approved; run `{}` again.",
                req.restart
            ));
        }
        let text = presp.text().await.unwrap_or_default();
        if !status.is_success() {
            if text.contains("pair_code_mismatch") {
                return Err(dead("The code entered in the browser did not match."));
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
                let sub = pairing::subkeys(&k);
                let mac = pairing::keys_mac(
                    &sub.k_keys[..],
                    req.principal,
                    req.principal_id,
                    &id_pub,
                    sc_pk,
                );
                // Store-once on the server (the same keys_mac again is a no-op), so a
                // send that failed on the wire is safe to repeat.
                let body = json!({
                    "device_code": auth.device_code,
                    "pop": pop,
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
            "failed" => return Err(dead("The code entered in the browser did not match.")),
            "approved" => {
                let k_owner = k_owner.ok_or_else(|| {
                    dead("The server reported an approval without the code exchange.")
                })?;
                return verify_approval(poll, &k_owner[..], req, sc_pk).map_err(|e| dead(&e));
            }
            other => return Err(format!("unexpected pairing status '{}'", other)),
        }
    }
}

/// Step 5: the approving owner is authenticated by `owner_mac` (only the
/// browser that held the code could compute it) and must have signed the admit
/// of THIS principal's own keys.
fn verify_approval(
    body: Value,
    k_owner: &[u8],
    req: &PairRequest<'_>,
    sc_pk: &[u8],
) -> Result<Paired, String> {
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
    let admit = body
        .get("admit")
        .ok_or("The approval carries no owner-signed admit.")?;
    let owner =
        crate::principal_ledger::verify_pairing_admit(admit, &uik_pub, req.principal_id, sc_pk)?;
    debug_assert_eq!(owner, uik_id);
    Ok(Paired {
        body,
        uik_id,
        uik_pub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The approval checks: the owner proof and the admit over our own keys.
    #[test]
    fn approval_needs_owner_mac_and_our_admit() {
        let owner = SigningIdentity::from_seed(&[7u8; 32]);
        let acct = owner.user_id();
        let dik = SigningIdentity::from_seed(&[8u8; 32]);
        let dev = dik.id(crate::identity::IdKind::Device);
        let pk = [5u8; 32];
        let req = PairRequest {
            principal: "device",
            name: "box",
            principal_id: &dev,
            signer: &dik,
            sc_pk: Some(pk),
            cloud: "https://x",
            origin: "https://app.x",
            restart: "sc login",
        };
        let k_owner = [3u8; 32];
        let input = crate::identity::principal_event_input(&acct, "admit", &dev, 2, &acct, &pk);
        let body = |mac: [u8; 32], sc: &[u8]| {
            json!({
                "status": "approved",
                "account_uik_id": acct,
                "account_uik_pub": URL_SAFE_NO_PAD.encode(owner.public_bytes()),
                "owner_mac": URL_SAFE_NO_PAD.encode(mac),
                "admit": {
                    "seq": 2, "op": "admit", "principal_id": dev, "anchor_uik": acct,
                    "owner_id": acct, "sc_pk": URL_SAFE_NO_PAD.encode(sc),
                    "sig": STANDARD.encode(owner.sign(&input)),
                },
            })
        };
        let good = pairing::owner_mac(&k_owner, &acct, &owner.public_bytes());
        let p = verify_approval(body(good, &pk), &k_owner, &req, &pk).unwrap();
        assert_eq!(p.uik_id, acct);
        assert!(
            verify_approval(body([0u8; 32], &pk), &k_owner, &req, &pk).is_err(),
            "owner_mac"
        );
        assert!(
            verify_approval(body(good, &[6u8; 32]), &k_owner, &req, &pk).is_err(),
            "sc_pk"
        );
        let mut b = body(good, &pk);
        b["account_uik_id"] = json!("us_someoneelse");
        assert!(verify_approval(b, &k_owner, &req, &pk).is_err(), "label");
    }
}
