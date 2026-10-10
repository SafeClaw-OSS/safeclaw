//! The new side of admit-by-code (trust-reset design D2, contract 1.2 / 5 / 8.1):
//! shared by `sc login` (kind `device`) and `sc agent add` (kind `agent`).
//!
//! 1. The caller generated its keys; here we mint the secret code `s` (80 bits),
//!    derive `lookup`/`commit`, and `POST {backend}/admit`. `s` is never sent.
//! 2. We print the console page (`{console}/admit`, WITHOUT the code) and the
//!    code itself; the human types the code there and approves with a passkey.
//! 3. We poll `GET {backend}/admit/{lookup}/status`. An approved result is
//!    trusted only if its `mac` verifies under OUR code and its effect covers OUR
//!    keys ([`verify_admission_result`]). A backend that doesn't know `s` can
//!    neither re-home the admission nor swap a key in it.

use std::io::IsTerminal;
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use serde_json::{json, Value};

use crate::crypto::admission::{
    admit_commit, verify_admission_result, AdmissionFields, AdmitCode, AdmitKind,
};

/// Where a pairing goes: the backend (API) and the console (approval pages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub backend: String,
    pub console: String,
}

/// Resolve the target. Precedence:
///   1. `SAFECLAW_CLOUD_URL` — the BACKEND base URL (self-host escape hatch);
///      the console is derived by dropping a leading `api.` label;
///   2. `--profile {prod,dev}` — a SYMBOL resolved against a compiled-in
///      allowlist (a hostile install prompt can at worst flip between your own
///      prod/dev, never to a third party);
///   3. `SAFECLAW_BAKED_CLOUD_URL` — compile-time self-host bake (backend URL);
///   4. prod.
pub fn resolve_target(profile: Option<&str>) -> Result<Target, String> {
    let from_backend = |b: &str| {
        let backend = b.trim_end_matches('/').to_string();
        Target {
            console: crate::cli::active::derive_frontend_from_backend(&backend),
            backend,
        }
    };
    if let Ok(u) = std::env::var("SAFECLAW_CLOUD_URL") {
        if !u.is_empty() {
            return Ok(from_backend(&u));
        }
    }
    if let Some(p) = profile {
        return profile_target(p);
    }
    if let Some(u) = option_env!("SAFECLAW_BAKED_CLOUD_URL") {
        if !u.is_empty() {
            return Ok(from_backend(u));
        }
    }
    profile_target("prod")
}

/// The `--profile` allowlist: a symbol → first-party URLs only.
pub fn profile_target(profile: &str) -> Result<Target, String> {
    match profile {
        "prod" => Ok(Target {
            backend: "https://api.safeclaw.pro".into(),
            console: "https://safeclaw.pro".into(),
        }),
        "dev" => Ok(Target {
            backend: "https://api.dev.safeclaw.pro".into(),
            console: "https://dev.safeclaw.pro".into(),
        }),
        other => Err(format!(
            "unknown --profile '{}': expected 'prod' or 'dev'",
            other
        )),
    }
}

/// HTTPS is required for the server, except on-host loopback or `--insecure`.
pub fn require_https(url: &str, insecure: bool) -> Result<(), String> {
    if insecure || url.starts_with("https://") || is_localhost_http(url) {
        return Ok(());
    }
    Err(format!(
        "the SafeClaw server URL must use HTTPS ({} is plaintext); pass --insecure to override \
         (test-only)",
        url
    ))
}

/// `http://localhost[:PORT]` / `http://127.0.0.1[:PORT]` (the traffic never
/// leaves the host). `0.0.0.0`, `[::1]` and RFC1918 addresses are NOT exempt.
fn is_localhost_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1"
}

/// The `POST /admit` body (contract 8.1). `enc_pub` and `extra` are omitted
/// when empty (agent).
pub fn admit_body(fields: &AdmissionFields, code: &AdmitCode) -> Value {
    let keys = code.keys();
    let commit = admit_commit(&keys.commit_key, fields);
    let mut body = json!({
        "kind": fields.kind.as_str(),
        "sig_pub": BASE64URL_NOPAD.encode(&fields.sig_pub),
        "label": fields.label,
        "lookup": keys.lookup,
        "commit": BASE64URL_NOPAD.encode(&commit),
    });
    if !fields.enc_pub.is_empty() {
        body["enc_pub"] = json!(BASE64URL_NOPAD.encode(&fields.enc_pub));
    }
    if !fields.extra.is_empty() {
        body["extra"] = json!(BASE64URL_NOPAD.encode(&fields.extra));
    }
    body
}

/// A verified approval: who approved it (mac'd under our code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    pub us: String,
    pub uik_sign_pub: [u8; 32],
    pub email: String,
}

/// The outcome of one status read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Pending,
    Expired,
    Approved(Approved),
}

/// Interpret a `GET /admit/{lookup}/status` body: an `approved` result must
/// verify under OUR code and cover OUR keys, else it is refused (never pinned).
pub fn read_status(
    body: &Value,
    code: &AdmitCode,
    fields: &AdmissionFields,
) -> Result<Status, String> {
    match body.get("status").and_then(|v| v.as_str()) {
        Some("pending") => return Ok(Status::Pending),
        Some("expired") => return Ok(Status::Expired),
        Some("approved") => {}
        other => return Err(format!("unexpected admission status {:?}", other)),
    }
    let b = |k: &str| -> Result<Vec<u8>, String> {
        body.get(k)
            .and_then(|v| v.as_str())
            .and_then(|s| BASE64URL_NOPAD.decode(s.as_bytes()).ok())
            .ok_or_else(|| format!("approved admission is missing a valid `{}`", k))
    };
    let s = |k: &str| -> Result<String, String> {
        body.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("approved admission is missing `{}`", k))
    };
    let effect = b("effect")?;
    let mac = b("mac")?;
    let uik_sign_pub: [u8; 32] = b("uik_sign_pub")?
        .try_into()
        .map_err(|_| "approved admission carries a malformed uik_sign_pub".to_string())?;
    let us = s("us")?;
    let email = s("email")?;
    if !verify_admission_result(code, fields, &effect, &uik_sign_pub, &us, &email, &mac) {
        return Err(
            "the approval does not verify against the code shown here: it was not made for \
             this request (or was tampered with). Nothing was saved."
                .to_string(),
        );
    }
    Ok(Status::Approved(Approved {
        us,
        uik_sign_pub,
        email,
    }))
}

/// TTL of a pending admission (contract 1.2) plus slack for the last poll.
const WAIT: Duration = Duration::from_secs(11 * 60);
const POLL: Duration = Duration::from_secs(3);

/// Post the admission, show the human where to approve and the code, and wait
/// for a verified approval. `what` names the thing being admitted ("this
/// machine", "the agent 'x'").
pub async fn post_and_wait(
    target: &Target,
    fields: &AdmissionFields,
    code: &AdmitCode,
    what: &str,
) -> Result<Approved, String> {
    let client = crate::cli::egress_proxy::client(Duration::from_secs(15))
        .map_err(|e| format!("http client init: {}", e))?;
    let body = admit_body(fields, code);
    let resp = client
        .post(format!("{}/admit", target.backend))
        .header(crate::cloud::HDR_VERSION, env!("CARGO_PKG_VERSION"))
        .json(&body)
        .send()
        .await
        .map_err(|e| crate::cli::neterr::reach_failed(&target.backend, &e))?;
    if !resp.status().is_success() {
        return Err(crate::cloud::error_text(resp, "could not start the admission").await);
    }
    let lookup = code.keys().lookup;

    eprintln!();
    eprintln!("To approve {}, open:", what);
    eprintln!("  {}/admit", target.console);
    eprintln!("and enter this code:");
    eprintln!();
    eprintln!("    {}", code.display());
    eprintln!();
    eprintln!("The code is shown only here. Type it only into the SafeClaw console;");
    eprintln!("never share it. It expires in 10 minutes.");
    eprintln!();
    eprintln!("Waiting for approval…");

    let started = tokio::time::Instant::now();
    let status_url = format!("{}/admit/{}/status", target.backend, lookup);
    loop {
        if started.elapsed() > WAIT {
            return Err("the code expired before it was approved; run the command again".into());
        }
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            _ = tokio::signal::ctrl_c() => return Err("interrupted".into()),
        }
        let resp = match client
            .get(&status_url)
            .header(crate::cloud::HDR_VERSION, env!("CARGO_PKG_VERSION"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue, // transient; keep polling
        };
        match resp.status().as_u16() {
            200 => {}
            404 | 410 => {
                return Err("the code expired before it was approved; run the command again".into())
            }
            _ => return Err(crate::cloud::error_text(resp, "admission status").await),
        }
        let body: Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        match read_status(&body, code, fields)? {
            Status::Pending => continue,
            Status::Expired => {
                return Err("the code expired before it was approved; run the command again".into())
            }
            Status::Approved(a) => return Ok(a),
        }
    }
}

/// Can the confirmation be answered? `--yes` answers it; otherwise stdin must
/// be a terminal. Checked BEFORE any key is minted or `/admit` is posted, so a
/// run with no way to confirm (an agent's shell) fails at once and leaves
/// nothing behind: no keys on disk, no pending admission in the console.
pub fn check_confirmable(command: &str, assume_yes: bool, interactive: bool) -> Result<(), String> {
    if assume_yes || interactive {
        return Ok(());
    }
    Err(format!(
        "`{}` asks you to confirm the account, and this is not a terminal. Run it in a \
         terminal, or re-run with --yes (the approval is still verified against the code, \
         and the account it pairs to is printed).",
        command
    ))
}

/// [`check_confirmable`] against this process's stdin.
pub fn require_confirmable(command: &str, assume_yes: bool) -> Result<(), String> {
    check_confirmable(command, assume_yes, std::io::stdin().is_terminal())
}

/// Ask `question [y/N]` on the terminal. `assume_yes` answers yes. The caller
/// ran [`require_confirmable`] first; a non-terminal stdin here is still a
/// refusal, never a silent yes.
pub fn confirm(question: &str, assume_yes: bool) -> Result<bool, String> {
    if assume_yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "{} — not a terminal; re-run with --yes to confirm",
            question
        ));
    }
    eprint!("{} [y/N] ", question);
    use std::io::Write as _;
    let _ = std::io::stderr().flush();
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(matches!(buf.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

/// The warning shown when an approval's person differs from the one this
/// machine was paired to before (design D2: "warns if us_ differs").
pub fn person_change_warning(previous: Option<&str>, now: &str) -> Option<String> {
    let prev = previous.filter(|p| !p.is_empty())?;
    (prev != now).then(|| {
        format!(
            "WARNING: this machine was previously paired to a DIFFERENT SafeClaw account ({}). \
             Continue only if you meant to switch accounts.",
            prev
        )
    })
}

/// The admission fields for a device pair.
pub fn device_fields(dik_pub: [u8; 32], enc_pub: [u8; 32], label: &str) -> AdmissionFields {
    AdmissionFields {
        kind: AdmitKind::Device,
        sig_pub: dik_pub.to_vec(),
        enc_pub: enc_pub.to_vec(),
        label: label.to_string(),
        extra: Vec::new(),
    }
}

/// The admission fields for an agent (AIK).
pub fn agent_fields(aik_pub: [u8; 32], label: &str) -> AdmissionFields {
    AdmissionFields {
        kind: AdmitKind::Agent,
        sig_pub: aik_pub.to_vec(),
        enc_pub: Vec::new(),
        label: label.to_string(),
        extra: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::admission::admit_mac;
    use crate::crypto::ledger::LedgerEventFields;
    use crate::identity::{IdKind, SigningIdentity};

    #[test]
    fn profile_allowlist_maps_first_party_only() {
        assert_eq!(
            profile_target("prod").unwrap(),
            Target {
                backend: "https://api.safeclaw.pro".into(),
                console: "https://safeclaw.pro".into()
            }
        );
        assert_eq!(
            profile_target("dev").unwrap().backend,
            "https://api.dev.safeclaw.pro"
        );
        assert!(profile_target("https://attacker.com").is_err());
        assert!(profile_target("staging").is_err());
        assert!(profile_target("").is_err());
    }

    #[test]
    fn https_gate() {
        assert!(require_https("https://api.safeclaw.pro", false).is_ok());
        assert!(require_https("http://localhost:8787", false).is_ok());
        assert!(require_https("http://127.0.0.1/x", false).is_ok());
        assert!(require_https("http://evil.example", false).is_err());
        assert!(require_https("http://0.0.0.0:1", false).is_err());
        assert!(require_https("http://evil.example", true).is_ok());
    }

    /// The posted body never carries the code; it carries exactly the
    /// committed fields, the hex lookup and the commit.
    #[test]
    fn admit_body_carries_no_code() {
        let code = AdmitCode::from_bytes([3u8; 10]);
        let f = device_fields([1; 32], [2; 32], "laptop");
        let body = admit_body(&f, &code);
        let text = body.to_string();
        assert!(!text.contains(&code.display()));
        assert!(!text.contains(&code.display().replace('-', "")));
        assert_eq!(body["kind"], "device");
        assert_eq!(body["lookup"].as_str().unwrap().len(), 32);
        assert!(body.get("extra").is_none());
        let agent = admit_body(&agent_fields([1; 32], "bot"), &code);
        assert!(agent.get("enc_pub").is_none() && agent.get("extra").is_none());
        let commit = BASE64URL_NOPAD
            .decode(agent["commit"].as_str().unwrap().as_bytes())
            .unwrap();
        assert_eq!(commit.len(), 32);
    }

    /// An approved status is accepted only if it is mac'd under OUR code and the
    /// effect is the ledger admit of OUR keys; anything else is refused.
    #[test]
    fn approved_status_verifies_mac_and_effect_coverage() {
        let code = AdmitCode::from_bytes([7u8; 10]);
        let dik = SigningIdentity::from_seed(&[4; 32]);
        let enc = [5u8; 32];
        let f = device_fields(dik.public_bytes(), enc, "laptop");
        let uik = SigningIdentity::from_seed(&[6; 32]);
        let us = uik.user_id();
        let effect = LedgerEventFields {
            us: us.clone(),
            op: "admit".into(),
            kind: "device".into(),
            principal: dik.id(IdKind::Device),
            sig_pub: dik.public_bytes().to_vec(),
            enc_pub: enc.to_vec(),
            label: "renamed by approver".into(),
            seq: 3,
        }
        .signing_input();
        let mac = admit_mac(
            &code.keys().mac_key,
            &effect,
            &uik.public_bytes(),
            &us,
            "a@b.c",
        );
        let body = |effect: &[u8], mac: &[u8], us: &str| {
            json!({
                "status": "approved",
                "effect": BASE64URL_NOPAD.encode(effect),
                "mac": BASE64URL_NOPAD.encode(mac),
                "uik_sign_pub": BASE64URL_NOPAD.encode(&uik.public_bytes()),
                "us": us,
                "email": "a@b.c",
            })
        };
        match read_status(&body(&effect, &mac, &us), &code, &f).unwrap() {
            Status::Approved(a) => {
                assert_eq!(a.us, us);
                assert_eq!(a.email, "a@b.c");
                assert_eq!(a.uik_sign_pub, uik.public_bytes());
            }
            other => panic!("{other:?}"),
        }
        // Another code's mac: refused.
        let other = AdmitCode::from_bytes([8u8; 10]);
        let bad_mac = admit_mac(
            &other.keys().mac_key,
            &effect,
            &uik.public_bytes(),
            &us,
            "a@b.c",
        );
        assert!(read_status(&body(&effect, &bad_mac, &us), &code, &f).is_err());
        // An effect admitting ANOTHER enc key, correctly mac'd: refused (coverage).
        let swapped = LedgerEventFields::parse_signing_input(&effect)
            .map(|mut e| {
                e.enc_pub = vec![9; 32];
                e.signing_input()
            })
            .unwrap();
        let mac2 = admit_mac(
            &code.keys().mac_key,
            &swapped,
            &uik.public_bytes(),
            &us,
            "a@b.c",
        );
        assert!(read_status(&body(&swapped, &mac2, &us), &code, &f).is_err());
        // A `us` that doesn't fold from the served key: refused.
        let mac3 = admit_mac(
            &code.keys().mac_key,
            &effect,
            &uik.public_bytes(),
            "us_x",
            "a@b.c",
        );
        assert!(read_status(&body(&effect, &mac3, "us_x"), &code, &f).is_err());
        // Pending / expired / junk.
        assert_eq!(
            read_status(&json!({"status": "pending"}), &code, &f).unwrap(),
            Status::Pending
        );
        assert_eq!(
            read_status(&json!({"status": "expired"}), &code, &f).unwrap(),
            Status::Expired
        );
        assert!(read_status(&json!({"status": "approved"}), &code, &f).is_err());
        assert!(read_status(&json!({}), &code, &f).is_err());
    }

    /// No terminal and no --yes: refused up front (before keys or /admit);
    /// either one lets the command proceed.
    #[test]
    fn confirmation_must_be_answerable_before_anything_is_minted() {
        let e = check_confirmable("sc login", false, false).unwrap_err();
        assert!(e.contains("--yes") && e.contains("sc login"), "{e}");
        assert!(check_confirmable("sc login", true, false).is_ok());
        assert!(check_confirmable("sc agent add", false, true).is_ok());
    }

    #[test]
    fn person_change_is_warned() {
        assert!(person_change_warning(None, "us_a").is_none());
        assert!(person_change_warning(Some("us_a"), "us_a").is_none());
        assert!(person_change_warning(Some("us_a"), "us_b")
            .unwrap()
            .contains("us_a"));
    }

    /// The new side end to end against a fake backend: the posted row carries
    /// the commit of OUR fields (never the code), the status is read at OUR
    /// lookup, and an approval mac'd under our code is accepted.
    #[tokio::test]
    async fn post_and_wait_admits_against_a_backend() {
        use axum::{
            extract::{Path, State},
            http::StatusCode,
            routing::{get, post},
            Json, Router,
        };
        use std::sync::{Arc, Mutex};

        let code = AdmitCode::from_bytes([0x2a; 10]);
        let dik = SigningIdentity::from_seed(&[0x2b; 32]);
        let enc = [0x2c; 32];
        let fields = device_fields(dik.public_bytes(), enc, "laptop");
        let uik = SigningIdentity::from_seed(&[0x2d; 32]);
        let us = uik.user_id();
        let effect = LedgerEventFields {
            us: us.clone(),
            op: "admit".into(),
            kind: "device".into(),
            principal: dik.id(IdKind::Device),
            sig_pub: dik.public_bytes().to_vec(),
            enc_pub: enc.to_vec(),
            label: "laptop".into(),
            seq: 1,
        }
        .signing_input();
        let mac = admit_mac(
            &code.keys().mac_key,
            &effect,
            &uik.public_bytes(),
            &us,
            "a@b.c",
        );
        let approved = json!({
            "status": "approved",
            "effect": BASE64URL_NOPAD.encode(&effect),
            "mac": BASE64URL_NOPAD.encode(&mac),
            "uik_sign_pub": BASE64URL_NOPAD.encode(&uik.public_bytes()),
            "us": us,
            "email": "a@b.c",
        });

        type Posted = Arc<Mutex<Option<Value>>>;
        let posted: Posted = Arc::default();
        let app = Router::new()
            .route(
                "/admit",
                post(|State(p): State<Posted>, Json(b): Json<Value>| async move {
                    *p.lock().unwrap() = Some(b);
                    (StatusCode::CREATED, Json(json!({"expires_at": 0})))
                }),
            )
            .route(
                "/admit/{lookup}/status",
                get(move |State(p): State<Posted>, Path(lookup): Path<String>| {
                    let approved = approved.clone();
                    async move {
                        let row = p.lock().unwrap().clone().unwrap_or_default();
                        if row["lookup"] != lookup {
                            return (StatusCode::NOT_FOUND, Json(json!({})));
                        }
                        (StatusCode::OK, Json(approved))
                    }
                }),
            )
            .with_state(posted.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let target = Target {
            backend: base.clone(),
            console: base,
        };
        let got = post_and_wait(&target, &fields, &code, "this machine")
            .await
            .unwrap();
        assert_eq!(got.us, us);
        assert_eq!(got.email, "a@b.c");

        let row = posted.lock().unwrap().clone().unwrap();
        assert_eq!(row, admit_body(&fields, &code));
        let text = row.to_string();
        assert!(!text.contains(&code.display().replace('-', "")));
    }
}
