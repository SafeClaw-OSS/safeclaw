//! `sc op wait` — block until a pending approval op resolves, then exit.
//!
//! The waiter half of the captive-portal contract (CREDENTIAL_BROKER.md §14):
//! a brokered request that needs a passkey fails with an `op_id` + approve
//! link. The agent surfaces the link, backgrounds `sc op wait <op_id>`, and
//! treats the process exit as its wake-up — then re-runs the original
//! command (the approval is cached; the retry consumes it). Polling `/op/{id}`
//! never consumes anything, so waiting and retrying can't race each other.
//!
//! Exit codes are the contract: 0 approved, 5 not approved (a person said no,
//! or a stated cause), 6 ended without a decision (withdrawn by the requester
//! or superseded by a newer request), 3 expired/unknown, 4 timed out waiting,
//! 1 local failure. 2 is clap's usage-error code — a malformed invocation must
//! stay distinguishable from a human rejection.
//! Progress and the outcome are one line each on stderr; `--json` puts the final
//! poll body on stdout.

use std::time::{Duration, Instant};

use reqwest::header::RETRY_AFTER;
use serde_json::Value;

use crate::cli::active::{control_root, load};
use crate::config::OpWaitArgs;

/// Give up after this many CONSECUTIVE transport failures (~30s dark with the
/// 2s cadence + 15s client timeout) — a dead daemon must not strand a
/// background waiter forever; the op survives, so a fresh wait can re-attach.
const ERROR_STREAK_LIMIT: u32 = 10;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

enum Verdict {
    Approved,
    Rejected,
    Pending,
}

/// How an op that ended as `rejected` ended, from its `reason`: a person's
/// no, a withdrawal by the requester, a newer request replacing it, or
/// another stated cause (e.g. approved, but applying it failed).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NotApproved<'a> {
    Rejected,
    Withdrawn,
    Superseded,
    Other(&'a str),
}

pub(crate) fn not_approved(reason: &str) -> NotApproved<'_> {
    use crate::server::handlers::op::{ABANDONED_REASON, WITHDRAWN_REASON};
    match reason {
        // "user denied" = the same human no from an older daemon.
        "" | "user rejected" | "user denied" => NotApproved::Rejected,
        r if r == WITHDRAWN_REASON || r == ABANDONED_REASON => NotApproved::Withdrawn,
        r if r.contains("superseded") => NotApproved::Superseded,
        r => NotApproved::Other(r),
    }
}

/// Wire-status → outcome. `consumed` counts as approved: the gesture landed
/// and something already took the value — for the re-run ceremony that's
/// success, same as `cli::approve` treats it.
fn verdict(status: &str) -> Verdict {
    match status {
        "ok" | "consumed" => Verdict::Approved,
        "rejected" => Verdict::Rejected,
        _ => Verdict::Pending,
    }
}

fn not_answering(root: &str, op_id: &str) -> String {
    format!(
        "daemon not answering at {}. The approval survives; once it is back, re-run: sc op wait {}",
        root, op_id
    )
}

/// Poll cadence: honor the server's `Retry-After` hint when it's sane,
/// else the fixed default (matches `cli::approve`'s remote arm).
fn next_delay(retry_after: Option<&str>) -> Duration {
    retry_after
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|s| (1..=30).contains(s))
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
}

pub async fn run_wait(args: OpWaitArgs, json: bool) -> Result<(), String> {
    // Corrupt config degrades to defaults, NOT a hardcoded localhost that
    // would ignore an agent's $SAFECLAW_BROKER_URL (same rule as custodian.rs).
    let root = control_root(&load().unwrap_or_default());
    let poll_url = format!(
        "{}/op/{}",
        root.trim_end_matches('/'),
        urlencoding::encode(&args.op_id)
    );

    // The command that minted the op already printed its link.
    eprintln!("Waiting for approval in the browser.");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    // Clamp to a year — a u64::MAX timeout would overflow Instant + Duration.
    let deadline = Instant::now() + Duration::from_secs(args.timeout.min(31_536_000));
    let mut error_streak: u32 = 0;
    let mut delay = DEFAULT_POLL_INTERVAL;

    // Poll first, sleep after — the tap may already have landed before the
    // waiter started, and the first answer should be instant.
    loop {
        match client.get(&poll_url).send().await {
            Err(_) => {
                error_streak += 1;
                if error_streak >= ERROR_STREAK_LIMIT {
                    return Err(not_answering(&root, &args.op_id));
                }
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                eprintln!("Expired or unknown. Re-run the original command for a new approval.");
                std::process::exit(3);
            }
            Ok(resp) => {
                let http_ok = resp.status().is_success();
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                delay = next_delay(retry_after.as_deref());
                match resp.json::<Value>().await {
                    Ok(body) if http_ok => {
                        error_streak = 0;
                        let status = body.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        match verdict(status) {
                            Verdict::Approved => {
                                if json {
                                    println!("{}", body);
                                }
                                eprintln!("Approved. Re-run the original command.");
                                std::process::exit(0);
                            }
                            Verdict::Rejected => {
                                if json {
                                    println!("{}", body);
                                }
                                let reason =
                                    body.get("reason").and_then(|s| s.as_str()).unwrap_or("");
                                match not_approved(reason) {
                                    NotApproved::Superseded => {
                                        eprintln!(
                                            "Superseded by a newer approval request. \
                                             Re-run the original command."
                                        );
                                        std::process::exit(6);
                                    }
                                    NotApproved::Withdrawn => {
                                        eprintln!(
                                            "Withdrawn by the requester, not rejected. \
                                             Re-run the original command to ask again."
                                        );
                                        std::process::exit(6);
                                    }
                                    // Not a person saying no (e.g. "approved, but
                                    // applying it failed: …"): retrying after the
                                    // cause is fixed is legitimate.
                                    NotApproved::Other(r) => {
                                        eprintln!("Not approved: {}. Fix the cause, then re-run.", r);
                                    }
                                    NotApproved::Rejected => {
                                        eprintln!("Rejected by the approver. Do not retry.");
                                    }
                                }
                                std::process::exit(5);
                            }
                            Verdict::Pending => {}
                        }
                    }
                    // 5xx / auth walls / non-JSON: a server that isn't
                    // answering the contract counts toward the bail streak —
                    // never spin silently to the deadline.
                    _ => {
                        error_streak += 1;
                        if error_streak >= ERROR_STREAK_LIMIT {
                            return Err(not_answering(&root, &args.op_id));
                        }
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            eprintln!(
                "Timed out after {}s. If it is still pending, re-attach with: sc op wait {}",
                args.timeout, args.op_id
            );
            std::process::exit(4);
        }
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_withdrawal_or_a_newer_request_is_not_a_rejection() {
        use crate::server::handlers::op::{ABANDONED_REASON, WITHDRAWN_REASON};
        assert_eq!(not_approved(""), NotApproved::Rejected);
        assert_eq!(not_approved("user rejected"), NotApproved::Rejected);
        assert_eq!(not_approved("user denied"), NotApproved::Rejected);
        assert_eq!(not_approved(WITHDRAWN_REASON), NotApproved::Withdrawn);
        assert_eq!(not_approved(ABANDONED_REASON), NotApproved::Withdrawn);
        assert_eq!(not_approved("superseded by a newer request"), NotApproved::Superseded);
        assert_eq!(
            not_approved("approved, but applying it failed: x"),
            NotApproved::Other("approved, but applying it failed: x")
        );
    }

    #[test]
    fn verdict_maps_wire_statuses() {
        assert!(matches!(verdict("ok"), Verdict::Approved));
        assert!(matches!(verdict("consumed"), Verdict::Approved));
        assert!(matches!(verdict("rejected"), Verdict::Rejected));
        assert!(matches!(verdict("pending"), Verdict::Pending));
        assert!(matches!(verdict(""), Verdict::Pending));
    }

    #[test]
    fn next_delay_honors_sane_hints_only() {
        assert_eq!(next_delay(Some("3")), Duration::from_secs(3));
        assert_eq!(next_delay(Some(" 5 ")), Duration::from_secs(5));
        // Absent, unparseable, zero, or absurd hints fall back to the default.
        assert_eq!(next_delay(None), DEFAULT_POLL_INTERVAL);
        assert_eq!(next_delay(Some("soon")), DEFAULT_POLL_INTERVAL);
        assert_eq!(next_delay(Some("0")), DEFAULT_POLL_INTERVAL);
        assert_eq!(next_delay(Some("3600")), DEFAULT_POLL_INTERVAL);
    }
}
