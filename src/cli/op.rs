//! `sc op wait` — block until a pending approval op resolves, then exit.
//!
//! The waiter half of the captive-portal contract (CREDENTIAL_BROKER.md §14):
//! a brokered request that needs a passkey fails with an `op_id` + approve
//! link. The agent surfaces the link, backgrounds `sc op wait <op_id>`, and
//! treats the process exit as its wake-up — then re-runs the original
//! command (the approval is cached; the retry consumes it). Polling `/op/{id}`
//! never consumes anything, so waiting and retrying can't race each other.
//!
//! Exit codes are the contract: 0 approved, 2 rejected, 3 expired/unknown,
//! 4 timed out waiting, 1 local failure. Stdout gets the final poll body
//! (JSON); progress prose goes to stderr.

use std::time::{Duration, Instant};

use reqwest::header::RETRY_AFTER;
use serde_json::Value;

use crate::cli::active::{control_root, grant_url, load};
use crate::config::{OpWaitArgs, CONTROL_PORT};

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

/// Poll cadence: honor the server's `Retry-After` hint when it's sane,
/// else the fixed default (matches `cli::approve`'s remote arm).
fn next_delay(retry_after: Option<&str>) -> Duration {
    retry_after
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|s| (1..=30).contains(s))
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
}

pub async fn run_wait(args: OpWaitArgs) -> Result<(), String> {
    let root = match load() {
        Ok(cfg) => control_root(&cfg),
        Err(_) => format!("http://127.0.0.1:{}", CONTROL_PORT),
    };
    let poll_url = format!(
        "{}/op/{}",
        root.trim_end_matches('/'),
        urlencoding::encode(&args.op_id)
    );

    // Re-print the approve link when it's absolute (cloud-paired). A
    // local-only daemon's grant_url is relative — useless as prose; the
    // captive-portal body already carried whatever link there is.
    let link = grant_url(&args.op_id);
    if link.starts_with("http") {
        eprintln!("Approve with your passkey: {}", link);
    }
    eprintln!("Waiting for approval {}…", args.op_id);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let mut error_streak: u32 = 0;
    let mut delay = DEFAULT_POLL_INTERVAL;

    // Poll first, sleep after — the tap may already have landed before the
    // waiter started, and the first answer should be instant.
    loop {
        match client.get(&poll_url).send().await {
            Err(_) => {
                error_streak += 1;
                if error_streak >= ERROR_STREAK_LIMIT {
                    return Err(format!(
                        "daemon unreachable at {} — the op survives; re-run `sc op wait {}` once it's back",
                        root, args.op_id
                    ));
                }
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                eprintln!("expired or unknown — re-run the original command to mint a fresh approval");
                std::process::exit(3);
            }
            Ok(resp) => {
                error_streak = 0;
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                delay = next_delay(retry_after.as_deref());
                if let Ok(body) = resp.json::<Value>().await {
                    let status = body.get("status").and_then(|s| s.as_str()).unwrap_or("");
                    match verdict(status) {
                        Verdict::Approved => {
                            println!("{}", body);
                            eprintln!("approved ✓ — re-run the original command");
                            std::process::exit(0);
                        }
                        Verdict::Rejected => {
                            println!("{}", body);
                            eprintln!("rejected ✗ — do not retry");
                            std::process::exit(2);
                        }
                        Verdict::Pending => {}
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            eprintln!(
                "timed out after {}s — if the op is still pending, `sc op wait {}` re-attaches",
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
