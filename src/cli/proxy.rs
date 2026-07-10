//! `sc proxy set/show/clear` — manage the device's upstream EGRESS proxy.
//!
//! The daemon runs under launchd/systemd and does NOT inherit the operator's
//! shell `HTTPS_PROXY`, so behind a corporate or on-demand proxy its own egress
//! (OAuth code/refresh exchange, the resident proxy's forward hop, `sc upgrade`)
//! would hit the internet directly and time out. This stores the proxy at the
//! device level ([`egress_proxy`]) and bounces the daemon so it re-reads it at
//! startup — the standard "configure at the service, restart to apply" model.

use crate::cli::{egress_proxy, service, up};
use crate::config::ProxySubcommand;

pub async fn run(sub: ProxySubcommand) -> Result<(), String> {
    match sub {
        ProxySubcommand::Set { url } => set(url).await,
        ProxySubcommand::Show => show(),
        ProxySubcommand::Clear => clear().await,
    }
}

/// Accept a bare `host:port` as `http://host:port`; leave a full URL as-is.
fn normalize(url: &str) -> String {
    let u = url.trim();
    if u.contains("://") {
        u.to_string()
    } else {
        format!("http://{}", u)
    }
}

async fn set(url: String) -> Result<(), String> {
    let url = normalize(&url);
    if egress_proxy::load().as_deref() == Some(url.as_str()) {
        eprintln!("Egress proxy already set to {url} — nothing to do.");
        return Ok(());
    }
    egress_proxy::store(&url)?;
    eprintln!("Egress proxy set to {url}.");
    bounce_to_apply().await
}

async fn clear() -> Result<(), String> {
    if egress_proxy::load().is_none() {
        eprintln!("No egress proxy configured — nothing to clear.");
        return Ok(());
    }
    egress_proxy::clear()?;
    eprintln!("Egress proxy cleared — the daemon will reach the internet directly.");
    bounce_to_apply().await
}

fn show() -> Result<(), String> {
    match egress_proxy::load() {
        Some(url) => {
            println!("{url}");
            // A real shell HTTPS_PROXY overrides the stored value (env > config).
            // Note it so the effective route is never a surprise.
            if let Some(shell) = std::env::var_os("HTTPS_PROXY").filter(|v| !v.is_empty()) {
                let shell = shell.to_string_lossy();
                if shell != url {
                    eprintln!(
                        "note: your shell HTTPS_PROXY ({shell}) overrides this for `sc` \
                         itself; the daemon uses the value above."
                    );
                }
            }
            Ok(())
        }
        None => Err("no egress proxy configured (set one with `sc proxy set <url>`)".to_string()),
    }
}

/// Restart the daemon so it re-reads the egress proxy at startup, then converge
/// back to unlocked (one passkey tap) — same chokepoint as `sc restart`. When no
/// daemon unit is installed yet, the stored value will be picked up by the first
/// `sc up`.
async fn bounce_to_apply() -> Result<(), String> {
    if !service::unit_installed() {
        eprintln!("  (no daemon installed yet — it'll take effect on `sc up`.)");
        return Ok(());
    }
    eprintln!("  Restarting the daemon to apply (you'll re-unlock)…");
    up::restart().await
}
