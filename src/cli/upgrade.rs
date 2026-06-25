//! `sc upgrade` — built-in self-update.
//!
//! Mirrors `install.sh`: downloads the prebuilt binary for this platform from
//! the project's LATEST GitHub Release, verifies its sha256 against the
//! release's published `SHA256SUMS`, and atomically replaces the running
//! binary. This is the ONLY supported way to change which cloud the daemon
//! pairs with (the cloud URL is baked, not config) — a domain move ships as a
//! new release. See [[project_vault_agent_architecture_2026_06_25]].
//!
//! Version-scheme-agnostic: rather than parse tags, it compares the verified
//! download's hash to the running binary's hash and is a no-op when they match
//! ("already up to date"). `--force` rewrites anyway.

use std::time::Duration;

use crate::config::UpgradeArgs;

const BASE: &str = "https://github.com/SafeClaw-OSS/safeclaw/releases/latest/download";

/// Map the build target to the release asset name (matches install.sh + CI).
fn asset_name() -> Result<&'static str, String> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "safeclaw-linux-x86_64",
        ("linux", "aarch64") => "safeclaw-linux-aarch64",
        ("macos", "x86_64") => "safeclaw-macos-x86_64",
        ("macos", "aarch64") => "safeclaw-macos-aarch64",
        (os, arch) => return Err(format!("unsupported platform {}/{}", os, arch)),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().map(|b| format!("{:02x}", b)).collect()
}

/// Pull the expected hash for `asset` out of a `SHA256SUMS` file body
/// (`<hex>␠␠<name>` or `<hex>␠<name>` lines, as produced by sha256sum/shasum).
fn expected_hash(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let hex = parts.next()?;
        let name = parts.next()?;
        (name == asset).then(|| hex.to_string())
    })
}

pub async fn run(args: UpgradeArgs) -> Result<(), String> {
    let asset = asset_name()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("http client init: {}", e))?;

    // 1. Fetch the published checksums first — refuse to install anything we
    //    can't verify (unlike install.sh, which warns-and-continues; a
    //    self-replacing binary is higher-stakes, so we hard-fail).
    let sums_url = format!("{}/SHA256SUMS", BASE);
    let sums = client
        .get(&sums_url)
        .send()
        .await
        .map_err(|e| format!("fetch SHA256SUMS: {}", e))?;
    if !sums.status().is_success() {
        return Err(format!("fetch SHA256SUMS: HTTP {}", sums.status()));
    }
    let sums = sums.text().await.map_err(|e| format!("read SHA256SUMS: {}", e))?;
    let expected = expected_hash(&sums, asset)
        .ok_or_else(|| format!("no checksum for {} in the latest release", asset))?;

    // 2. Download the asset.
    let asset_url = format!("{}/{}", BASE, asset);
    eprintln!("Fetching {} (latest release)…", asset);
    let resp = client
        .get(&asset_url)
        .send()
        .await
        .map_err(|e| format!("download {}: {}", asset, e))?;
    if !resp.status().is_success() {
        return Err(format!("download {}: HTTP {}", asset, resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("read {}: {}", asset, e))?;

    // 3. Verify integrity before it touches disk.
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(format!(
            "checksum mismatch — refusing to install.\n  expected {}\n  got      {}",
            expected, actual
        ));
    }

    // 4. No-op when the verified download equals the running binary.
    let current = std::env::current_exe().map_err(|e| format!("locate current binary: {}", e))?;
    let current_hash = std::fs::read(&current).ok().map(|b| sha256_hex(&b));
    if current_hash.as_deref() == Some(actual.as_str()) && !args.force {
        eprintln!("Already up to date ({}).", &actual[..12]);
        return Ok(());
    }

    // 5. Atomically replace the running binary: write a sibling temp file (same
    //    dir ⇒ same filesystem ⇒ atomic rename), chmod +x, then rename over the
    //    current path. On Unix the running process keeps the old inode open, so
    //    replacing the path mid-run is safe; the next launch is the new build.
    let dir = current
        .parent()
        .ok_or_else(|| "current binary has no parent dir".to_string())?;
    let tmp = dir.join(format!(".sc-upgrade-{}.tmp", std::process::id()));
    std::fs::write(&tmp, &bytes).map_err(|e| {
        format!("write {} (need write access to {}): {}", tmp.display(), dir.display(), e)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("chmod {}: {}", tmp.display(), e));
        }
    }
    if let Err(e) = std::fs::rename(&tmp, &current) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "replace {}: {} — if it's in a system dir, re-run install.sh with the right permissions",
            current.display(),
            e
        ));
    }

    eprintln!("Upgraded {} ({}).", current.display(), &actual[..12]);
    // Take effect now: restart the running daemon onto the new binary so the
    // user isn't left on the old build. Best-effort — a foreground / non-systemd
    // daemon just keeps running until it's restarted by hand.
    if crate::cli::service::unit_installed() {
        if let Err(e) = crate::cli::service::run_restart() {
            eprintln!("  couldn't auto-restart the daemon ({e}); run `sc restart`.");
        }
    } else {
        eprintln!("  Start it with `sc up`.");
    }
    Ok(())
}
