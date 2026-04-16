//! Self-update: download latest safeclaw binary + templates from GitHub Releases.
//!
//! Usage:
//!   safeclaw update              — full update (binary + templates), restart required
//!   safeclaw update --check      — check for new version, print result, exit
//!   safeclaw update --templates  — update templates only (hot reload, no restart)

use std::fs;
use std::path::{Path, PathBuf};

const GITHUB_REPO: &str = "SafeClaw-OSS/safeclaw";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Resolved latest release info from GitHub.
struct ReleaseInfo {
    tag: String,
    version: String,
    binary_url: Option<String>,
    templates_url: Option<String>,
}

/// Entry point for `safeclaw update`.
pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let check_only = args.iter().any(|a| a == "--check");
    let templates_only = args.iter().any(|a| a == "--templates" || a == "--templates-only");

    eprintln!("[update] Current version: v{CURRENT_VERSION}");

    let release = fetch_latest_release()?;

    if check_only {
        if release.version == CURRENT_VERSION {
            eprintln!("[update] Already up to date (v{CURRENT_VERSION})");
        } else {
            eprintln!("[update] New version available: {} (current: v{CURRENT_VERSION})", release.tag);
        }
        return Ok(());
    }

    if release.version == CURRENT_VERSION && !templates_only {
        eprintln!("[update] Already up to date (v{CURRENT_VERSION})");
        eprintln!("[update] Use --templates to force-update templates anyway.");
        return Ok(());
    }

    // Determine install paths
    let binary_path = std::env::current_exe()?;
    let templates_dir = resolve_templates_dir();

    if templates_only {
        eprintln!("[update] Updating templates only...");
        update_templates(&release, &templates_dir)?;
        eprintln!("[update] ✅ Templates updated. Changes take effect immediately.");
        return Ok(());
    }

    // Full update: templates + binary
    eprintln!("[update] Upgrading to {}...", release.tag);
    update_templates(&release, &templates_dir)?;
    update_binary(&release, &binary_path)?;
    eprintln!("[update] ✅ Updated to {}. Restart safeclaw to apply.", release.tag);

    Ok(())
}

/// Resolve where templates should be written.
/// Always uses $SAFECLAW_DATA/templates/ (matches read_template() source).
fn resolve_templates_dir() -> PathBuf {
    if let Ok(data) = std::env::var("SAFECLAW_DATA") {
        return PathBuf::from(&data).join("templates");
    }
    // Fallback for bare-metal users without SAFECLAW_DATA set
    PathBuf::from("./data/templates")
}

/// Fetch latest release info from GitHub API.
fn fetch_latest_release() -> Result<ReleaseInfo, Box<dyn std::error::Error>> {
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let resp = ureq::get(&url)
        .set("User-Agent", &format!("safeclaw/{CURRENT_VERSION}"))
        .set("Accept", "application/vnd.github+json")
        .call()?;

    let body: serde_json::Value = resp.into_json()?;

    let tag = body["tag_name"]
        .as_str()
        .ok_or("Missing tag_name in release")?
        .to_string();
    let version = tag.strip_prefix('v').unwrap_or(&tag).to_string();

    // Find assets
    let assets = body["assets"].as_array();
    let mut binary_url = None;
    let mut templates_url = None;

    if let Some(assets) = assets {
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;
        // Binary: safeclaw-{os}-{arch} or safeclaw-{os}-{arch}.tar.gz
        let binary_pattern = format!("safeclaw-{os}-{arch}");
        let templates_pattern = "templates.tar.gz";

        for asset in assets {
            let name = asset["name"].as_str().unwrap_or("");
            let dl = asset["browser_download_url"].as_str().unwrap_or("");
            if name.starts_with(&binary_pattern) && !name.contains("templates") {
                binary_url = Some(dl.to_string());
            }
            if name == templates_pattern || name.ends_with("templates.tar.gz") {
                templates_url = Some(dl.to_string());
            }
        }
    }

    Ok(ReleaseInfo { tag, version, binary_url, templates_url })
}

/// Download and extract templates.
fn update_templates(
    release: &ReleaseInfo,
    templates_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = release
        .templates_url
        .as_deref()
        .ok_or("No templates asset found in release. Upload templates.tar.gz to the GitHub release.")?;

    eprintln!("[update] Downloading templates from {}...", release.tag);

    let resp = ureq::get(url)
        .set("User-Agent", &format!("safeclaw/{CURRENT_VERSION}"))
        .call()?;

    let mut data = Vec::new();
    resp.into_reader().read_to_end(&mut data)?;

    // Extract tar.gz
    let decoder = flate2::read::GzDecoder::new(&data[..]);
    let mut archive = tar::Archive::new(decoder);

    // Ensure target dir exists
    fs::create_dir_all(templates_dir)?;

    // Extract, stripping the leading "templates/" prefix if present
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();

        // Skip directories and archive/ subdirs
        if entry.header().entry_type().is_dir() {
            continue;
        }

        // Strip leading "templates/" if the tarball includes it
        let rel = path
            .strip_prefix("templates")
            .unwrap_or(&path)
            .to_path_buf();

        // Only extract .md files at top level (skip archive/, etc.)
        if rel.components().count() != 1 {
            continue;
        }

        let dest = templates_dir.join(&rel);
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut content)?;
        fs::write(&dest, &content)?;
        eprintln!("[update]   ✓ {}", rel.display());
    }

    Ok(())
}

/// Download and replace the binary.
fn update_binary(
    release: &ReleaseInfo,
    current_binary: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = release
        .binary_url
        .as_deref()
        .ok_or("No binary asset found for this platform in release.")?;

    eprintln!("[update] Downloading binary from {}...", release.tag);

    let resp = ureq::get(url)
        .set("User-Agent", &format!("safeclaw/{CURRENT_VERSION}"))
        .call()?;

    let mut data = Vec::new();
    resp.into_reader().read_to_end(&mut data)?;

    // If it's a .tar.gz, extract the binary from it
    let binary_data = if url.ends_with(".tar.gz") {
        extract_binary_from_tarball(&data)?
    } else {
        data
    };

    // Atomic replace: write to .new, rename over current
    let new_path = current_binary.with_extension("new");
    let old_path = current_binary.with_extension("old");

    fs::write(&new_path, &binary_data)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&new_path, fs::Permissions::from_mode(0o755))?;
    }

    // Rename current → .old, new → current
    if current_binary.exists() {
        let _ = fs::rename(current_binary, &old_path);
    }
    fs::rename(&new_path, current_binary)?;

    // Clean up old binary
    let _ = fs::remove_file(&old_path);

    eprintln!("[update]   ✓ Binary replaced ({} bytes)", binary_data.len());
    Ok(())
}

/// Extract the safeclaw binary from a tar.gz archive.
fn extract_binary_from_tarball(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let decoder = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if name == "safeclaw" {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut buf)?;
            return Ok(buf);
        }
    }

    Err("Binary 'safeclaw' not found in tarball".into())
}
