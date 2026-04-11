/// CLI: `safeclaw install <name>`, `safeclaw uninstall <name>`,
///       `safeclaw enable <name>`, `safeclaw disable <name>`
///
/// Resolution: if <name> matches an official service in the registry index,
/// download from github.com/safeclaw/services/<name>/.
/// Otherwise, treat <name> as a GitHub path: owner/repo/subdir or owner/repo.

use std::fs;
use std::path::PathBuf;

const REGISTRY_REPO: &str = "safeclaw/services";
const REGISTRY_BRANCH: &str = "main";

fn user_services_dir() -> Result<PathBuf, String> {
    crate::service::user_services_dir()
        .ok_or_else(|| "Cannot resolve home directory".to_string())
}

/// Fetch a raw file from GitHub. Returns Ok(body) or Err if 404/error.
fn fetch_github_raw(owner_repo: &str, branch: &str, file_path: &str) -> Result<String, String> {
    let url = format!(
        "https://raw.githubusercontent.com/{}/{}/{}",
        owner_repo, branch, file_path
    );
    let resp = ureq::get(&url).call().map_err(|e| format!("Failed to fetch {}: {}", url, e))?;
    resp.into_string().map_err(|e| format!("Failed to read response: {}", e))
}

/// Fetch the registry index to check if a short name is an official service.
fn is_official_service(name: &str) -> bool {
    // Try to fetch index.toml from the registry repo
    if let Ok(body) = fetch_github_raw(REGISTRY_REPO, REGISTRY_BRANCH, "index.toml") {
        #[derive(serde::Deserialize)]
        struct Index { #[serde(default)] services: Vec<String> }
        if let Ok(index) = toml::from_str::<Index>(&body) {
            return index.services.iter().any(|s| s == name);
        }
    }
    // If index fetch fails, try fetching the service directly (graceful fallback)
    fetch_github_raw(REGISTRY_REPO, REGISTRY_BRANCH, &format!("{}/service.toml", name)).is_ok()
}

/// Resolve a service name to (owner/repo, branch, subdir_within_repo).
fn resolve_source(name: &str) -> Result<(String, String, String), String> {
    // Check if it looks like a custom path: contains '/'
    if name.contains('/') {
        // Parse: owner/repo[/subdir...]
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        if parts.len() < 2 {
            return Err(format!("Invalid path: {}", name));
        }
        let owner_repo = format!("{}/{}", parts[0], parts[1]);
        let subdir = if parts.len() == 3 { parts[2].to_string() } else { String::new() };
        return Ok((owner_repo, REGISTRY_BRANCH.to_string(), subdir));
    }

    // Short name: check official registry
    if is_official_service(name) {
        return Ok((REGISTRY_REPO.to_string(), REGISTRY_BRANCH.to_string(), name.to_string()));
    }

    Err(format!(
        "'{}' is not in the official registry.\n\
         To install from a custom repo, use: safeclaw install owner/repo/service-name",
        name
    ))
}

/// Download service TOML files from a GitHub source into target_dir.
fn download_service_files(owner_repo: &str, branch: &str, subdir: &str, target_dir: &PathBuf) -> Result<String, String> {
    let prefix = if subdir.is_empty() { String::new() } else { format!("{}/", subdir) };

    // service.toml is required
    let service_toml = fetch_github_raw(owner_repo, branch, &format!("{}service.toml", prefix))?;

    // Extract service name for display
    let service_name = extract_field(&service_toml, "name")
        .unwrap_or_else(|| "unknown".to_string());

    fs::create_dir_all(target_dir)
        .map_err(|e| format!("Failed to create {}: {}", target_dir.display(), e))?;
    fs::write(target_dir.join("service.toml"), &service_toml)
        .map_err(|e| format!("Failed to write service.toml: {}", e))?;

    // recipe.toml (optional)
    if let Ok(content) = fetch_github_raw(owner_repo, branch, &format!("{}recipe.toml", prefix)) {
        let _ = fs::write(target_dir.join("recipe.toml"), content);
    }

    // policy.toml (optional)
    if let Ok(content) = fetch_github_raw(owner_repo, branch, &format!("{}policy.toml", prefix)) {
        let _ = fs::write(target_dir.join("policy.toml"), content);
    }

    // Remove .disabled marker if present (re-enable on reinstall)
    let disabled = target_dir.join(".disabled");
    if disabled.exists() { let _ = fs::remove_file(disabled); }

    Ok(service_name)
}

/// Quick field extraction from TOML (same as connect.rs helper).
fn extract_field(toml_str: &str, field: &str) -> Option<String> {
    let prefix = format!("{} = \"", field);
    toml_str.lines()
        .find(|l| l.trim().starts_with(&prefix))
        .and_then(|l| {
            let start = l.find(&prefix)? + prefix.len();
            let end = l[start..].find('"')? + start;
            Some(l[start..end].to_string())
        })
}

// ── Public CLI entry points ──────────────────────────────────────────────────

pub fn run_install(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: safeclaw install <name-or-owner/repo/path>".into());
    }
    let name = &args[0];

    let (owner_repo, branch, subdir) = resolve_source(name)?;

    // Determine the local service ID (last path component)
    let local_id = if subdir.is_empty() {
        owner_repo.split('/').last().unwrap_or(name).to_string()
    } else {
        subdir.split('/').last().unwrap_or(name).to_string()
    };

    let target_dir = user_services_dir()?.join(&local_id);

    eprintln!("[install] Downloading {}...", name);
    let service_name = download_service_files(&owner_repo, &branch, &subdir, &target_dir)?;

    eprintln!("[install] {} ({}) installed to {}", service_name, local_id, target_dir.display());
    eprintln!("[install] Restart safeclaw to activate, then run: safeclaw connect {}", local_id);
    Ok(())
}

pub fn run_uninstall(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: safeclaw uninstall <name>".into());
    }
    let name = &args[0];
    let target_dir = user_services_dir()?.join(name);
    if target_dir.exists() {
        fs::remove_dir_all(&target_dir)
            .map_err(|e| format!("Failed to remove {}: {}", target_dir.display(), e))?;
        eprintln!("[uninstall] Service '{}' removed. Restart safeclaw to apply.", name);
    } else {
        eprintln!("[uninstall] Service '{}' not found in ~/.safeclaw/services/", name);
    }
    Ok(())
}

pub fn run_enable(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: safeclaw enable <name>".into());
    }
    let name = &args[0];
    let target_dir = user_services_dir()?.join(name);
    if !target_dir.exists() {
        return Err(format!("Service '{}' not installed. Run: safeclaw install {}", name, name));
    }
    let marker = target_dir.join(".disabled");
    if marker.exists() {
        fs::remove_file(&marker)
            .map_err(|e| format!("Failed to remove .disabled: {}", e))?;
        eprintln!("[enable] Service '{}' enabled. Restart safeclaw to apply.", name);
    } else {
        eprintln!("[enable] Service '{}' is already enabled.", name);
    }
    Ok(())
}

pub fn run_disable(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("Usage: safeclaw disable <name>".into());
    }
    let name = &args[0];
    let target_dir = user_services_dir()?.join(name);
    if !target_dir.exists() {
        return Err(format!("Service '{}' not installed", name));
    }
    fs::write(target_dir.join(".disabled"), "")
        .map_err(|e| format!("Failed to create .disabled: {}", e))?;
    eprintln!("[disable] Service '{}' disabled. Restart safeclaw to apply.", name);
    Ok(())
}

pub fn run_list(args: &[String]) -> Result<(), String> {
    let _ = args; // no args needed
    let user_dir = user_services_dir()?;
    if !user_dir.is_dir() {
        eprintln!("No user-installed services. Install with: safeclaw install <name>");
        return Ok(());
    }

    let Ok(entries) = std::fs::read_dir(&user_dir) else {
        eprintln!("No user-installed services.");
        return Ok(());
    };

    let mut services = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        let id = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let disabled = path.join(".disabled").exists();
        let name = std::fs::read_to_string(path.join("service.toml"))
            .ok()
            .and_then(|c| extract_field(&c, "name"))
            .unwrap_or_else(|| id.clone());
        services.push((id, name, disabled));
    }

    if services.is_empty() {
        eprintln!("No user-installed services. Install with: safeclaw install <name>");
    } else {
        eprintln!("Installed services (~/.safeclaw/services/):\n");
        for (id, name, disabled) in &services {
            let status = if *disabled { " (disabled)" } else { "" };
            eprintln!("  {:<20} {}{}", id, name, status);
        }
        eprintln!();
    }
    Ok(())
}
