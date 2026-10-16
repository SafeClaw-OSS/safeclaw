//! Install the version-matched SafeClaw skill embedded in this binary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::config::{SkillInstallArgs, SkillRemoveArgs, SkillSubcommand};

const SKILL: &str = include_str!("../../skills/safeclaw/SKILL.md");

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    sha256: String,
    sc_version: String,
    #[serde(default)]
    claude_symlink: bool,
}

#[derive(Debug)]
pub struct InstallReport {
    pub paths: Vec<PathBuf>,
    pub modified: bool,
    pub notes: Vec<String>,
}

pub fn run(sub: SkillSubcommand) -> Result<(), String> {
    match sub {
        SkillSubcommand::Install(SkillInstallArgs { force }) => {
            let report = install(force)?;
            for path in &report.paths {
                println!("Installed: {}", path.display());
            }
            for note in &report.notes {
                println!("{}", note);
            }
            Ok(())
        }
        SkillSubcommand::Remove(SkillRemoveArgs { force }) => {
            let removed = remove(force)?;
            if removed.is_empty() {
                println!("SafeClaw skill is not installed.");
            } else {
                for path in removed {
                    println!("Removed: {}", path.display());
                }
            }
            Ok(())
        }
    }
}

pub fn manifest_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("cannot locate home dir")?;
    Ok(home.join(".safeclaw").join("skill-manifest.json"))
}

pub fn install(force: bool) -> Result<InstallReport, String> {
    let home = dirs::home_dir().ok_or("cannot locate home dir")?;
    install_at(&home, force)
}

fn install_at(home: &Path, force: bool) -> Result<InstallReport, String> {
    let skill_dir = home.join(".agents/skills/safeclaw");
    let skill_path = skill_dir.join("SKILL.md");
    let manifest_path = home.join(".safeclaw/skill-manifest.json");
    let old_manifest = read_manifest(&manifest_path)?;
    let new_hash = sha256(SKILL.as_bytes());
    let current_hash = fs::read(&skill_path).ok().map(|b| sha256(&b));
    let was_modified = current_hash.as_ref().is_some_and(|hash| {
        hash != &new_hash
            && old_manifest
                .as_ref()
                .map(|m| m.sha256.as_str())
                != Some(hash.as_str())
    });

    let mut report = InstallReport {
        paths: Vec::new(),
        modified: was_modified && !force,
        notes: Vec::new(),
    };
    if was_modified && !force {
        report.paths.push(skill_path.clone());
        report.notes.push(format!(
            "Left the modified skill at {} unchanged. Use `sc skill install --force` to replace it.",
            skill_path.display()
        ));
        ensure_claude_link(home, &skill_dir, old_manifest.as_ref(), &mut report, false)?;
        return Ok(report);
    }

    fs::create_dir_all(&skill_dir)
        .map_err(|e| format!("create {}: {}", skill_dir.display(), e))?;
    if current_hash.as_deref() != Some(new_hash.as_str()) {
        atomic_write(&skill_path, SKILL.as_bytes())?;
    } else {
        set_private(&skill_path)?;
    }
    report.paths.push(skill_path.clone());

    let claude_owned = ensure_claude_link(
        home,
        &skill_dir,
        old_manifest.as_ref(),
        &mut report,
        true,
    )?;
    let manifest = Manifest {
        sha256: new_hash,
        sc_version: crate::build_version().to_string(),
        claude_symlink: claude_owned,
    };
    let body = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("serialize skill manifest: {}", e))?;
    atomic_write(&manifest_path, &body)?;
    Ok(report)
}

/// Ensure Claude sees the shared skill. Returns whether the symlink is known to
/// have been created by SafeClaw and can therefore be removed later.
fn ensure_claude_link(
    home: &Path,
    skill_dir: &Path,
    old_manifest: Option<&Manifest>,
    report: &mut InstallReport,
    may_create: bool,
) -> Result<bool, String> {
    let claude = home.join(".claude");
    if !claude.exists() {
        return Ok(false);
    }
    let skills_dir = claude.join("skills");
    fs::create_dir_all(&skills_dir)
        .map_err(|e| format!("create {}: {}", skills_dir.display(), e))?;
    let link = skills_dir.join("safeclaw");
    match fs::symlink_metadata(&link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if link_points_to(&link, skill_dir) {
                report.paths.push(link);
                return Ok(old_manifest.map(|m| m.claude_symlink).unwrap_or(false));
            }
            report.notes.push(format!(
                "Left the existing symlink at {} unchanged because it points elsewhere.",
                link.display()
            ));
            Ok(false)
        }
        Ok(_) => {
            report.notes.push(format!(
                "Left the existing path at {} unchanged because it is not SafeClaw's symlink.",
                link.display()
            ));
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && may_create => {
            #[cfg(unix)]
            std::os::unix::fs::symlink(skill_dir, &link)
                .map_err(|e| format!("create symlink {}: {}", link.display(), e))?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(skill_dir, &link)
                .map_err(|e| format!("create symlink {}: {}", link.display(), e))?;
            report.paths.push(link);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("inspect {}: {}", link.display(), e)),
    }
}

fn link_points_to(link: &Path, target: &Path) -> bool {
    let Ok(raw) = fs::read_link(link) else {
        return false;
    };
    let resolved = if raw.is_absolute() {
        raw
    } else {
        link.parent().unwrap_or_else(|| Path::new(".")).join(raw)
    };
    match (fs::canonicalize(resolved), fs::canonicalize(target)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

pub fn remove(force: bool) -> Result<Vec<PathBuf>, String> {
    let home = dirs::home_dir().ok_or("cannot locate home dir")?;
    remove_at(&home, force)
}

fn remove_at(home: &Path, force: bool) -> Result<Vec<PathBuf>, String> {
    let manifest_path = home.join(".safeclaw/skill-manifest.json");
    let Some(manifest) = read_manifest(&manifest_path)? else {
        return Ok(Vec::new());
    };
    let skill_dir = home.join(".agents/skills/safeclaw");
    let skill_path = skill_dir.join("SKILL.md");
    if skill_path.exists() {
        let hash = sha256(
            &fs::read(&skill_path)
                .map_err(|e| format!("read {}: {}", skill_path.display(), e))?,
        );
        if hash != manifest.sha256 && !force {
            return Err(format!(
                "{} was modified after SafeClaw installed it; re-run `sc skill remove --force` to remove it",
                skill_path.display()
            ));
        }
    }

    let mut removed = Vec::new();
    let link = home.join(".claude/skills/safeclaw");
    if manifest.claude_symlink && link_points_to(&link, &skill_dir) {
        fs::remove_file(&link).map_err(|e| format!("remove {}: {}", link.display(), e))?;
        removed.push(link);
    }
    if skill_path.exists() {
        fs::remove_file(&skill_path)
            .map_err(|e| format!("remove {}: {}", skill_path.display(), e))?;
        removed.push(skill_path);
    }
    let _ = fs::remove_dir(&skill_dir);
    if manifest_path.exists() {
        fs::remove_file(&manifest_path)
            .map_err(|e| format!("remove {}: {}", manifest_path.display(), e))?;
        removed.push(manifest_path);
    }
    Ok(removed)
}

fn read_manifest(path: &Path) -> Result<Option<Manifest>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {}", path.display(), e)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| format!("parse {}: {}", path.display(), e))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {}", parent.display(), e))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("create {}: {}", tmp.display(), e))?;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    file.sync_all()
        .map_err(|e| format!("sync {}: {}", tmp.display(), e))?;
    set_private(&tmp)?;
    fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} to {}: {}", tmp.display(), path.display(), e))?;
    Ok(())
}

fn set_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {}", path.display(), e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_detects_modification_and_manages_claude_symlink() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir(home.path().join(".claude")).unwrap();

        let first = install_at(home.path(), false).unwrap();
        assert!(!first.modified);
        let skill = home.path().join(".agents/skills/safeclaw/SKILL.md");
        let link = home.path().join(".claude/skills/safeclaw");
        assert_eq!(fs::read_to_string(&skill).unwrap(), SKILL);
        assert!(link_points_to(&link, skill.parent().unwrap()));

        fs::write(&skill, "user edit\n").unwrap();
        let skipped = install_at(home.path(), false).unwrap();
        assert!(skipped.modified);
        assert_eq!(fs::read_to_string(&skill).unwrap(), "user edit\n");

        let forced = install_at(home.path(), true).unwrap();
        assert!(!forced.modified);
        assert_eq!(fs::read_to_string(&skill).unwrap(), SKILL);

        let removed = remove_at(home.path(), false).unwrap();
        assert!(removed.iter().any(|p| p == &skill));
        assert!(!skill.exists());
        assert!(fs::symlink_metadata(&link).is_err());

        let conflicted_home = tempfile::tempdir().unwrap();
        let conflict = conflicted_home.path().join(".claude/skills/safeclaw");
        fs::create_dir_all(&conflict).unwrap();
        let report = install_at(conflicted_home.path(), false).unwrap();
        assert!(conflict.is_dir(), "an existing real directory is left alone");
        assert!(report.notes.iter().any(|note| note.contains("not SafeClaw's symlink")));
    }
}
