//! What this device found when it checked where a vault's definitions came
//! from: daemon-local facts, kept beside the vault's store
//! (`vaults/<vid>/service-checks.json`), never in the vault. A stored service
//! record is data any member may write, so whether its source was checked is
//! never read from it.
//!
//! A fact is written only when this daemon fetched a GitHub source again at
//! its pinned commit and found the same definitions (the card it stamped at op
//! creation says so), as the approved `service-add` lands. It names the
//! definition by its digest, so it speaks for that definition text and that
//! source at that commit only: an entry changed since (by anyone) is no longer
//! the one this device checked.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{definition_digest, ServiceSource};

/// The file the facts of one vault are kept in, in that vault's directory.
pub const FILE: &str = "service-checks.json";

/// One definition this device checked: its digest
/// ([`definition_digest`]), its source's identity, and the commit it was
/// fetched at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCheck {
    pub digest: String,
    pub source: String,
    pub commit: String,
}

impl DeviceCheck {
    /// The fact for a definition (`service`, `policy`) read from `source`, a
    /// GitHub source; `None` for a local folder (never checked).
    pub fn of(service: &str, policy: Option<&str>, source: &ServiceSource) -> Option<Self> {
        match source {
            ServiceSource::Github { commit, .. } => Some(DeviceCheck {
                digest: definition_digest(service, policy),
                source: source.identity(),
                commit: commit.clone(),
            }),
            ServiceSource::Local { .. } => None,
        }
    }
}

/// Service id → the fact this device recorded for it.
pub type DeviceChecks = BTreeMap<String, DeviceCheck>;

/// The facts file of the vault whose directory is `vault_dir`.
pub fn path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(FILE)
}

/// The facts recorded at `path`. None recorded, or a file that does not
/// read: none (every source then reads as stated by the requester).
pub fn load(path: &Path) -> DeviceChecks {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Record `facts` at `path`, over earlier facts for the same ids.
pub fn record(path: &Path, facts: impl IntoIterator<Item = (String, DeviceCheck)>) -> std::io::Result<()> {
    let mut all = load(path);
    all.extend(facts);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&all)?;
    let tmp = path.with_extension(format!("json.tmp.{:08x}", rand::random::<u32>()));
    if let Err(e) = std::fs::write(&tmp, &bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// The commit this device checked the stored definition `id` at, when it
/// did: the recorded fact names this definition text (`digest`) and the
/// stored source at the stored commit. Anything else: `None` (as stated by
/// the requester).
pub fn checked_commit<'a>(
    facts: &'a DeviceChecks,
    id: &str,
    source: Option<&ServiceSource>,
    digest: Option<&str>,
) -> Option<&'a str> {
    let fact = facts.get(id)?;
    let ServiceSource::Github { commit, .. } = source? else {
        return None;
    };
    (Some(fact.digest.as_str()) == digest
        && fact.source == source?.identity()
        && &fact.commit == commit)
        .then_some(fact.commit.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gh(commit: char) -> ServiceSource {
        ServiceSource::Github {
            repo: "acme/tools".into(),
            path: None,
            git_ref: None,
            commit: commit.to_string().repeat(40),
        }
    }

    /// A fact speaks for the definition text, source and commit it names;
    /// anything changed since reads as stated.
    #[test]
    fn a_fact_speaks_only_for_what_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let p = path(dir.path());
        assert!(load(&p).is_empty());
        let fact = DeviceCheck::of("svc", None, &gh('a')).unwrap();
        record(&p, [("a1".to_string(), fact.clone())]).unwrap();
        let facts = load(&p);
        assert_eq!(facts["a1"], fact);
        let d = definition_digest("svc", None);
        let a = "a".repeat(40);
        assert_eq!(checked_commit(&facts, "a1", Some(&gh('a')), Some(&d)), Some(a.as_str()));
        // Other text, another commit, another source, another id, no source.
        let other = definition_digest("svc2", None);
        assert_eq!(checked_commit(&facts, "a1", Some(&gh('a')), Some(&other)), None);
        assert_eq!(checked_commit(&facts, "a1", Some(&gh('b')), Some(&d)), None);
        let mut moved = gh('a');
        if let ServiceSource::Github { repo, .. } = &mut moved {
            *repo = "acme/other".into();
        }
        assert_eq!(checked_commit(&facts, "a1", Some(&moved), Some(&d)), None);
        assert_eq!(checked_commit(&facts, "b2", Some(&gh('a')), Some(&d)), None);
        assert_eq!(checked_commit(&facts, "a1", None, Some(&d)), None);
        // A local folder is never checked.
        assert!(DeviceCheck::of("svc", None, &ServiceSource::Local { name: "m".into() }).is_none());
        // A file that does not read: none.
        std::fs::write(&p, b"not json").unwrap();
        assert!(load(&p).is_empty());
    }
}
