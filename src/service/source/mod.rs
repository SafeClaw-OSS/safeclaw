//! Service sources: where `sc service add` reads definitions from, and how a
//! vault records where each of its definitions came from.
//!
//! A source is a folder in the same layout as the built-in catalog: either one
//! service folder (`service.toml` + optional `policy.toml`) or a collection
//! (`services/<id>/service.toml` + optional `policy.toml`). It is read from a
//! local path or from a GitHub repository pinned to a full commit. Only those
//! fixed file names are read, only as regular files; symlinks are never
//! followed (a local folder is walked with `openat` and `O_NOFOLLOW`) and a
//! GitHub tarball is read in memory, never extracted.
//!
//! Every definition then goes through [`crate::service::gate::admit`], the one
//! gate for definition text. Nothing in this module trusts what it reads.

pub mod card;
pub mod github;
pub mod tar;

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::service::{gate, ServiceDef};

// ── Limits ───────────────────────────────────────────────────────────────────
// One source is approved on one card and carried by one op, so it is bounded
// as a whole. The official catalog (36 services, 66 KB of TOML) fits with room.

/// Services in one source (36: the built-in catalog).
pub const MAX_SOURCE_SERVICES: usize = 64;
/// Definition text in one source, all files together. The op carrying it
/// and the card's copy of it (at most
/// [`card::MAX_CARD_DEFINITIONS_BYTES`]), JSON-escaped, must stay under the
/// daemon's 256 KiB request limit (66 KB: the built-in catalog).
pub const MAX_SOURCE_DEFINITION_BYTES: usize = 112 * 1024;
/// Compressed size of a GitHub tarball (1.7 MB: the core repository itself).
pub const MAX_TARBALL_BYTES: usize = 16 * 1024 * 1024;
/// Bytes a GitHub tarball may unpack to, read through and discarded except for
/// the fixed file names (4.4 MB: the core repository).
pub const MAX_TARBALL_UNPACKED_BYTES: u64 = 64 * 1024 * 1024;
/// Archive entries in a GitHub tarball (336: the core repository).
pub const MAX_TARBALL_ENTRIES: usize = 10_000;
/// One `icon.png` (PNG only; SVG and every other format are refused — a
/// vector format can carry script).
pub const MAX_ICON_BYTES: usize = 32 * 1024;

/// The PNG signature every `icon.png` must start with.
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Why `bytes` is not an icon a source may ship, or `Ok`: a PNG (by its
/// signature) of at most [`MAX_ICON_BYTES`].
pub fn check_icon(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < PNG_MAGIC.len() || bytes[..PNG_MAGIC.len()] != PNG_MAGIC {
        return Err("is not a PNG (only PNG icons are read)".into());
    }
    if bytes.len() > MAX_ICON_BYTES {
        return Err(format!(
            "is {} bytes; the limit is {}",
            bytes.len(),
            MAX_ICON_BYTES
        ));
    }
    Ok(())
}

// ── The stored form ──────────────────────────────────────────────────────────

/// Where a vault definition came from, as the requester stated it. Recorded
/// with the definition so `sc service ls` can group by it and `sc service
/// update` can re-fetch it. A local path is meaningless on another machine, so
/// a local source keeps only the folder name.
///
/// The stored record is data any member may write. A `checked` field an
/// older record carries is read and ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "lowercase",
    deny_unknown_fields,
    from = "SourceRecord"
)]
pub enum ServiceSource {
    Github {
        /// `owner/repo`.
        repo: String,
        /// Sub-folder inside the repository, when the source is not its root.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// The branch or tag the user asked for; absent = the repository's
        /// default branch at add time.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        git_ref: Option<String>,
        /// The full 40-hex commit the definitions were read at.
        commit: String,
    },
    Local {
        /// The folder's name (not its path).
        name: String,
    },
}

/// A source record as read: [`ServiceSource`]'s fields, and the `checked`
/// claim older records carry, which is ignored.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum SourceRecord {
    Github {
        repo: String,
        #[serde(default)]
        path: Option<String>,
        #[serde(rename = "ref", default)]
        git_ref: Option<String>,
        commit: String,
        #[serde(default, rename = "checked")]
        _checked: Option<serde::de::IgnoredAny>,
    },
    Local {
        name: String,
    },
}

impl From<SourceRecord> for ServiceSource {
    fn from(r: SourceRecord) -> Self {
        match r {
            SourceRecord::Github {
                repo,
                path,
                git_ref,
                commit,
                ..
            } => ServiceSource::Github {
                repo,
                path,
                git_ref,
                commit,
            },
            SourceRecord::Local { name } => ServiceSource::Local { name },
        }
    }
}

impl ServiceSource {
    /// Check every field against the same rules the CLI applies before it
    /// builds a URL: a stored or requested source is untrusted input too.
    pub fn check(&self) -> Result<(), String> {
        match self {
            ServiceSource::Github {
                repo,
                path,
                git_ref,
                commit,
                ..
            } => {
                let (owner, name) = repo
                    .split_once('/')
                    .ok_or_else(|| "source repo must be owner/repo".to_string())?;
                github::check_owner(owner)?;
                github::check_repo(name)?;
                if let Some(p) = path {
                    check_sub_path(p)?;
                }
                if let Some(r) = git_ref {
                    github::check_ref(r)?;
                }
                if !github::is_full_commit(commit) {
                    return Err("source commit must be a full 40-hex commit".into());
                }
                Ok(())
            }
            ServiceSource::Local { name } => {
                if name.is_empty()
                    || name.len() > 255
                    || name.contains('/')
                    || name.contains('\\')
                    || name.chars().any(crate::util::is_unsafe_display_char)
                {
                    return Err("source folder name is not a plain folder name".into());
                }
                Ok(())
            }
        }
    }

    /// What identifies the source across versions: two definitions with the
    /// same identity come from the same place (a GitHub repo and sub-folder,
    /// compared case-insensitively as GitHub does, or a local folder name).
    pub fn identity(&self) -> String {
        match self {
            ServiceSource::Github { repo, path, .. } => match path {
                Some(p) => format!("github:{}:{}", repo.to_ascii_lowercase(), p),
                None => format!("github:{}", repo.to_ascii_lowercase()),
            },
            ServiceSource::Local { name } => format!("local:{}", name),
        }
    }

    /// One line for humans: the source and, for GitHub, its ref and its
    /// pinned commit (`github:owner/repo[:path] (<ref>) @ <commit>`).
    pub fn display(&self) -> String {
        match self {
            ServiceSource::Github {
                repo,
                path,
                git_ref,
                commit,
                ..
            } => {
                let at = match git_ref {
                    Some(r) => r.as_str(),
                    None => "default branch",
                };
                match path {
                    Some(p) => format!("github:{}:{} ({}) @ {}", repo, p, at, commit),
                    None => format!("github:{} ({}) @ {}", repo, at, commit),
                }
            }
            ServiceSource::Local { name } => format!("local folder {}", name),
        }
    }

    /// The ref a GitHub source is pinned at, as a sentence names it: `'<ref>'`,
    /// or `the default branch`.
    pub fn ref_label(&self) -> String {
        match self {
            ServiceSource::Github {
                git_ref: Some(r), ..
            } => format!("'{}'", r),
            _ => "the default branch".to_string(),
        }
    }
}

/// One `aux.services` value. Two stored shapes: the object
/// `{ service, policy?, source?, summary? }` every new write uses, and the
/// plain string written before sources existed, which reads as a service.toml
/// with no policy and no source. An entry with a source is *installed* (a
/// third-party service, loaded only while the vault's owner allows them); one
/// without (a console-authored definition, a plain string) is not. The value
/// is kept as written (so an entry nobody changes is never rewritten);
/// [`StoredService::parts`] reads it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StoredService(serde_json::Value);

/// A stored entry, read.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredParts {
    pub service: String,
    pub policy: Option<String>,
    pub source: Option<ServiceSource>,
}

/// What an installed definition declares, as the gate admitted it at
/// install: stored beside it for the console to display. Never read back by
/// the daemon (an entry without one reads the same).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallSummary {
    pub name: String,
    pub hosts: Vec<String>,
    pub secrets: Vec<String>,
    pub oauth: bool,
}

impl InstallSummary {
    pub fn of(def: &ServiceDef) -> Self {
        InstallSummary {
            name: def.service.name.clone(),
            hosts: def.service.hosts.clone(),
            secrets: def.service.secrets.clone(),
            oauth: def.oauth2().is_some(),
        }
    }
}

impl StoredService {
    /// An installed entry: the object form with its source and the summary
    /// of the admitted definition `def`.
    pub fn installed(
        service: String,
        policy: Option<String>,
        source: ServiceSource,
        def: &ServiceDef,
    ) -> Self {
        let mut e = StoredService::new(service, policy, Some(source));
        if let (serde_json::Value::Object(o), Ok(sum)) =
            (&mut e.0, serde_json::to_value(InstallSummary::of(def)))
        {
            o.insert("summary".into(), sum);
        }
        e
    }

    /// The object form every new write uses.
    pub fn new(service: String, policy: Option<String>, source: Option<ServiceSource>) -> Self {
        let mut o = serde_json::Map::new();
        o.insert("service".into(), serde_json::Value::String(service));
        if let Some(p) = policy {
            o.insert("policy".into(), serde_json::Value::String(p));
        }
        if let Some(s) = source {
            o.insert(
                "source".into(),
                serde_json::to_value(s).unwrap_or(serde_json::Value::Null),
            );
        }
        StoredService(serde_json::Value::Object(o))
    }

    /// Read the entry. An entry in neither shape, with an unknown field, or
    /// with a source that fails [`ServiceSource::check`] is unreadable as a
    /// whole: the caller skips it and reports why.
    pub fn parts(&self) -> Result<StoredParts, String> {
        match &self.0 {
            serde_json::Value::String(s) => Ok(StoredParts {
                service: s.clone(),
                policy: None,
                source: None,
            }),
            serde_json::Value::Object(o) => {
                // `summary` is display data for the console, never read here.
                if let Some(k) = o
                    .keys()
                    .find(|k| !matches!(k.as_str(), "service" | "policy" | "source" | "summary"))
                {
                    return Err(format!(
                        "stored entry has an unknown field '{}'",
                        crate::util::terminal_safe(k)
                    ));
                }
                let service = o
                    .get("service")
                    .and_then(|v| v.as_str())
                    .ok_or("stored entry has no service text")?
                    .to_string();
                let policy = match o.get("policy") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(p)) => Some(p.clone()),
                    Some(_) => return Err("stored entry's policy is not text".into()),
                };
                let source = match o.get("source") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => {
                        let s: ServiceSource = serde_json::from_value(v.clone())
                            .map_err(|_| "stored entry has an unreadable source".to_string())?;
                        s.check()?;
                        Some(s)
                    }
                };
                Ok(StoredParts {
                    service,
                    policy,
                    source,
                })
            }
            _ => Err("stored entry is neither text nor an object".into()),
        }
    }

    /// The entry's source, when it has a readable one.
    pub fn source(&self) -> Option<ServiceSource> {
        self.parts().ok().and_then(|p| p.source)
    }

    /// An installed entry: stored with a source (one that does not read
    /// counts: the entry is not trusted to be anything else).
    pub fn is_installed(&self) -> bool {
        self.0
            .get("source")
            .is_some_and(|v| !v.is_null())
    }

    /// Admit the stored entry through the gate under its storage key `id`.
    pub fn admit(&self, id: &str) -> Result<ServiceDef, Vec<String>> {
        let p = self.parts().map_err(|e| vec![e])?;
        gate::admit(Some(id), &p.service, p.policy.as_deref())
    }
}

/// A content digest of one definition's text (service.toml, policy.toml):
/// `sc service update` compares it to tell an unchanged definition from a
/// changed one without the text leaving the daemon.
pub fn definition_digest(service: &str, policy: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    // Each part length-prefixed, the policy tagged present or absent: two
    // different (service, policy) pairs never hash the same input.
    let mut h = Sha256::new();
    h.update((service.len() as u64).to_be_bytes());
    h.update(service.as_bytes());
    match policy {
        None => h.update([0u8]),
        Some(p) => {
            h.update([1u8]);
            h.update((p.len() as u64).to_be_bytes());
            h.update(p.as_bytes());
        }
    }
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

impl From<String> for StoredService {
    /// The plain-string form written before sources existed.
    fn from(s: String) -> Self {
        StoredService(serde_json::Value::String(s))
    }
}

impl From<&str> for StoredService {
    fn from(s: &str) -> Self {
        StoredService::from(s.to_string())
    }
}

// ── Source arguments ─────────────────────────────────────────────────────────

/// A GitHub source: `owner/repo`, optionally a sub-folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubSpec {
    pub owner: String,
    pub repo: String,
    pub path: Option<String>,
}

impl GitHubSpec {
    /// The identity a stored GitHub source of this spec has.
    pub fn identity(&self) -> String {
        ServiceSource::Github {
            repo: format!("{}/{}", self.owner, self.repo),
            path: self.path.clone(),
            git_ref: None,
            commit: String::new(),
        }
        .identity()
    }
}

/// What a `<source>` argument names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSpec {
    /// `./path`, `../path`, `/abs/path` or `~/path`.
    Local(std::path::PathBuf),
    /// `git:owner/repo[:sub/path]` or `github:owner/repo[:sub/path]`.
    GitHub(GitHubSpec),
    /// `owner/slug`: the service registry.
    Registry { owner: String, slug: String },
    /// A bare name: a built-in service, or nothing.
    Name(String),
}

const ONLY_GITHUB: &str = "only GitHub sources are supported for now; write github:owner/repo";

/// Parse a `<source>` argument. Pure: nothing is read or fetched.
pub fn parse_source(arg: &str) -> Result<SourceSpec, String> {
    let a = arg.trim();
    if a.is_empty() {
        return Err("empty source".into());
    }
    if a == "."
        || a == ".."
        || a.starts_with("./")
        || a.starts_with("../")
        || a.starts_with('/')
        || a.starts_with("~/")
    {
        let p = match a.strip_prefix("~/") {
            Some(rest) => dirs::home_dir()
                .ok_or("cannot find your home folder")?
                .join(rest),
            None => std::path::PathBuf::from(a),
        };
        return Ok(SourceSpec::Local(p));
    }
    for prefix in ["github:", "git:"] {
        if let Some(rest) = a.strip_prefix(prefix) {
            if rest.contains("://") || rest.starts_with("git@") {
                return Err(ONLY_GITHUB.into());
            }
            return parse_github(rest).map(SourceSpec::GitHub);
        }
    }
    if a.contains("://") || a.starts_with("git@") || a.contains(':') {
        return Err(ONLY_GITHUB.into());
    }
    let parts: Vec<&str> = a.split('/').collect();
    match parts.as_slice() {
        [name] => Ok(SourceSpec::Name((*name).to_string())),
        [owner, slug] if !owner.is_empty() && !slug.is_empty() => Ok(SourceSpec::Registry {
            owner: (*owner).to_string(),
            slug: (*slug).to_string(),
        }),
        _ => Err(format!(
            "'{}' is not a source: use ./path, github:owner/repo[:path], or a service name",
            crate::util::terminal_safe(a)
        )),
    }
}

/// `owner/repo[:sub/path]`, each part checked against GitHub's charset.
fn parse_github(rest: &str) -> Result<GitHubSpec, String> {
    let (repo_part, path) = match rest.split_once(':') {
        Some((r, p)) => (r, Some(p)),
        None => (rest, None),
    };
    let (owner, repo) = repo_part
        .split_once('/')
        .ok_or("a GitHub source is github:owner/repo")?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    github::check_owner(owner)?;
    github::check_repo(repo)?;
    let path = match path {
        None => None,
        Some(p) => {
            let p = p.trim_matches('/');
            check_sub_path(p)?;
            Some(p.to_string())
        }
    };
    Ok(GitHubSpec {
        owner: owner.to_string(),
        repo: repo.to_string(),
        path,
    })
}

/// A sub-folder inside a source: `/`-separated plain names, never `.` or `..`,
/// so it can never leave the repository.
pub fn check_sub_path(p: &str) -> Result<(), String> {
    if p.is_empty() || p.len() > 255 {
        return Err("the :path part must be 1 to 255 characters".into());
    }
    let segs: Vec<&str> = p.split('/').collect();
    if segs.len() > 32 {
        return Err("the :path part has too many folders".into());
    }
    for s in segs {
        if s.is_empty()
            || s == "."
            || s == ".."
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "'{}' is not a valid :path inside the repository",
                crate::util::terminal_safe(p)
            ));
        }
    }
    Ok(())
}

// ── The files of a source ────────────────────────────────────────────────────

/// The definition files read from a source root, before the gate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceFiles {
    /// Folder key → (service.toml, policy.toml). The key is the `services/<id>`
    /// folder name in a collection, or empty for a single service folder.
    pub defs: BTreeMap<String, (String, Option<String>)>,
    /// True for a single service folder (service.toml at the root).
    pub single: bool,
}

impl SourceFiles {
    fn label(&self, key: &str) -> String {
        if self.single {
            "service.toml".to_string()
        } else {
            format!("services/{}", crate::util::terminal_safe(key))
        }
    }
}

/// What the readers saw at the fixed paths, assembled into [`SourceFiles`]
/// with one set of layout rules for both a local folder and a tarball.
#[derive(Default)]
pub(crate) struct Layout {
    /// `service.toml` / `policy.toml` / `icon.png` at the root.
    pub root_service: Option<String>,
    pub root_policy: Option<String>,
    pub root_icon: Option<Vec<u8>>,
    /// Something exists at `service.toml` at the root (read or not).
    pub root_service_seen: bool,
    /// Something exists at `services/` (a folder, or any entry under it).
    pub services_seen: bool,
    /// `services/<id>` folders seen, with what was read inside
    /// (service.toml, policy.toml, icon.png).
    pub folders: BTreeMap<String, FolderSlot>,
    /// Problems found while reading (a symlink at a fixed path, a file over
    /// the size limit, a file that is not UTF-8).
    pub problems: Vec<String>,
}

/// What was read inside one `services/<id>` folder.
#[derive(Default)]
pub(crate) struct FolderSlot {
    pub service: Option<String>,
    pub policy: Option<String>,
    pub icon: Option<Vec<u8>>,
}

impl Layout {
    pub(crate) fn finish(self) -> Result<SourceFiles, Vec<String>> {
        let mut problems = self.problems;
        if self.root_service_seen && self.services_seen {
            problems.push(
                "the source has both a service.toml and a services/ folder; point at one of them"
                    .into(),
            );
            return Err(problems);
        }
        let mut files = SourceFiles::default();
        // An `icon.png` is a format allowance, not content: it is validated
        // (PNG, size) so the convention stays disciplined, then dropped. It is
        // never stored, never part of what is approved; icons display from
        // the public catalog when it opens, not from installs.
        let check_icon_at = |key: &str, icon: Option<Vec<u8>>, problems: &mut Vec<String>| {
            let Some(bytes) = icon else { return };
            let label = if key.is_empty() {
                "icon.png".to_string()
            } else {
                format!("services/{}/icon.png", crate::util::terminal_safe(key))
            };
            if let Err(e) = check_icon(&bytes) {
                problems.push(format!("{} {}", label, e));
            }
        };
        if self.root_service_seen {
            files.single = true;
            check_icon_at("", self.root_icon, &mut problems);
            match self.root_service {
                Some(s) => {
                    files.defs.insert(String::new(), (s, self.root_policy));
                }
                None if problems.is_empty() => {
                    problems.push("service.toml could not be read".into());
                }
                None => {}
            }
        } else if self.services_seen {
            if self.folders.len() > MAX_SOURCE_SERVICES {
                problems.push(format!(
                    "the source has {} services; the limit is {}",
                    self.folders.len(),
                    MAX_SOURCE_SERVICES
                ));
                return Err(problems);
            }
            for (key, slot) in self.folders {
                check_icon_at(&key, slot.icon, &mut problems);
                match slot.service {
                    Some(s) => {
                        files.defs.insert(key, (s, slot.policy));
                    }
                    None => {
                        let label = format!("services/{}", crate::util::terminal_safe(&key));
                        if !problems.iter().any(|p| p.starts_with(&label)) {
                            problems.push(format!("{} has no service.toml", label));
                        }
                    }
                }
            }
            if files.defs.is_empty() && problems.is_empty() {
                problems.push("the services/ folder holds no service".into());
            }
        } else {
            problems.push("no service.toml or services/ folder found".into());
        }
        if problems.is_empty() {
            Ok(files)
        } else {
            Err(problems)
        }
    }
}

/// The file kinds a source is read at ([`fixed_path`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileKind {
    Service,
    Policy,
    Icon,
}

impl FileKind {
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            FileKind::Service => "service.toml",
            FileKind::Policy => "policy.toml",
            FileKind::Icon => "icon.png",
        }
    }
}

/// The paths a source is read at, relative to its root: `Some((folder key,
/// kind))` for the fixed names, `None` for anything else. A folder key is
/// empty at the root.
pub(crate) fn fixed_path(rel: &str) -> Option<(String, FileKind)> {
    let kind = |file: &str| match file {
        "service.toml" => Some(FileKind::Service),
        "policy.toml" => Some(FileKind::Policy),
        "icon.png" => Some(FileKind::Icon),
        _ => None,
    };
    if let Some(k) = kind(rel) {
        return Some((String::new(), k));
    }
    let rest = rel.strip_prefix("services/")?;
    let (key, file) = rest.split_once('/')?;
    if key.is_empty() || file.contains('/') {
        return None;
    }
    kind(file).map(|k| (key.to_string(), k))
}

// ── Local folders ────────────────────────────────────────────────────────────

/// Read a local source folder. Its path is resolved once (links on the path
/// the user typed are theirs, the folder itself must not be one); from the
/// filesystem root down to each file every component is then opened relative
/// to its parent with `O_NOFOLLOW`, so a symbolic link anywhere, there from
/// the start or swapped in while reading, is refused and never followed. A
/// file is opened non-blocking and read only when `fstat` on the opened file
/// says it is a regular file within the size limit, so a FIFO or a device can
/// neither block nor feed the read. Only the fixed file names are read; file
/// content is never quoted in a problem.
#[cfg(unix)]
pub fn read_local(root: &Path) -> Result<SourceFiles, Vec<String>> {
    use local::{Folder, Opened};
    let shown = crate::util::terminal_safe(&root.display().to_string()).into_owned();
    let dir = Folder::open_root(root).map_err(|e| vec![format!("{} {}", shown, e)])?;
    let mut lay = Layout::default();
    let svc = dir.file("service.toml");
    if !matches!(svc, Opened::Absent) {
        lay.root_service_seen = true;
        lay.root_service = read_fixed(svc, "service.toml", &mut lay.problems);
        lay.root_policy = read_fixed(dir.file("policy.toml"), "policy.toml", &mut lay.problems);
        lay.root_icon = read_fixed_bytes(dir.file("icon.png"), "icon.png", &mut lay.problems);
    }
    match dir.folder("services") {
        Opened::Absent => {}
        services => {
            lay.services_seen = true;
            if !lay.root_service_seen {
                read_local_collection(services, &mut lay);
            }
        }
    }
    lay.finish()
}

/// Local folders are read with `openat` and `O_NOFOLLOW` (see [`read_local`]),
/// which this platform does not offer here.
#[cfg(not(unix))]
pub fn read_local(_root: &Path) -> Result<SourceFiles, Vec<String>> {
    Err(vec![
        "a local source folder can be read on macOS and Linux only; use a GitHub source".into(),
    ])
}

#[cfg(unix)]
fn read_local_collection(services: local::Opened<local::Folder>, lay: &mut Layout) {
    use local::Opened;
    let services = match services {
        Opened::Found(f) => f,
        Opened::Failed(e) => {
            lay.problems.push(format!("services/: {}", e));
            return;
        }
        _ => {
            lay.problems
                .push("services/ is not a folder (a symbolic link is not followed)".into());
            return;
        }
    };
    let cap = MAX_SOURCE_SERVICES * 4;
    let (mut names, unreadable) = match services.names(cap) {
        Ok(n) => n,
        Err(e) => {
            lay.problems.push(format!("services/ {}", e));
            return;
        }
    };
    for _ in 0..unreadable {
        lay.problems
            .push("services/: an entry name is not UTF-8".into());
    }
    names.sort();
    for name in names {
        let label = format!("services/{}", crate::util::terminal_safe(&name));
        let folder = match services.folder(&name) {
            Opened::Found(f) => f,
            Opened::Link => {
                lay.problems
                    .push(format!("{} is a symbolic link; it is not followed", label));
                continue;
            }
            Opened::Failed(e) => {
                lay.problems.push(format!("{}: {}", label, e));
                continue;
            }
            // A README or similar next to the service folders, or gone.
            Opened::Other | Opened::Absent => continue,
        };
        let slot = FolderSlot {
            service: read_fixed(
                folder.file("service.toml"),
                &format!("{}/service.toml", label),
                &mut lay.problems,
            ),
            policy: read_fixed(
                folder.file("policy.toml"),
                &format!("{}/policy.toml", label),
                &mut lay.problems,
            ),
            icon: read_fixed_bytes(
                folder.file("icon.png"),
                &format!("{}/icon.png", label),
                &mut lay.problems,
            ),
        };
        lay.folders.insert(name, slot);
    }
}

/// The text of one fixed-name file, or `None` (absent, or a problem pushed
/// under `label`).
#[cfg(unix)]
fn read_fixed(
    opened: local::Opened<std::fs::File>,
    label: &str,
    problems: &mut Vec<String>,
) -> Option<String> {
    let bytes = read_fixed_bytes(opened, label, problems)?;
    match String::from_utf8(bytes) {
        Ok(s) => Some(s),
        Err(_) => {
            problems.push(format!("{} is not UTF-8", label));
            None
        }
    }
}

/// The bytes of one fixed-name file (the icon is binary), or `None` (absent,
/// or a problem pushed under `label`).
#[cfg(unix)]
fn read_fixed_bytes(
    opened: local::Opened<std::fs::File>,
    label: &str,
    problems: &mut Vec<String>,
) -> Option<Vec<u8>> {
    use local::Opened;
    let bytes = match opened {
        Opened::Absent => return None,
        Opened::Found(f) => local::read_bytes(f),
        Opened::Link => Err("is a symbolic link; only regular files are read".to_string()),
        Opened::Other => Err("is not a regular file".to_string()),
        Opened::Failed(e) => Err(format!("cannot be read: {}", e)),
    };
    match bytes {
        Ok(b) => Some(b),
        Err(e) => {
            problems.push(format!("{} {}", label, e));
            None
        }
    }
}

/// The `openat` walk [`read_local`] reads a local source with.
#[cfg(unix)]
pub(crate) mod local {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::path::{Component, Path};

    use rustix::fs::{openat, statat, AtFlags, Dir, FileType, Mode, OFlags, CWD};
    use rustix::io::Errno;

    use crate::service::limits::MAX_FILE_BYTES;

    /// What is at a name inside an opened folder.
    pub enum Opened<T> {
        Absent,
        /// A symbolic link (not followed).
        Link,
        /// Something of the other kind (a file where a folder was asked for,
        /// or the reverse).
        Other,
        Failed(String),
        Found(T),
    }

    /// An opened folder: names inside it are opened relative to it.
    pub struct Folder(OwnedFd);

    fn folder_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
    }

    fn file_flags() -> OFlags {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY
    }

    /// `O_NOFOLLOW` met a symbolic link (`ELOOP`; `EMLINK` on some BSDs).
    fn is_link(e: Errno) -> bool {
        e == Errno::LOOP || e == Errno::MLINK
    }

    impl Folder {
        /// Open `root` (`Err` reads after its path): resolved once, then
        /// walked from `/` one component at a time without following links.
        pub fn open_root(root: &Path) -> Result<Folder, String> {
            let meta = std::fs::symlink_metadata(root).map_err(|e| format!(": {}", e))?;
            if meta.file_type().is_symlink() {
                return Err("is a symbolic link; pass the folder it points to".into());
            }
            if !meta.is_dir() {
                return Err("is not a folder".into());
            }
            let canonical = std::fs::canonicalize(root).map_err(|e| format!(": {}", e))?;
            let mut cur =
                openat(CWD, "/", folder_flags(), Mode::empty()).map_err(|e| format!(": {}", e))?;
            for c in canonical.components() {
                match c {
                    Component::RootDir => {}
                    Component::Normal(name) => {
                        cur = openat(&cur, name, folder_flags(), Mode::empty()).map_err(|e| {
                            if is_link(e) || e == Errno::NOTDIR {
                                "changed while it was read (a symbolic link on its path is not followed)".to_string()
                            } else {
                                format!(": {}", e)
                            }
                        })?;
                    }
                    _ => return Err("is not a plain folder path".into()),
                }
            }
            Ok(Folder(cur))
        }

        /// The folder `name` inside this one.
        pub fn folder(&self, name: &str) -> Opened<Folder> {
            match openat(&self.0, name, folder_flags(), Mode::empty()) {
                Ok(fd) => Opened::Found(Folder(fd)),
                Err(e) if e == Errno::NOENT => Opened::Absent,
                Err(e) if is_link(e) || e == Errno::NOTDIR => self.kind_of(name),
                Err(e) => Opened::Failed(e.to_string()),
            }
        }

        /// The file `name` inside this one, opened (not yet read).
        pub fn file(&self, name: &str) -> Opened<std::fs::File> {
            match openat(&self.0, name, file_flags(), Mode::empty()) {
                Ok(fd) => Opened::Found(std::fs::File::from(fd)),
                Err(e) if e == Errno::NOENT => Opened::Absent,
                Err(e) if is_link(e) => Opened::Link,
                Err(e) => Opened::Failed(e.to_string()),
            }
        }

        /// What `name` is when it could not be opened as a folder. Looking
        /// never follows it.
        fn kind_of<T>(&self, name: &str) -> Opened<T> {
            match statat(&self.0, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) if FileType::from_raw_mode(st.st_mode as _) == FileType::Symlink => {
                    Opened::Link
                }
                Ok(_) => Opened::Other,
                Err(e) if e == Errno::NOENT => Opened::Absent,
                Err(e) => Opened::Failed(e.to_string()),
            }
        }

        /// The names inside this folder (`.` and `..` left out) and how many
        /// were not UTF-8; `Err` past `cap` entries.
        pub fn names(&self, cap: usize) -> Result<(Vec<String>, usize), String> {
            let dir = Dir::read_from(&self.0).map_err(|e| format!(": {}", e))?;
            let mut names = Vec::new();
            let mut unreadable = 0usize;
            for entry in dir {
                let entry = entry.map_err(|e| format!(": {}", e))?;
                let raw = entry.file_name().to_bytes();
                if raw == b"." || raw == b".." {
                    continue;
                }
                match std::str::from_utf8(raw) {
                    Ok(n) => names.push(n.to_string()),
                    Err(_) => unreadable += 1,
                }
                if names.len() + unreadable > cap {
                    return Err(format!("has more than {} entries", cap));
                }
            }
            Ok((names, unreadable))
        }
    }

    /// Read an opened file: only a regular file (by `fstat` on the open file)
    /// within the size limit.
    pub fn read_bytes(file: std::fs::File) -> Result<Vec<u8>, String> {
        let meta = file
            .metadata()
            .map_err(|e| format!("cannot be read: {}", e))?;
        if !meta.file_type().is_file() {
            return Err("is not a regular file".into());
        }
        if meta.len() > MAX_FILE_BYTES as u64 {
            return Err(format!(
                "is {} bytes; the limit is {}",
                meta.len(),
                MAX_FILE_BYTES
            ));
        }
        let mut buf = Vec::new();
        file.take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot be read: {}", e))?;
        if buf.len() > MAX_FILE_BYTES {
            return Err(format!("is larger than the {}-byte limit", MAX_FILE_BYTES));
        }
        Ok(buf)
    }
}

// ── Admission ────────────────────────────────────────────────────────────────

/// One definition of a source, admitted by the gate.
#[derive(Debug, Clone)]
pub struct Admitted {
    /// The storage key: the declared `[service] id` (after any rename).
    pub id: String,
    /// The text stored for it.
    pub service: String,
    pub policy: Option<String>,
    /// The definition as admitted (full policy; a vault applies
    /// [`ServiceDef::for_vault`] of it).
    pub def: ServiceDef,
}

/// Admit every definition of a source through the gate, all or nothing.
/// `rename` (`--id`) is only for a single service folder: its `[service] id`
/// is rewritten so the stored id is the new one. Returns every problem found.
pub fn admit_files(
    files: &SourceFiles,
    rename: Option<&str>,
) -> Result<Vec<Admitted>, Vec<String>> {
    let mut problems = Vec::new();
    let mut out = Vec::new();
    let total: usize = files
        .defs
        .values()
        .map(|(s, p)| s.len() + p.as_ref().map_or(0, |p| p.len()))
        .sum();
    if total > MAX_SOURCE_DEFINITION_BYTES {
        return Err(vec![format!(
            "the source's definitions total {} bytes; one approval carries at most {} (add a sub-folder with :path)",
            total, MAX_SOURCE_DEFINITION_BYTES
        )]);
    }
    if rename.is_some() && !files.single {
        return Err(vec![format!(
            "--id renames a single service; this source has {} services",
            files.defs.len()
        )]);
    }
    for (key, (svc, pol)) in &files.defs {
        let label = files.label(key);
        let gate_key = (!files.single).then_some(key.as_str());
        let def = match gate::admit(gate_key, svc, pol.as_deref()) {
            Ok(d) => d,
            Err(ps) => {
                problems.extend(ps.into_iter().map(|p| format!("{}: {}", label, p)));
                continue;
            }
        };
        let (service, def) = match rename {
            Some(new_id) if new_id != def.service.id => {
                let text = match rename_service(svc, new_id) {
                    Ok(t) => t,
                    Err(e) => {
                        problems.push(format!("{}: {}", label, e));
                        continue;
                    }
                };
                match gate::admit(Some(new_id), &text, pol.as_deref()) {
                    Ok(d) => (text, d),
                    Err(ps) => {
                        problems.extend(ps.into_iter().map(|p| format!("--id: {}", p)));
                        continue;
                    }
                }
            }
            _ => (svc.clone(), def),
        };
        out.push(Admitted {
            id: def.service.id.clone(),
            service,
            policy: pol.clone(),
            def,
        });
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    if out.is_empty() {
        return Err(vec!["the source holds no service".into()]);
    }
    Ok(out)
}

/// The `service-add` op for `admitted` from `source` into `vault`
/// (`update`: `sc service update`): the request the daemon's op creation
/// checks and stamps. One shape for every requester.
pub fn add_op(
    vault: &str,
    source: &ServiceSource,
    admitted: &[Admitted],
    update: bool,
    iat: u64,
) -> serde_json::Value {
    let defs: serde_json::Map<String, serde_json::Value> = admitted
        .iter()
        .map(|a| {
            let mut d = serde_json::json!({ "service": a.service });
            if let Some(p) = &a.policy {
                d["policy"] = serde_json::json!(p);
            }
            (a.id.clone(), d)
        })
        .collect();
    serde_json::json!({
        "act": {
            "type": { "custom": "service-add" },
            "target": source.identity(),
            "scope": { "defs": defs, "source": source, "update": update },
        },
        "bind": { "redeemer": vault },
        "valid": { "iat": iat, "multiplicity": 1 }
    })
}

/// Problems under a heading, as `sc service` prints them: `✗ <what>: <n>
/// problem(s):` then one `  • ` line each (continuation lines indented).
pub fn problems_text(what: &str, problems: &[String]) -> String {
    let mut out = format!(
        "✗ {}: {} problem{}:",
        what,
        problems.len(),
        if problems.len() == 1 { "" } else { "s" }
    );
    for p in problems {
        let mut lines = p.lines();
        if let Some(first) = lines.next() {
            out.push_str(&format!("\n  • {}", first));
        }
        for l in lines {
            out.push_str(&format!("\n    {}", l));
        }
    }
    out
}

/// Rewrite a service.toml's `[service] id`. The text is re-serialized from
/// its parsed form (comments are not kept); the result is admitted again.
pub fn rename_service(text: &str, new_id: &str) -> Result<String, String> {
    let mut t: toml::Table = text
        .parse()
        .map_err(|_| "service.toml does not parse".to_string())?;
    let svc = t
        .get_mut("service")
        .and_then(|v| v.as_table_mut())
        .ok_or("service.toml has no [service] table")?;
    svc.insert("id".into(), toml::Value::String(new_id.to_string()));
    toml::to_string(&t).map_err(|e| format!("cannot rewrite the id: {}", e))
}

#[cfg(test)]
pub(crate) mod tests;
