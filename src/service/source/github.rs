//! GitHub sources: resolve a ref to a full commit, fetch that commit's
//! tarball, read the source out of it in memory.
//!
//! Every name that goes into a URL (owner, repo, ref, the resolved commit) is
//! checked against GitHub's charset first. Requests go through the normal
//! HTTP client ([`crate::cli::egress_proxy::client`]), so a device or broker
//! proxy is honoured. The network calls sit behind [`GitHubApi`] so tests use
//! a fake and never reach GitHub.

use std::time::Duration;

use super::{tar, GitHubSpec, ServiceSource, SourceFiles, MAX_TARBALL_BYTES};

/// A GitHub owner (user or organization): 1 to 39 letters, digits or
/// hyphens, not starting or ending with a hyphen.
pub fn check_owner(s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.len() <= 39
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "'{}' is not a GitHub owner name",
            crate::util::terminal_safe(s)
        ))
    }
}

/// A GitHub repository name: 1 to 100 of letters, digits, `.`, `_`, `-`,
/// not `.` or `..`.
pub fn check_repo(s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "'{}' is not a GitHub repository name",
            crate::util::terminal_safe(s)
        ))
    }
}

/// A branch, tag or commit: git's ref-name rules restricted to the URL-safe
/// set (letters, digits, `.`, `_`, `-`, `/`), so it can go into a URL path
/// as is.
pub fn check_ref(s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.len() <= 255
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        && !s.starts_with(['-', '/', '.'])
        && !s.ends_with(['/', '.'])
        && !s.ends_with(".lock")
        && !s.contains("..")
        && !s.contains("//")
        && !s.contains("/.");
    if ok {
        Ok(())
    } else {
        Err(format!(
            "'{}' is not a branch, tag or commit name",
            crate::util::terminal_safe(s)
        ))
    }
}

/// A full commit id: 40 lowercase hex digits.
pub fn is_full_commit(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// Why a GitHub read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// GitHub was not reached or failed on its side: a transport error, a
    /// timeout, a 5xx. Says nothing about the source.
    Unreachable(String),
    /// GitHub answered: the repository, ref or commit is not there (404,
    /// 422), the request was refused (401, 403, 429), or the download is too
    /// large. A definitive answer.
    Answered(String),
}

impl FetchError {
    pub fn message(&self) -> &str {
        match self {
            FetchError::Unreachable(m) | FetchError::Answered(m) => m,
        }
    }
}

impl From<FetchError> for String {
    fn from(e: FetchError) -> String {
        match e {
            FetchError::Unreachable(m) | FetchError::Answered(m) => m,
        }
    }
}

/// The three GitHub reads a source needs. [`GitHubHttp`] is the real one.
#[allow(async_fn_in_trait)]
pub trait GitHubApi {
    /// The repository's default branch.
    async fn default_branch(&self, owner: &str, repo: &str) -> Result<String, FetchError>;
    /// The full commit a branch, tag or (short or full) commit resolves to.
    async fn commit_of(&self, owner: &str, repo: &str, git_ref: &str)
        -> Result<String, FetchError>;
    /// The `tar.gz` of the repository at `commit`, at most
    /// [`MAX_TARBALL_BYTES`].
    async fn tarball(&self, owner: &str, repo: &str, commit: &str) -> Result<Vec<u8>, FetchError>;
}

/// Fetch a GitHub source: resolve `git_ref` (absent: the default branch) to a
/// full commit, fetch that commit's tarball and read the source out of it.
/// Returns the files and the source record pinning the commit.
pub async fn fetch<A: GitHubApi>(
    api: &A,
    spec: &GitHubSpec,
    git_ref: Option<&str>,
) -> Result<(SourceFiles, ServiceSource), Vec<String>> {
    check_owner(&spec.owner).map_err(|e| vec![e])?;
    check_repo(&spec.repo).map_err(|e| vec![e])?;
    if let Some(p) = &spec.path {
        super::check_sub_path(p).map_err(|e| vec![e])?;
    }
    let target = match git_ref {
        Some(r) => {
            check_ref(r).map_err(|e| vec![e])?;
            r.to_string()
        }
        None => {
            let b = api
                .default_branch(&spec.owner, &spec.repo)
                .await
                .map_err(|e| vec![e.into()])?;
            check_ref(&b)
                .map_err(|_| vec!["GitHub returned an unusable default branch name".to_string()])?;
            b
        }
    };
    let commit = api
        .commit_of(&spec.owner, &spec.repo, &target)
        .await
        .map_err(|e| vec![e.into()])?
        .trim()
        .to_ascii_lowercase();
    if !is_full_commit(&commit) {
        return Err(vec!["GitHub did not return a full commit id".into()]);
    }
    let gz = api
        .tarball(&spec.owner, &spec.repo, &commit)
        .await
        .map_err(|e| vec![e.into()])?;
    let files = tar::read_tarball(&gz, spec.path.as_deref())?;
    Ok((
        files,
        ServiceSource::Github {
            repo: format!("{}/{}", spec.owner, spec.repo),
            path: spec.path.clone(),
            git_ref: git_ref.map(str::to_string),
            commit,
            checked: false,
        },
    ))
}

/// Check that `defs` (service id → service.toml, policy.toml), as a request
/// carries them, are what `source` holds: a GitHub source is fetched again at
/// its pinned commit and every definition's digest compared (a single service
/// folder stored under another id through `--id` is compared after the same
/// rename). `Ok(Fetched)` when they match. `Err` when they do not, when the
/// commit does not hold a source, or when GitHub gives a definitive answer
/// ([`FetchError::Answered`]: not found, refused, too large). `Ok(NotReached)`
/// only when GitHub was not reached ([`FetchError::Unreachable`]: a transport
/// error, a timeout, a 5xx), and `Ok(LocalFolder)` for a local folder: neither
/// can be checked here, and the card says so.
pub async fn verify<A: GitHubApi>(
    api: &A,
    source: &ServiceSource,
    defs: &std::collections::BTreeMap<String, (String, Option<String>)>,
) -> Result<super::card::SourceCheck, String> {
    use super::card::SourceCheck;
    use super::definition_digest;
    let ServiceSource::Github {
        repo, path, commit, ..
    } = source
    else {
        return Ok(SourceCheck::LocalFolder);
    };
    let (owner, name) = repo
        .split_once('/')
        .ok_or("source repo must be owner/repo")?;
    check_owner(owner)?;
    check_repo(name)?;
    if !is_full_commit(commit) {
        return Err("source commit must be a full 40-hex commit".into());
    }
    let mismatch = || {
        format!(
            "the definitions in this request are not what {} holds; nothing was stored",
            crate::util::terminal_safe(&source.display())
        )
    };
    let gz = match api.tarball(owner, name, commit).await {
        Ok(gz) => gz,
        Err(FetchError::Unreachable(_)) => return Ok(SourceCheck::NotReached),
        Err(FetchError::Answered(e)) => {
            return Err(format!(
                "{}: {}; nothing was stored",
                crate::util::terminal_safe(&source.display()),
                e
            ))
        }
    };
    let files = tar::read_tarball(&gz, path.as_deref()).map_err(|_| mismatch())?;
    let digest = |(s, p): &(String, Option<String>)| definition_digest(s, p.as_deref());
    let matches = if files.single {
        match (files.defs.get(""), defs.iter().next()) {
            (Some((text, policy)), Some((id, carried))) if defs.len() == 1 => {
                let renamed = super::rename_service(text, id).ok();
                [Some(text.clone()), renamed]
                    .into_iter()
                    .flatten()
                    .any(|t| digest(&(t, policy.clone())) == digest(carried))
            }
            _ => false,
        }
    } else {
        files.defs.len() == defs.len()
            && files
                .defs
                .iter()
                .all(|(key, held)| defs.get(key).is_some_and(|c| digest(c) == digest(held)))
    };
    if matches {
        Ok(SourceCheck::Fetched)
    } else {
        Err(mismatch())
    }
}

/// The real [`GitHubApi`]: GitHub's REST API for refs, codeload for tarballs.
pub struct GitHubHttp {
    client: reqwest::Client,
    api: String,
    codeload: String,
}

/// Small JSON / text answers (repository metadata, a commit id).
const MAX_META_RESPONSE: usize = 1024 * 1024;

impl GitHubHttp {
    pub fn new() -> Result<Self, String> {
        let client = crate::cli::egress_proxy::client(Duration::from_secs(60))
            .map_err(|e| format!("http client: {}", e))?;
        Ok(Self {
            client,
            api: "https://api.github.com".into(),
            codeload: "https://codeload.github.com".into(),
        })
    }

    fn get(&self, url: &str, accept: &str) -> reqwest::RequestBuilder {
        self.client.get(url).header("accept", accept).header(
            "user-agent",
            concat!("safeclaw/", env!("CARGO_PKG_VERSION")),
        )
    }
}

/// The URLs a source fetch uses, built only from checked names.
pub(crate) fn repo_url(api: &str, owner: &str, repo: &str) -> String {
    format!("{}/repos/{}/{}", api, owner, repo)
}
pub(crate) fn commit_url(api: &str, owner: &str, repo: &str, git_ref: &str) -> String {
    format!("{}/repos/{}/{}/commits/{}", api, owner, repo, git_ref)
}
pub(crate) fn tarball_url(codeload: &str, owner: &str, repo: &str, commit: &str) -> String {
    format!("{}/{}/{}/tar.gz/{}", codeload, owner, repo, commit)
}

/// What a non-success status says: a 5xx is GitHub failing on its side
/// ([`FetchError::Unreachable`]); every other status is its answer
/// ([`FetchError::Answered`]).
pub(crate) fn status_problem(status: u16, what: &str) -> FetchError {
    match status {
        404 | 422 => FetchError::Answered(format!(
            "{} not found (only public repositories are supported)",
            what
        )),
        401 | 403 | 429 => FetchError::Answered(format!(
            "GitHub refused the request for {} (HTTP {}; often its rate limit), try again later",
            what, status
        )),
        s @ 500..=599 => {
            FetchError::Unreachable(format!("GitHub failed with HTTP {} for {}", s, what))
        }
        s => FetchError::Answered(format!("GitHub answered HTTP {} for {}", s, what)),
    }
}

/// A request that got no answer: a timeout or a transport error.
fn unreachable(e: reqwest::Error) -> FetchError {
    FetchError::Unreachable(format!("cannot reach GitHub: {}", e))
}

/// Read a response body, refusing one over `cap` bytes (checked against the
/// declared length first, then while reading).
async fn body_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, FetchError> {
    let too_large = || FetchError::Answered(format!("the download is larger than {} bytes", cap));
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(too_large());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FetchError::Unreachable(format!("download failed: {}", e)))?
    {
        if out.len() + chunk.len() > cap {
            return Err(too_large());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

impl GitHubApi for GitHubHttp {
    async fn default_branch(&self, owner: &str, repo: &str) -> Result<String, FetchError> {
        let what = format!("github:{}/{}", owner, repo);
        let resp = self
            .get(
                &repo_url(&self.api, owner, repo),
                "application/vnd.github+json",
            )
            .send()
            .await
            .map_err(unreachable)?;
        if !resp.status().is_success() {
            return Err(status_problem(resp.status().as_u16(), &what));
        }
        let body = body_capped(resp, MAX_META_RESPONSE).await?;
        let answered = |m: &str| FetchError::Answered(m.to_string());
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| answered("GitHub returned unreadable repository metadata"))?;
        v.get("default_branch")
            .and_then(|b| b.as_str())
            .map(str::to_string)
            .ok_or_else(|| answered("GitHub returned no default branch"))
    }

    async fn commit_of(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
    ) -> Result<String, FetchError> {
        let what = format!("ref '{}' in github:{}/{}", git_ref, owner, repo);
        let resp = self
            .get(
                &commit_url(&self.api, owner, repo, git_ref),
                "application/vnd.github.sha",
            )
            .send()
            .await
            .map_err(unreachable)?;
        if !resp.status().is_success() {
            return Err(status_problem(resp.status().as_u16(), &what));
        }
        let body = body_capped(resp, 256).await?;
        String::from_utf8(body)
            .map_err(|_| FetchError::Answered("GitHub returned an unreadable commit id".into()))
    }

    async fn tarball(&self, owner: &str, repo: &str, commit: &str) -> Result<Vec<u8>, FetchError> {
        let what = format!("github:{}/{} at {}", owner, repo, commit);
        let resp = self
            .get(
                &tarball_url(&self.codeload, owner, repo, commit),
                "application/x-gzip",
            )
            .send()
            .await
            .map_err(unreachable)?;
        if !resp.status().is_success() {
            return Err(status_problem(resp.status().as_u16(), &what));
        }
        body_capped(resp, MAX_TARBALL_BYTES).await
    }
}
