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

/// A full git object id (a commit, a tag object): 40 lowercase hex digits.
pub fn is_full_commit(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// The refs a stated ref may be among the repository's own branches and
/// tags, as `heads/<name>` / `tags/<name>`: `refs/heads/<x>` or
/// `refs/tags/<x>` is exactly that ref; any other `refs/...` is neither; a
/// bare name (hex digits included) may be either.
fn head_paths(git_ref: &str) -> Vec<String> {
    match git_ref.strip_prefix("refs/") {
        Some(rest) if rest.starts_with("heads/") || rest.starts_with("tags/") => {
            vec![rest.to_string()]
        }
        Some(_) => Vec::new(),
        None => vec![format!("heads/{}", git_ref), format!("tags/{}", git_ref)],
    }
}

/// Annotated tags peeled in a row before a ref is refused.
const MAX_TAG_DEPTH: usize = 4;

/// The commit `obj` (a ref's target) names, peeling annotated tags.
async fn peel<A: GitHubApi>(
    api: &A,
    owner: &str,
    repo: &str,
    mut obj: GitObject,
    shown: &str,
) -> Result<String, FetchError> {
    for _ in 0..=MAX_TAG_DEPTH {
        match obj {
            GitObject::Commit(c) => return Ok(c),
            GitObject::Tag(t) => obj = api.tag_target(owner, repo, &t).await?,
            GitObject::Other => break,
        }
    }
    Err(FetchError::Answered(format!(
        "'{}' in github:{}/{} does not name a commit",
        crate::util::terminal_safe(shown),
        owner,
        repo
    )))
}

/// The commit at the head of the repository's own branch or tag `git_ref`
/// names (see [`head_paths`]; an annotated tag peeled to its commit), or
/// `None` when it names no branch or tag of the repository. A bare name that
/// is a branch and a tag at different commits is refused: the requester
/// states `refs/heads/<name>` or `refs/tags/<name>`.
pub async fn ref_head<A: GitHubApi>(
    api: &A,
    owner: &str,
    repo: &str,
    git_ref: &str,
) -> Result<Option<String>, FetchError> {
    let mut heads: Vec<String> = Vec::new();
    for path in head_paths(git_ref) {
        if let Some(obj) = api.git_ref(owner, repo, &path).await? {
            let c = peel(api, owner, repo, obj, git_ref).await?;
            heads.push(c.trim().to_ascii_lowercase());
        }
    }
    heads.dedup();
    match heads.len() {
        0 => Ok(None),
        1 => Ok(heads.pop()),
        _ => {
            let r = crate::util::terminal_safe(git_ref);
            Err(FetchError::Answered(format!(
                "'{}' is both a branch and a tag of github:{}/{} at different commits; state refs/heads/{} or refs/tags/{}",
                r, owner, repo, r, r
            )))
        }
    }
}

/// Why a GitHub read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// No answer arrived: a transport error before the response, or none by
    /// the deadline. Says nothing about the source.
    Unreachable(String),
    /// An answer arrived and the read did not succeed: any non-success
    /// status (not found, refused, a server or proxy error), or a download
    /// that is too large, too slow or cut off after the answer.
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

/// A git object a ref or an annotated tag points at, as GitHub reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitObject {
    /// A commit (its full id).
    Commit(String),
    /// An annotated tag object (its full id), peeled through
    /// [`GitHubApi::tag_target`].
    Tag(String),
    /// Anything else (a tree, a blob).
    Other,
}

/// The GitHub reads a source needs. [`GitHubHttp`] is the real one.
#[allow(async_fn_in_trait)]
pub trait GitHubApi {
    /// The repository's default branch.
    async fn default_branch(&self, owner: &str, repo: &str) -> Result<String, FetchError>;
    /// The object the repository's own ref `path` (`heads/<branch>` or
    /// `tags/<tag>`, matched exactly) points at; `None` when it has no such
    /// ref.
    async fn git_ref(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<Option<GitObject>, FetchError>;
    /// The object the annotated tag object `sha` points at.
    async fn tag_target(&self, owner: &str, repo: &str, sha: &str)
        -> Result<GitObject, FetchError>;
    /// The `tar.gz` of the repository at `commit`, at most
    /// [`MAX_TARBALL_BYTES`].
    async fn tarball(&self, owner: &str, repo: &str, commit: &str) -> Result<Vec<u8>, FetchError>;
}

/// Fetch a GitHub source: resolve `git_ref` (absent: the default branch)
/// among the repository's own branches and tags ([`ref_head`]) to a full
/// commit, fetch that commit's tarball and read the source out of it. A ref
/// that is neither (a commit id, another `refs/` name) is refused
/// ([`not_branch_or_tag`]). Returns the files and the source record pinning
/// the commit.
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
    let (owner, repo) = (spec.owner.as_str(), spec.repo.as_str());
    let commit = match git_ref {
        Some(r) => {
            check_ref(r).map_err(|e| vec![e])?;
            ref_head(api, owner, repo, r)
                .await
                .map_err(|e| vec![e.into()])?
                .ok_or_else(|| vec![not_branch_or_tag(r, owner, repo)])?
        }
        None => {
            let b = api
                .default_branch(owner, repo)
                .await
                .map_err(|e| vec![e.into()])?;
            check_ref(&b)
                .map_err(|_| vec!["GitHub returned an unusable default branch name".to_string()])?;
            ref_head(api, owner, repo, &format!("refs/heads/{}", b))
                .await
                .map_err(|e| vec![e.into()])?
                .ok_or_else(|| vec!["GitHub has no commit for the default branch".to_string()])?
        }
    }
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
        },
    ))
}

/// Why a ref that names no branch or tag of the repository is refused.
pub fn not_branch_or_tag(git_ref: &str, owner: &str, repo: &str) -> String {
    format!(
        "'{}' is not a branch or tag of github:{}/{}; a GitHub source is added from a branch or tag",
        crate::util::terminal_safe(git_ref),
        owner,
        repo
    )
}

/// Check that `defs` (service id → service.toml, policy.toml), as a request
/// carries them, are what `source` holds. A GitHub source is checked only at
/// the head of one of the repository's own branches or tags: its stated ref
/// (absent: the default branch) is resolved under `refs/heads/` or
/// `refs/tags/` ([`ref_head`], an annotated tag peeled to its commit) and
/// must point at the pinned commit; that commit is fetched again and every
/// definition's digest compared (a single service folder stored under
/// another id through `--id` is compared after the same rename).
/// `Ok` when all of it holds. `Err` when it does not, when the commit does
/// not hold a source, when the ref is no branch or tag of the repository (a
/// commit id, any other ref), or when GitHub does not answer with the data.
/// A local folder is only ever read by the requester: `Ok`.
pub async fn verify<A: GitHubApi>(
    api: &A,
    source: &ServiceSource,
    defs: &std::collections::BTreeMap<String, (String, Option<String>)>,
) -> Result<(), String> {
    use super::definition_digest;
    let ServiceSource::Github {
        repo,
        path,
        git_ref,
        commit,
        ..
    } = source
    else {
        return Ok(());
    };
    let (owner, name) = repo
        .split_once('/')
        .ok_or("source repo must be owner/repo")?;
    check_owner(owner)?;
    check_repo(name)?;
    if !is_full_commit(commit) {
        return Err("source commit must be a full 40-hex commit".into());
    }
    let shown = crate::util::terminal_safe(&source.display()).into_owned();
    let refused = |e: &str| format!("{}: {}; nothing was stored", shown, e);
    let silent = || refused("GitHub did not respond");
    let mismatch = || {
        format!(
            "the definitions in this request are not what {} holds; nothing was stored",
            shown
        )
    };
    // The head of the ref, among the repository's own branches and tags, at
    // the time of the check.
    let target = match git_ref {
        Some(r) => {
            check_ref(r)?;
            r.clone()
        }
        None => match api.default_branch(owner, name).await {
            Ok(b) => {
                check_ref(&b)
                    .map_err(|_| refused("GitHub returned an unusable default branch name"))?;
                format!("refs/heads/{}", b)
            }
            Err(FetchError::Unreachable(_)) => return Err(silent()),
            Err(FetchError::Answered(e)) => return Err(refused(&e)),
        },
    };
    let head = match ref_head(api, owner, name, &target).await {
        Ok(Some(h)) => h,
        Ok(None) if git_ref.is_some() => {
            return Err(format!(
                "{}; nothing was stored",
                not_branch_or_tag(&target, owner, name)
            ))
        }
        Ok(None) => return Err(refused("GitHub has no commit for the default branch")),
        Err(FetchError::Unreachable(_)) => return Err(silent()),
        Err(FetchError::Answered(e)) => return Err(refused(&e)),
    };
    if !is_full_commit(&head) {
        return Err(refused("GitHub did not return a full commit id"));
    }
    if head != *commit {
        return Err(refused(&format!(
            "{} is at {}, not at the pinned commit",
            source.ref_label(),
            head
        )));
    }
    let gz = match api.tarball(owner, name, commit).await {
        Ok(gz) => gz,
        Err(FetchError::Unreachable(_)) => return Err(silent()),
        Err(FetchError::Answered(e)) => return Err(refused(&e)),
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
        Ok(())
    } else {
        Err(mismatch())
    }
}

/// The real [`GitHubApi`]: GitHub's REST API for refs, codeload for tarballs.
pub struct GitHubHttp {
    client: reqwest::Client,
    api: String,
    codeload: String,
    /// When set, every read must be answered by then: no response by the
    /// deadline is [`FetchError::Unreachable`]; a response whose body is not
    /// read by then is [`FetchError::Answered`] (too large or too slow).
    deadline: Option<tokio::time::Instant>,
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
            deadline: None,
        })
    }

    /// Every read must be answered by `deadline` (see [`Self::deadline`]).
    pub fn answering_by(mut self, deadline: tokio::time::Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Send a request and take any status: no response (a transport error,
    /// or none by the deadline) is [`FetchError::Unreachable`]; a proxy's
    /// refusal to open the connection is its answer ([`no_response`]).
    async fn send_any(
        &self,
        req: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<reqwest::Response, FetchError> {
        let sent = req.send();
        let resp = match self.deadline {
            Some(d) => tokio::time::timeout_at(d, sent).await.map_err(|_| {
                FetchError::Unreachable(format!("GitHub did not answer in time for {}", what))
            })?,
            None => sent.await,
        };
        resp.map_err(|e| no_response(&e, what))
    }

    /// [`Self::send_any`], a non-success status refused ([`status_problem`]).
    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        what: &str,
    ) -> Result<reqwest::Response, FetchError> {
        let resp = self.send_any(req, what).await?;
        if !resp.status().is_success() {
            return Err(status_problem(resp.status().as_u16(), what));
        }
        Ok(resp)
    }

    /// Read an answered response's body, at most `cap` bytes, by the
    /// deadline: anything else is [`FetchError::Answered`].
    async fn read(
        &self,
        resp: reqwest::Response,
        cap: usize,
        what: &str,
    ) -> Result<Vec<u8>, FetchError> {
        let read = body_capped(resp, cap, what);
        match self.deadline {
            Some(d) => tokio::time::timeout_at(d, read)
                .await
                .map_err(|_| too_large_or_slow(what))?,
            None => read.await,
        }
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
pub(crate) fn git_ref_url(api: &str, owner: &str, repo: &str, path: &str) -> String {
    format!("{}/repos/{}/{}/git/ref/{}", api, owner, repo, path)
}
pub(crate) fn git_tag_url(api: &str, owner: &str, repo: &str, sha: &str) -> String {
    format!("{}/repos/{}/{}/git/tags/{}", api, owner, repo, sha)
}
pub(crate) fn tarball_url(codeload: &str, owner: &str, repo: &str, commit: &str) -> String {
    format!("{}/{}/{}/tar.gz/{}", codeload, owner, repo, commit)
}

/// What a non-success status says. Every status is an answer
/// ([`FetchError::Answered`]); a request timeout (408) is not GitHub's answer
/// about the repository, and says so. (Every source URL is HTTPS: a proxy
/// answers inside its tunnel setup, see [`no_response`].)
pub(crate) fn status_problem(status: u16, what: &str) -> FetchError {
    FetchError::Answered(match status {
        404 | 422 => format!(
            "{} not found (only public repositories are supported)",
            what
        ),
        401 | 403 | 429 => format!(
            "GitHub refused the request for {} (HTTP {}; often its rate limit), try again later",
            what, status
        ),
        408 => format!(
            "the request for {} timed out before GitHub read it (HTTP 408), try again later",
            what
        ),
        s @ 500..=599 => format!(
            "GitHub failed with HTTP {} for {}, try again later",
            s, what
        ),
        s => format!("GitHub answered HTTP {} for {}", s, what),
    })
}

/// A request that got no response. A proxy that refused to open the
/// connection to GitHub answered, with its own refusal
/// ([`FetchError::Answered`], said as the proxy's); anything else (no route,
/// a reset, TLS) is no answer ([`FetchError::Unreachable`]).
fn no_response(e: &reqwest::Error, what: &str) -> FetchError {
    match proxy_refusal(e) {
        Some(why) => FetchError::Answered(format!(
            "the proxy between this device and GitHub refused the connection for {} ({}); check the proxy (`sc proxy`)",
            what, why
        )),
        None => FetchError::Unreachable(format!("cannot reach GitHub: {}", e)),
    }
}

/// Why a proxy refused to open a tunnel, read from the HTTP client's tunnel
/// error (its type is not exported; its text is stable and tested below).
fn proxy_refusal(e: &(dyn std::error::Error + 'static)) -> Option<&'static str> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        match err.to_string().as_str() {
            "tunnel error: proxy authorization required" => {
                return Some("it requires proxy authentication")
            }
            "tunnel error: unsuccessful" => return Some("it answered the tunnel request with a refusal"),
            "tunnel error: proxy response headers too long" => {
                return Some("its answer to the tunnel request was unreadable")
            }
            _ => {}
        }
        cur = err.source();
    }
    None
}

/// A ref's or a tag's target object as GitHub's git database reports it
/// (`{sha, type}`): its id must be a full object id.
fn git_object(v: Option<&serde_json::Value>) -> Result<GitObject, FetchError> {
    let o = v.ok_or_else(|| FetchError::Answered("GitHub returned a ref without its object".into()))?;
    let sha = o
        .get("sha")
        .and_then(|s| s.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| is_full_commit(s))
        .ok_or_else(|| FetchError::Answered("GitHub returned an unreadable object id".into()))?;
    Ok(match o.get("type").and_then(|t| t.as_str()) {
        Some("commit") => GitObject::Commit(sha),
        Some("tag") => GitObject::Tag(sha),
        _ => GitObject::Other,
    })
}

/// An answered download that cannot be read in full: too large or too slow.
fn too_large_or_slow(what: &str) -> FetchError {
    FetchError::Answered(format!(
        "could not verify {}: the download is too large or too slow",
        what
    ))
}

/// Read an answered response's body, refusing one over `cap` bytes (by its
/// declared length before reading, when it has one, then while reading) or
/// cut off.
async fn body_capped(
    mut resp: reqwest::Response,
    cap: usize,
    what: &str,
) -> Result<Vec<u8>, FetchError> {
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(too_large_or_slow(what));
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        FetchError::Answered(format!(
            "the download of {} broke off after GitHub answered: {}",
            what, e
        ))
    })? {
        if out.len() + chunk.len() > cap {
            return Err(too_large_or_slow(what));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

impl GitHubApi for GitHubHttp {
    async fn default_branch(&self, owner: &str, repo: &str) -> Result<String, FetchError> {
        let what = format!("github:{}/{}", owner, repo);
        let req = self.get(
            &repo_url(&self.api, owner, repo),
            "application/vnd.github+json",
        );
        let resp = self.send(req, &what).await?;
        let body = self.read(resp, MAX_META_RESPONSE, &what).await?;
        let answered = |m: &str| FetchError::Answered(m.to_string());
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| answered("GitHub returned unreadable repository metadata"))?;
        v.get("default_branch")
            .and_then(|b| b.as_str())
            .map(str::to_string)
            .ok_or_else(|| answered("GitHub returned no default branch"))
    }

    async fn git_ref(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<Option<GitObject>, FetchError> {
        let what = format!("ref '{}' in github:{}/{}", path, owner, repo);
        let req = self.get(
            &git_ref_url(&self.api, owner, repo, path),
            "application/vnd.github+json",
        );
        let resp = self.send_any(req, &what).await?;
        match resp.status().as_u16() {
            404 => return Ok(None),
            s if !(200..300).contains(&s) => return Err(status_problem(s, &what)),
            _ => {}
        }
        let body = self.read(resp, MAX_META_RESPONSE, &what).await?;
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| FetchError::Answered("GitHub returned an unreadable ref".into()))?;
        // Only the exact ref counts (never a list of refs it prefixes).
        if v.get("ref").and_then(|r| r.as_str()) != Some(format!("refs/{}", path).as_str()) {
            return Ok(None);
        }
        git_object(v.get("object")).map(Some)
    }

    async fn tag_target(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> Result<GitObject, FetchError> {
        if !is_full_commit(sha) {
            return Err(FetchError::Answered(
                "GitHub returned an unreadable object id".into(),
            ));
        }
        let what = format!("tag object {} in github:{}/{}", sha, owner, repo);
        let req = self.get(
            &git_tag_url(&self.api, owner, repo, sha),
            "application/vnd.github+json",
        );
        let resp = self.send(req, &what).await?;
        let body = self.read(resp, MAX_META_RESPONSE, &what).await?;
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| FetchError::Answered("GitHub returned an unreadable tag".into()))?;
        git_object(v.get("object"))
    }

    async fn tarball(&self, owner: &str, repo: &str, commit: &str) -> Result<Vec<u8>, FetchError> {
        let what = format!("github:{}/{} at {}", owner, repo, commit);
        let req = self.get(
            &tarball_url(&self.codeload, owner, repo, commit),
            "application/x-gzip",
        );
        let resp = self.send(req, &what).await?;
        self.read(resp, MAX_TARBALL_BYTES, &what).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stand-in for GitHub on 127.0.0.1: for every connection it reads the
    /// request, writes `reply` (nothing: no answer), then holds the
    /// connection open. Returns its base URL.
    async fn stand_in(reply: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(&reply).await;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });
        base
    }

    /// A reader at `base` whose every read must be answered within `within`.
    fn reader(base: &str, within: Duration) -> GitHubHttp {
        GitHubHttp {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            api: base.into(),
            codeload: base.into(),
            deadline: None,
        }
        .answering_by(tokio::time::Instant::now() + within)
    }

    /// Once GitHub has answered, a download not read in full by the deadline,
    /// or declared larger than the cap, is an answer that refuses (too large
    /// or too slow), never "not reached"; only no answer at all is.
    #[test]
    fn a_slow_or_oversize_answer_refuses_and_only_silence_is_unreachable() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let commit = "a".repeat(40);
            let within = Duration::from_millis(400);
            // Headers, then a body that never completes.
            let slow =
                stand_in(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial".to_vec()).await;
            let e = reader(&slow, within)
                .tarball("acme", "tools", &commit)
                .await
                .unwrap_err();
            assert!(
                matches!(&e, FetchError::Answered(m) if m.contains("too large or too slow")),
                "{e:?}"
            );
            // Declared larger than the cap: refused at once, before the deadline.
            let big = stand_in(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    MAX_TARBALL_BYTES + 1
                )
                .into_bytes(),
            )
            .await;
            let started = tokio::time::Instant::now();
            let e = reader(&big, Duration::from_secs(20))
                .tarball("acme", "tools", &commit)
                .await
                .unwrap_err();
            assert!(
                matches!(&e, FetchError::Answered(m) if m.contains("too large or too slow")),
                "{e:?}"
            );
            assert!(started.elapsed() < Duration::from_secs(5));
            // No answer at all: not reached.
            let silent = stand_in(Vec::new()).await;
            let e = reader(&silent, within)
                .default_branch("acme", "tools")
                .await
                .unwrap_err();
            assert!(matches!(e, FetchError::Unreachable(_)), "{e:?}");
            // A status is an answer.
            let gone =
                stand_in(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec())
                    .await;
            let e = reader(&gone, within)
                .default_branch("acme", "tools")
                .await
                .unwrap_err();
            assert!(matches!(e, FetchError::Answered(_)), "{e:?}");
        });
    }

    /// A request timeout (408) is not GitHub's answer about the repository:
    /// its message says what it is. Every status is an answer.
    #[test]
    fn request_timeout_status_says_what_it_is() {
        let m = |s| status_problem(s, "github:acme/tools").message().to_string();
        assert!(
            m(408).contains("timed out") && !m(408).contains("refused"),
            "{}",
            m(408)
        );
        assert!(m(404).contains("not found"));
        for s in [407u16, 408, 404, 500] {
            assert!(matches!(status_problem(s, "x"), FetchError::Answered(_)));
        }
    }

    /// A reader of `https://api.github.com` through the proxy at `proxy`.
    fn via_proxy(proxy: &str) -> GitHubHttp {
        GitHubHttp {
            client: reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(proxy).unwrap())
                .build()
                .unwrap(),
            api: "https://api.github.com".into(),
            codeload: "https://codeload.github.com".into(),
            deadline: None,
        }
        .answering_by(tokio::time::Instant::now() + Duration::from_secs(5))
    }

    /// A proxy that refuses to open the HTTPS tunnel answered: its refusal
    /// is said as the proxy's (never as GitHub not answering) and refuses.
    /// A proxy that closes without an answer is no answer.
    #[test]
    fn a_proxy_refusing_the_tunnel_is_its_own_answer() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for (reply, why) in [
                (
                    &b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"[..],
                    "requires proxy authentication",
                ),
                (
                    &b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"[..],
                    "refusal",
                ),
            ] {
                let proxy = stand_in(reply.to_vec()).await;
                let e = via_proxy(&proxy)
                    .default_branch("acme", "tools")
                    .await
                    .unwrap_err();
                assert!(
                    matches!(&e, FetchError::Answered(m) if m.contains("the proxy between this device and GitHub refused") && m.contains(why) && !m.contains("did not answer")),
                    "{e:?}"
                );
            }
            // Closed without an answer: not reached.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    drop(sock);
                }
            });
            let e = via_proxy(&proxy)
                .default_branch("acme", "tools")
                .await
                .unwrap_err();
            assert!(matches!(e, FetchError::Unreachable(_)), "{e:?}");
        });
    }

    /// A ref read from GitHub's git database: only the exact ref counts, its
    /// object id must be a full id, and a missing ref is `None`.
    #[test]
    fn a_ref_is_read_exactly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sha = "b".repeat(40);
            let reply = |body: String| {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .into_bytes()
            };
            let exact = stand_in(reply(format!(
                r#"{{"ref":"refs/tags/v1","object":{{"sha":"{}","type":"tag"}}}}"#,
                sha
            )))
            .await;
            let within = Duration::from_secs(5);
            assert_eq!(
                reader(&exact, within).git_ref("acme", "tools", "tags/v1").await,
                Ok(Some(GitObject::Tag(sha.clone())))
            );
            // Another ref than the one asked for: none.
            assert_eq!(
                reader(&exact, within).git_ref("acme", "tools", "heads/v1").await,
                Ok(None)
            );
            let gone = stand_in(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
            assert_eq!(
                reader(&gone, within).git_ref("acme", "tools", "heads/main").await,
                Ok(None)
            );
            let short = stand_in(reply(
                r#"{"ref":"refs/heads/main","object":{"sha":"abc","type":"commit"}}"#.into(),
            ))
            .await;
            assert!(matches!(
                reader(&short, within).git_ref("acme", "tools", "heads/main").await,
                Err(FetchError::Answered(_))
            ));
            // A tag object's id is checked before it goes into a URL.
            assert!(matches!(
                reader(&exact, within).tag_target("acme", "tools", "../x").await,
                Err(FetchError::Answered(_))
            ));
        });
    }
}
