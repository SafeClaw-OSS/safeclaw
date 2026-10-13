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

/// A ref that names a commit (hex digits only, a full or short commit id)
/// rather than a branch or tag.
pub fn is_commit_ref(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
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
/// carries them, are what `source` holds. A GitHub source is pinned at the
/// head of a branch or tag: its stated ref (absent: the default branch) is
/// resolved and must point at the pinned commit (GitHub serves a commit that
/// exists only in a fork through the parent repository's URLs, so a commit is
/// the repository's only as the head of one of its refs); that commit is
/// fetched again and every definition's digest compared (a single service
/// folder stored under another id through `--id` is compared after the same
/// rename). `Ok(Fetched)` when all of it holds. `Err` when it does not, when
/// the commit does not hold a source, or when GitHub answers without the
/// data ([`FetchError::Answered`]). `Ok(NotReached)` only when no answer
/// arrived ([`FetchError::Unreachable`]), `Ok(CommitRef)` for a ref that is a
/// commit id, and `Ok(LocalFolder)` for a local folder: none can be checked
/// here, and the card says so.
pub async fn verify<A: GitHubApi>(
    api: &A,
    source: &ServiceSource,
    defs: &std::collections::BTreeMap<String, (String, Option<String>)>,
) -> Result<super::card::SourceCheck, String> {
    use super::card::SourceCheck;
    use super::definition_digest;
    let ServiceSource::Github {
        repo,
        path,
        git_ref,
        commit,
        ..
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
    let shown = crate::util::terminal_safe(&source.display()).into_owned();
    let refused = |e: &str| format!("{}: {}; nothing was stored", shown, e);
    let mismatch = || {
        format!(
            "the definitions in this request are not what {} holds; nothing was stored",
            shown
        )
    };
    // The ref's head at the time of the check.
    let target = match git_ref {
        Some(r) if is_commit_ref(r) => return Ok(SourceCheck::CommitRef),
        Some(r) => {
            check_ref(r)?;
            r.clone()
        }
        None => match api.default_branch(owner, name).await {
            Ok(b) => {
                check_ref(&b)
                    .map_err(|_| refused("GitHub returned an unusable default branch name"))?;
                b
            }
            Err(FetchError::Unreachable(_)) => return Ok(SourceCheck::NotReached),
            Err(FetchError::Answered(e)) => return Err(refused(&e)),
        },
    };
    let head = match api.commit_of(owner, name, &target).await {
        Ok(h) => h.trim().to_ascii_lowercase(),
        Err(FetchError::Unreachable(_)) => return Ok(SourceCheck::NotReached),
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
        Err(FetchError::Unreachable(_)) => return Ok(SourceCheck::NotReached),
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

    /// Send a request: no response (a transport error, or none by the
    /// deadline) is [`FetchError::Unreachable`].
    async fn send(
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
        let resp = resp.map_err(unreachable)?;
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
pub(crate) fn commit_url(api: &str, owner: &str, repo: &str, git_ref: &str) -> String {
    format!("{}/repos/{}/{}/commits/{}", api, owner, repo, git_ref)
}
pub(crate) fn tarball_url(codeload: &str, owner: &str, repo: &str, commit: &str) -> String {
    format!("{}/{}/{}/tar.gz/{}", codeload, owner, repo, commit)
}

/// What a non-success status says. Every status is an answer
/// ([`FetchError::Answered`]); a proxy's (407) or a request timeout (408) is
/// not GitHub's answer about the repository, and says so.
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
        407 => format!(
            "the proxy between this device and GitHub refused the request for {} (HTTP 407: proxy authentication required)",
            what
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

/// A request that got no answer: a transport error before the response.
fn unreachable(e: reqwest::Error) -> FetchError {
    FetchError::Unreachable(format!("cannot reach GitHub: {}", e))
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

    async fn commit_of(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
    ) -> Result<String, FetchError> {
        let what = format!("ref '{}' in github:{}/{}", git_ref, owner, repo);
        let req = self.get(
            &commit_url(&self.api, owner, repo, git_ref),
            "application/vnd.github.sha",
        );
        let resp = self.send(req, &what).await?;
        let body = self.read(resp, 256, &what).await?;
        String::from_utf8(body)
            .map_err(|_| FetchError::Answered("GitHub returned an unreadable commit id".into()))
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
                .commit_of("acme", "tools", "main")
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

    /// 407 and 408 are not GitHub's answer about the repository: their
    /// messages say what they are.
    #[test]
    fn proxy_and_request_timeout_statuses_say_what_they_are() {
        let m = |s| status_problem(s, "github:acme/tools").message().to_string();
        assert!(
            m(407).contains("proxy") && !m(407).contains("not found"),
            "{}",
            m(407)
        );
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
}
