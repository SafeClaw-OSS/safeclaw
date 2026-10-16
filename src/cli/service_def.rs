//! `sc service add | update | ls | rm | validate`: service definitions in the
//! active vault, added from sources (a local folder, or a GitHub repository
//! pinned to a commit). See [`crate::service::source`] for what a source is
//! and how it is read; every definition goes through the same gate the
//! daemon re-runs when it stores and loads it.
//!
//! Every human-readable line here that carries definition-derived text goes
//! through `util::terminal_safe` (definitions and sources are untrusted input).

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cli::active::resolve_active;
use crate::cli::approve::{act_result, approve_op, ApproveOpts};
use crate::cli::webauthn::now_unix;
use crate::config::{
    ServiceAddArgs, ServiceLsArgs, ServiceRmArgs, ServiceUpdateArgs, ServiceValidateArgs,
};
use crate::service::source::card::{diff, summarize, DefSummary};
use crate::service::source::{
    self, definition_digest, github, parse_source, Admitted, ServiceSource, SourceSpec,
};
use crate::service::ServiceRegistry;
use crate::util::terminal_safe;

fn safe(s: &str) -> String {
    terminal_safe(s).into_owned()
}

/// Print a list of problems under a heading and turn them into the error.
fn report(what: &str, problems: Vec<String>) -> String {
    eprintln!("{}", safe(&source::problems_text(what, &problems)));
    format!("{}: see the problems above", safe(what))
}

// ── Loading a source ─────────────────────────────────────────────────────────

/// A source read and admitted: its record (with the pinned commit) and its
/// definitions.
struct Loaded {
    source: ServiceSource,
    /// A single service folder (only such a source can be renamed).
    single: bool,
    admitted: Vec<Admitted>,
}

/// Read `spec` (fetching a GitHub source) and admit every definition. `rename`
/// is `--id`.
async fn load(
    spec: &SourceSpec,
    git_ref: Option<&str>,
    rename: Option<&str>,
    reg: &ServiceRegistry,
) -> Result<Loaded, Vec<String>> {
    let (files, source) = read(spec, git_ref, reg).await?;
    admit(files, source, rename)
}

/// Admit what [`read`] returned (`rename` is `--id`).
fn admit(
    files: source::SourceFiles,
    source: ServiceSource,
    rename: Option<&str>,
) -> Result<Loaded, Vec<String>> {
    let admitted = source::admit_files(&files, rename)?;
    Ok(Loaded {
        source,
        single: files.single,
        admitted,
    })
}

/// Read `spec`'s files (fetching a GitHub source once, at one pinned commit).
async fn read(
    spec: &SourceSpec,
    git_ref: Option<&str>,
    reg: &ServiceRegistry,
) -> Result<(source::SourceFiles, ServiceSource), Vec<String>> {
    Ok(match spec {
        SourceSpec::Local(path) => {
            if git_ref.is_some() {
                return Err(vec!["--ref applies only to a GitHub source".into()]);
            }
            let name = std::fs::canonicalize(path)
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .ok_or_else(|| vec![format!("{}: not a folder", safe(&path.display().to_string()))])?;
            let src = ServiceSource::Local { name };
            src.check().map_err(|e| vec![e])?;
            (source::read_local(path)?, src)
        }
        SourceSpec::GitHub(gh) => {
            let api = github::GitHubHttp::new().map_err(|e| vec![e])?;
            github::fetch(&api, gh, git_ref).await?
        }
        SourceSpec::Registry { .. } => {
            return Err(vec![
                "the service registry is not open yet; add a GitHub source (github:owner/repo) or a local folder (./path)".into(),
            ])
        }
        SourceSpec::Name(n) => {
            return Err(vec![if reg.get(n).is_some() {
                format!(
                    "'{}' is already built in; connect it with `sc connection add <id> --service {}`",
                    safe(n),
                    safe(n)
                )
            } else {
                format!(
                    "no built-in service '{}'; a source is ./path or github:owner/repo",
                    safe(n)
                )
            }])
        }
    })
}

/// The ids of `loaded` that are built-in services (refused by the daemon too).
fn built_in_problems(loaded: &Loaded, reg: &ServiceRegistry) -> Vec<String> {
    loaded
        .admitted
        .iter()
        .filter(|a| reg.get(&a.id).is_some())
        .map(|a| {
            format!(
                "'{}' is a built-in service id; store it under another id with --id",
                safe(&a.id)
            )
        })
        .collect()
}

/// Print what a loaded source holds: each service, where its credentials may
/// go, the rules it applies, and the parts of its policy a vault does not apply.
fn print_loaded(loaded: &Loaded) {
    println!("Source: {}", safe(&loaded.source.display()));
    for a in &loaded.admitted {
        let s = summarize(&a.def);
        println!("  {}", safe(&a.id));
        println!(
            "    sends credentials to: {}",
            safe(&s.destinations.join(", "))
        );
        if s.pkce_off {
            println!("    PKCE: off");
        }
        for r in &s.rules {
            println!("    rule: {}", safe(&r.text));
        }
        let (_, notes) = a.def.clone().for_vault();
        for n in &notes {
            println!("    note: {}", safe(n));
        }
    }
}

// ── The daemon's listing ─────────────────────────────────────────────────────

/// One row of `GET /v/{vid}/services`.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct Listed {
    id: String,
    #[serde(default)]
    source: Option<ServiceSource>,
    valid: bool,
    #[serde(default)]
    problems: Vec<String>,
    #[serde(default)]
    connections: Vec<String>,
    #[serde(default)]
    summary: Option<DefSummary>,
    #[serde(default)]
    digest: Option<String>,
}

/// What `sc service ls` says of a locked vault.
const LOCKED: &str = "the vault is locked; run `sc unlock` first";

/// The vault's definitions.
async fn listing(custodian: &str, vault: &str) -> Result<Vec<Listed>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let url = format!(
        "{}/v/{}/services",
        custodian.trim_end_matches('/'),
        urlencoding::encode(vault)
    );
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("cannot reach the daemon: {}", e))?;
    match resp.status().as_u16() {
        200 => {}
        423 => return Err(LOCKED.into()),
        s => return Err(format!("the daemon answered HTTP {}", s)),
    }
    let body: Value = resp.json().await.map_err(|e| format!("parse: {}", e))?;
    serde_json::from_value(body.get("services").cloned().unwrap_or(json!([])))
        .map_err(|e| format!("parse: {}", e))
}

/// The heading a stored source groups under: the source's display (one
/// group per source and commit), or `added before sources`.
fn group_of(l: &Listed) -> (String, String) {
    match &l.source {
        Some(s) => {
            let head = s.display();
            (format!("{}\n{}", s.identity(), head), head)
        }
        None => (String::new(), "added before sources".into()),
    }
}

// ── add ──────────────────────────────────────────────────────────────────────

fn opts(no_browser: bool, cb_port: Option<u16>, timeout: u64) -> ApproveOpts {
    ApproveOpts {
        no_browser,
        cb_port,
        timeout,
        return_after_remote_link: false,
    }
}

/// Create the `service-add` op for `loaded` and wait for its approval.
async fn submit(
    custodian: &str,
    vault: &str,
    loaded: &Loaded,
    update: bool,
    opts: &ApproveOpts,
) -> Result<Value, String> {
    let identity = loaded.source.identity();
    let op = source::add_op(vault, &loaded.source, &loaded.admitted, now_unix());
    let label = if update {
        format!("Update services from {}", identity)
    } else {
        format!("Add services from {}", identity)
    };
    let body = approve_op(custodian, vault, &op, &label, opts).await?;
    Ok(act_result(&body))
}

fn ids_of(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub async fn run_add(args: ServiceAddArgs) -> Result<(), String> {
    let spec = parse_source(&args.source)?;
    let reg = ServiceRegistry::load();
    let loaded = load(&spec, args.git_ref.as_deref(), args.id.as_deref(), &reg)
        .await
        .map_err(|p| report(&args.source, p))?;
    let clash = built_in_problems(&loaded, &reg);
    if !clash.is_empty() {
        return Err(report(&args.source, clash));
    }
    let (custodian, vault) = resolve_active(None)?;
    // Installing a source the vault holds would update it; `add` says so
    // instead (the daemon's card would show the update either way).
    let identity = loaded.source.identity();
    let stored = listing(&custodian, &vault).await?;
    if stored
        .iter()
        .any(|l| l.source.as_ref().is_some_and(|s| s.identity() == identity))
    {
        return Err(format!(
            "{} is already added; run `sc service update {}`",
            safe(&identity),
            safe(&identity)
        ));
    }
    print_loaded(&loaded);
    let result = submit(
        &custodian,
        &vault,
        &loaded,
        false,
        &opts(args.no_browser, args.cb_port, args.timeout),
    )
    .await?;
    println!("stored: {}", safe(&ids_of(&result, "ids").join(", ")));
    Ok(())
}

// ── update ───────────────────────────────────────────────────────────────────

/// What one stored source is updated from.
enum Target {
    GitHub(source::GitHubSpec),
    Local(std::path::PathBuf),
}

/// The stored sources `args` names: `(identity, how to re-read it)`.
fn update_targets(
    args: &ServiceUpdateArgs,
    stored: &[Listed],
) -> Result<Vec<(String, Target)>, String> {
    let github_target = |s: &ServiceSource| -> Option<Target> {
        match s {
            ServiceSource::Github { repo, path, .. } => {
                let (owner, name) = repo.split_once('/')?;
                Some(Target::GitHub(source::GitHubSpec {
                    owner: owner.to_string(),
                    repo: name.to_string(),
                    path: path.clone(),
                }))
            }
            ServiceSource::Local { .. } => None,
        }
    };
    if args.all {
        let mut out: Vec<(String, Target)> = Vec::new();
        let mut locals = Vec::new();
        for l in stored {
            let Some(s) = &l.source else { continue };
            if out.iter().any(|(i, _)| *i == s.identity()) {
                continue;
            }
            match github_target(s) {
                Some(t) => out.push((s.identity(), t)),
                None => locals.push(s.identity()),
            }
        }
        locals.sort();
        locals.dedup();
        for l in locals {
            eprintln!(
                "note: {} is a local folder; update it with `sc service update <path>`",
                safe(&l)
            );
        }
        if out.is_empty() {
            return Err("no GitHub sources to update".into());
        }
        return Ok(out);
    }
    let target = args.target.as_deref().unwrap_or_default();
    let present = |identity: &str| {
        stored
            .iter()
            .any(|l| l.source.as_ref().is_some_and(|s| s.identity() == identity))
    };
    match parse_source(target)? {
        SourceSpec::GitHub(gh) => {
            let identity = gh.identity();
            if !present(&identity) {
                return Err(format!(
                    "{} is not added; run `sc service add {}`",
                    safe(&identity),
                    safe(target)
                ));
            }
            Ok(vec![(identity, Target::GitHub(gh))])
        }
        SourceSpec::Local(path) => {
            let name = std::fs::canonicalize(&path)
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .ok_or_else(|| format!("{}: not a folder", safe(target)))?;
            let identity = ServiceSource::Local { name }.identity();
            if !present(&identity) {
                return Err(format!(
                    "{} is not added; run `sc service add {}`",
                    safe(&identity),
                    safe(target)
                ));
            }
            Ok(vec![(identity, Target::Local(path))])
        }
        SourceSpec::Registry { .. } => Err("the service registry is not open yet".into()),
        SourceSpec::Name(id) => {
            let l = stored
                .iter()
                .find(|l| l.id == id)
                .ok_or_else(|| format!("no service '{}' in this vault", safe(&id)))?;
            match &l.source {
                None => Err(format!(
                    "'{}' was added before sources; it has no source to update from",
                    safe(&id)
                )),
                Some(ServiceSource::Local { name }) => {
                    Err(format!(
                        "'{}' comes from the local folder {}; pass its path: `sc service update ./path/to/{}`",
                        safe(&id),
                        safe(name),
                        safe(name)
                    ))
                }
                Some(s) => Ok(vec![(
                    s.identity(),
                    github_target(s).ok_or("unreadable source")?,
                )]),
            }
        }
    }
}

pub async fn run_update(args: ServiceUpdateArgs) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let stored = listing(&custodian, &vault).await?;
    let targets = update_targets(&args, &stored)?;
    let reg = ServiceRegistry::load();
    let approve = opts(args.no_browser, args.cb_port, args.timeout);
    for (identity, target) in targets {
        let mine: Vec<&Listed> = stored
            .iter()
            .filter(|l| l.source.as_ref().is_some_and(|s| s.identity() == identity))
            .collect();
        let spec = match &target {
            Target::GitHub(gh) => SourceSpec::GitHub(gh.clone()),
            Target::Local(p) => SourceSpec::Local(p.clone()),
        };
        // A single-service source keeps the id it is stored under (an earlier
        // `--id`, or the id before the upstream renamed it).
        let (files, src) = read(&spec, args.git_ref.as_deref(), &reg)
            .await
            .map_err(|p| report(&identity, p))?;
        let first = admit(files.clone(), src.clone(), None).map_err(|p| report(&identity, p))?;
        let loaded = match (first.admitted.as_slice(), mine.as_slice()) {
            ([one], [cur]) if first.single && one.id != cur.id => {
                admit(files, src, Some(&cur.id)).map_err(|p| report(&identity, p))?
            }
            _ => first,
        };
        let old: BTreeMap<String, DefSummary> = mine
            .iter()
            .filter_map(|l| l.summary.clone().map(|s| (l.id.clone(), s)))
            .collect();
        let new: BTreeMap<String, DefSummary> = loaded
            .admitted
            .iter()
            .map(|a| (a.id.clone(), summarize(&a.def)))
            .collect();
        let unchanged = mine.len() == loaded.admitted.len()
            && loaded.admitted.iter().all(|a| {
                mine.iter().any(|l| {
                    l.id == a.id
                        && l.digest.as_deref()
                            == Some(&definition_digest(&a.service, a.policy.as_deref()))
                })
            });
        println!("{}", safe(&identity));
        println!("  now: {}", safe(&loaded.source.display()));
        if unchanged {
            println!("  up to date: no definition changed");
            continue;
        }
        print_diff(&old, &new, &mine, &loaded);
        if args.check {
            continue;
        }
        if !args.yes {
            if !std::io::stdin().is_terminal() {
                return Err(
                    "refusing to update without confirmation; pass `-y` (non-interactive)".into(),
                );
            }
            let ans = crate::cli::connect::prompt_line("Apply this update? [y/N]: ")?;
            if !matches!(ans.trim(), "y" | "Y" | "yes" | "YES") {
                eprintln!("skipped");
                continue;
            }
        }
        let result = submit(&custodian, &vault, &loaded, true, &approve).await?;
        println!("  stored: {}", safe(&ids_of(&result, "ids").join(", ")));
        let removed = ids_of(&result, "removed");
        if !removed.is_empty() {
            println!("  removed: {}", safe(&removed.join(", ")));
        }
    }
    Ok(())
}

/// The update diff: services added / changed / removed, then the facts an
/// approver must weigh, marked: `+` a destination host no current service
/// had, `!` what now lets requests through more easily (a rule gone or less
/// strict, a longer approval window, a request variable no longer bound, PKCE
/// off).
fn print_diff(
    old: &BTreeMap<String, DefSummary>,
    new: &BTreeMap<String, DefSummary>,
    mine: &[&Listed],
    loaded: &Loaded,
) {
    let d = diff(old, new);
    let invalid_before: Vec<&str> = mine
        .iter()
        .filter(|l| !l.valid)
        .map(|l| l.id.as_str())
        .collect();
    for id in &d.added {
        if invalid_before.contains(&id.as_str()) {
            println!("  ~ {} (was skipped as invalid)", safe(id));
        } else {
            println!("  + service {}", safe(id));
        }
    }
    for id in &d.changed {
        println!("  ~ service {}", safe(id));
    }
    for a in &loaded.admitted {
        if !d.added.contains(&a.id) && !d.changed.contains(&a.id) {
            let same = mine.iter().any(|l| {
                l.id == a.id
                    && l.digest.as_deref()
                        == Some(&definition_digest(&a.service, a.policy.as_deref()))
            });
            if !same {
                println!("  ~ service {} (text only)", safe(&a.id));
            }
        }
    }
    for id in &d.removed {
        println!("  - service {} (its connections stop working)", safe(id));
    }
    for h in &d.new_destinations {
        println!("  + NEW HOST {}", safe(h));
    }
    for r in &d.loosens {
        println!("  ! LOOSENED {}", safe(r));
    }
}

// ── ls ───────────────────────────────────────────────────────────────────────

pub async fn run_ls(args: ServiceLsArgs, json: bool) -> Result<(), String> {
    let (custodian, vault) = resolve_active(None)?;
    let mut rows = match listing(&custodian, &vault).await {
        Ok(rows) => rows,
        // Locked: what the daemon has not applied is still known (`sc status`
        // shows the same), so it is said before the refusal.
        Err(e) if e == LOCKED && !json => {
            print_held(&held_notes(&custodian, &vault).await);
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    if let Some(id) = &args.id {
        rows.retain(|l| &l.id == id);
        if rows.is_empty() {
            return Err(format!("no service '{}' in this vault", safe(id)));
        }
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    let held = held_notes(&custodian, &vault).await;
    if rows.is_empty() {
        println!("no service definitions in this vault; add one with `sc service add <source>`");
        print_held(&held);
        return Ok(());
    }
    let mut groups: BTreeMap<String, (String, Vec<&Listed>)> = BTreeMap::new();
    for l in &rows {
        let (key, head) = group_of(l);
        groups.entry(key).or_insert((head, Vec::new())).1.push(l);
    }
    for (_, (head, items)) in groups {
        println!("{}", safe(&head));
        for l in items {
            let used = if l.connections.is_empty() {
                String::new()
            } else {
                format!("  (connections: {})", l.connections.join(", "))
            };
            if l.valid {
                println!("  ✓ {}{}", safe(&l.id), safe(&used));
            } else {
                println!("  ✗ {}  skipped{}", safe(&l.id), safe(&used));
                for p in &l.problems {
                    println!("      • {}", safe(p));
                }
            }
            if args.id.is_some() {
                if let Some(s) = &l.summary {
                    println!(
                        "      sends credentials to: {}",
                        safe(&s.destinations.join(", "))
                    );
                    for r in &s.rules {
                        println!("      rule: {}", safe(&r.text));
                    }
                }
                if let Some(ServiceSource::Github { commit, .. }) = &l.source {
                    println!("      commit: {}", safe(commit));
                }
            }
        }
    }
    print_held(&held);
    Ok(())
}

/// What the daemon has not applied for this vault (`GET /v/{vid}/held`).
async fn held_notes(custodian: &str, vault: &str) -> Vec<String> {
    match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => crate::cli::status::fetch_held(&c, custodian, vault).await,
        Err(_) => Vec::new(),
    }
}

fn print_held(held: &[String]) {
    for line in held {
        println!("note: {}", safe(line));
    }
}

// ── rm ───────────────────────────────────────────────────────────────────────

/// The op target for `sc service rm <arg>`: a service id, or a source's
/// identity.
fn rm_target(arg: &str) -> Result<String, String> {
    match parse_source(arg)? {
        SourceSpec::Name(id) => Ok(id),
        SourceSpec::GitHub(gh) => Ok(gh.identity()),
        SourceSpec::Local(path) => {
            let name = std::fs::canonicalize(&path)
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()))
                .ok_or_else(|| format!("{}: not a folder name", safe(arg)))?;
            Ok(ServiceSource::Local { name }.identity())
        }
        SourceSpec::Registry { .. } => Err("the service registry is not open yet".into()),
    }
}

pub async fn run_rm(args: ServiceRmArgs) -> Result<(), String> {
    let target = rm_target(&args.target)?;
    let (custodian, vault) = resolve_active(None)?;
    let stored = listing(&custodian, &vault).await?;
    let hit: Vec<&Listed> = stored
        .iter()
        .filter(|l| l.id == target || l.source.as_ref().is_some_and(|s| s.identity() == target))
        .collect();
    if hit.is_empty() {
        return Err(format!(
            "no service or source '{}' in this vault",
            safe(&target)
        ));
    }
    let ids: Vec<&str> = hit.iter().map(|l| l.id.as_str()).collect();
    println!("Removing: {}", safe(&ids.join(", ")));
    let mut conns: Vec<&str> = hit
        .iter()
        .flat_map(|l| l.connections.iter().map(String::as_str))
        .collect();
    conns.sort();
    conns.dedup();
    if !conns.is_empty() {
        eprintln!(
            "warning: connection{} {} still use{} it; {} kept but stop{} working until a definition is added again",
            if conns.len() == 1 { "" } else { "s" },
            safe(&conns.join(", ")),
            if conns.len() == 1 { "s" } else { "" },
            if conns.len() == 1 { "it is" } else { "they are" },
            if conns.len() == 1 { "s" } else { "" },
        );
    }
    let op = json!({
        "act": { "type": { "custom": "service-rm" }, "target": target, "scope": null },
        "bind": { "redeemer": vault },
        "valid": { "iat": now_unix(), "multiplicity": 1 }
    });
    let body = approve_op(
        &custodian,
        &vault,
        &op,
        &format!("Remove {}", target),
        &opts(args.no_browser, args.cb_port, args.timeout),
    )
    .await?;
    println!(
        "removed: {}",
        safe(&ids_of(&act_result(&body), "removed").join(", "))
    );
    Ok(())
}

// ── validate ─────────────────────────────────────────────────────────────────

pub async fn run_validate(args: ServiceValidateArgs, json: bool) -> Result<(), String> {
    let spec = parse_source(&args.source)?;
    let reg = ServiceRegistry::load();
    let result = load(&spec, args.git_ref.as_deref(), None, &reg)
        .await
        .and_then(|l| {
            let clash = built_in_problems(&l, &reg);
            if clash.is_empty() {
                Ok(l)
            } else {
                Err(clash)
            }
        });
    if json {
        let v = match &result {
            Ok(l) => json!({
                "valid": true,
                "source": l.source,
                "services": l.admitted.iter().map(|a| json!({
                    "id": a.id,
                    "summary": summarize(&a.def),
                    "notes": a.def.clone().for_vault().1,
                })).collect::<Vec<_>>(),
            }),
            Err(p) => json!({ "valid": false, "problems": p }),
        };
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return match result {
            Ok(_) => Ok(()),
            Err(_) => Err(format!("{}: validation failed", safe(&args.source))),
        };
    }
    match result {
        Ok(l) => {
            print_loaded(&l);
            println!("✓ {}: valid", safe(&args.source));
            Ok(())
        }
        Err(p) => {
            report(&args.source, p);
            Err(format!("{}: validation failed", safe(&args.source)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(id: &str, source: Option<ServiceSource>) -> Listed {
        Listed {
            id: id.into(),
            source,
            valid: true,
            problems: vec![],
            connections: vec![],
            summary: None,
            digest: None,
        }
    }

    /// `sc service ls` heads each installed source with its display only; a
    /// stored record saying it was checked is not read.
    #[test]
    fn ls_heading_is_the_source_display() {
        let gh: ServiceSource = serde_json::from_value(serde_json::json!({
            "kind": "github", "repo": "acme/tools", "path": "svc", "ref": "v1.2.0",
            "commit": "a".repeat(40), "checked": true,
        }))
        .unwrap();
        let (key, head) = group_of(&listed("a1", Some(gh.clone())));
        assert_eq!(
            head,
            format!("github:acme/tools:svc (v1.2.0) @ {}", "a".repeat(40))
        );
        assert_eq!(head, gh.display());
        assert_eq!(group_of(&listed("a2", Some(gh))).0, key, "one group");
        let local = ServiceSource::Local {
            name: "mine".into(),
        };
        let (_, head) = group_of(&listed("m1", Some(local)));
        assert_eq!(head, "local folder mine");
        assert_eq!(group_of(&listed("old", None)).1, "added before sources");
    }

    fn update_args(target: Option<&str>, all: bool) -> ServiceUpdateArgs {
        ServiceUpdateArgs {
            target: target.map(str::to_string),
            all,
            check: true,
            yes: false,
            git_ref: None,
            no_browser: true,
            cb_port: None,
            timeout: 1,
        }
    }

    #[test]
    fn rm_and_update_name_a_service_or_a_source() {
        assert_eq!(rm_target("acme").unwrap(), "acme");
        assert_eq!(
            rm_target("github:Acme/Tools:svc").unwrap(),
            "github:acme/tools:svc"
        );
        assert!(rm_target("acme/thing").is_err());

        let gh = ServiceSource::Github {
            repo: "acme/tools".into(),
            path: None,
            git_ref: None,
            commit: "a".repeat(40),
        };
        let local = ServiceSource::Local {
            name: "mine".into(),
        };
        let stored = vec![
            listed("a1", Some(gh.clone())),
            listed("b2", Some(gh)),
            listed("m1", Some(local)),
            listed("old", None),
        ];
        let t = update_targets(&update_args(Some("a1"), false), &stored).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, "github:acme/tools");
        let e = update_targets(&update_args(Some("m1"), false), &stored)
            .err()
            .unwrap();
        assert!(e.contains("sc service update ./path/to/mine"), "{e}");
        let e = update_targets(&update_args(Some("old"), false), &stored)
            .err()
            .unwrap();
        assert!(e.contains("before sources"), "{e}");
        let e = update_targets(&update_args(Some("github:x/y"), false), &stored)
            .err()
            .unwrap();
        assert!(e.contains("not added"), "{e}");
        // --all: each GitHub source once; local folders are left to their path.
        let t = update_targets(&update_args(None, true), &stored).unwrap();
        assert_eq!(t.len(), 1);
    }
}
