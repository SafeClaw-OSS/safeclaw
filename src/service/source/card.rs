//! What a source change does, as machine-computed facts: the approval card
//! for `service-add` / `service-rm`, and the diff `sc service update` shows.
//!
//! The card is computed from the definitions as the vault applies them
//! ([`ServiceDef::for_vault`]): every host that receives a credential or an
//! OAuth artifact (the declared hosts, the token endpoint, the authorization
//! page and a redirect that is not on this device), the rules that tighten,
//! and an OAuth flow without PKCE. Display text from the definition (labels)
//! is shown, never used to decide. The daemon stamps the card into the signed
//! op at creation and recomputes it at apply, refusing any difference, so what
//! was approved is what is written.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{ServiceSource, StoredService};
use crate::core::policy::{AccessLevel, PolicyRule};
use crate::service::{AuthDef, ServiceDef, ServiceRegistry};

/// One definition as a vault applies it, reduced to what an approver weighs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefSummary {
    /// Every host that receives a credential or an OAuth artifact of this
    /// service ([`definition_destinations`]).
    pub destinations: Vec<String>,
    /// The rules in effect (a vault keeps only the ones that tighten).
    pub rules: Vec<RuleSummary>,
    /// The `[default]` read / write levels in effect, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<String>,
    /// The `[default]` approval window (seconds), when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// `[requests]` name → the variables an approval binds (its `scope`),
    /// sorted. Requests that bind nothing are left out.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scopes: BTreeMap<String, Vec<String>>,
    /// The OAuth connect flow runs without PKCE (`pkce = false`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pkce_off: bool,
}

/// One rule: what it matches (`key`), its level, its approval window, and a
/// line to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSummary {
    /// What the rule matches (method/path patterns, body, when): two rules
    /// with the same key decide the same requests.
    pub key: String,
    pub level: String,
    /// `<label or id or match>: <level>`.
    pub text: String,
    /// How long an approval lasts (seconds), when the rule sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

fn rule_summary(r: &PolicyRule) -> RuleSummary {
    let level = r.level.map(|l| l.to_string()).unwrap_or_default();
    let matched = r.match_patterns.join(" | ");
    let mut key = matched.clone();
    if let Some(b) = &r.body {
        key.push_str(" body~");
        key.push_str(b.as_str());
    }
    if let Some(w) = &r.when {
        key.push_str(" when ");
        key.push_str(w);
    }
    let name = r.label.clone().or_else(|| r.id.clone()).unwrap_or_else(|| {
        if matched.is_empty() {
            key.clone()
        } else {
            matched
        }
    });
    RuleSummary {
        text: format!("{}: {}", name, level),
        key,
        level,
        ttl: r.ttl,
    }
}

/// The out-of-band redirect: the provider shows the code on its own page.
const OOB_REDIRECT: &str = "urn:ietf:wg:oauth:2.0:oob";

/// The host of an http(s) URL.
fn url_host(u: &str) -> Option<String> {
    url::Url::parse(u)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Where an OAuth redirect delivers the code, unless it stays on this device:
/// the host of an http(s) redirect that is not loopback, or `<scheme>:` for an
/// app's own scheme (the app registered for it receives the code). `None` for
/// a loopback redirect or the out-of-band one.
fn redirect_destination(uri: &str) -> Option<String> {
    if uri == OOB_REDIRECT {
        return None;
    }
    let u = url::Url::parse(uri).ok()?;
    match u.scheme() {
        "http" | "https" => match u.host()? {
            url::Host::Domain(d) if d.eq_ignore_ascii_case("localhost") => None,
            url::Host::Domain(d) => Some(d.to_string()),
            url::Host::Ipv4(ip) if ip.is_loopback() => None,
            url::Host::Ipv4(ip) => Some(ip.to_string()),
            url::Host::Ipv6(ip) if ip.is_loopback() => None,
            url::Host::Ipv6(ip) => Some(format!("[{}]", ip)),
        },
        scheme => Some(format!("{}:", scheme)),
    }
}

/// Every host that receives a credential or an OAuth artifact of `def`, each
/// once: the declared hosts, then the token endpoint's host, the
/// authorization page's host and where the redirect delivers the code
/// ([`redirect_destination`]).
pub fn definition_destinations(def: &ServiceDef) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: &str| {
        let h = h.trim();
        if !h.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(h)) {
            out.push(h.to_string());
        }
    };
    for h in &def.service.hosts {
        push(h);
    }
    match &def.auth {
        Some(AuthDef::Oauth2(o)) => {
            for u in [&o.token_url, &o.authorization_url].into_iter().flatten() {
                if let Some(h) = url_host(u) {
                    push(&h);
                }
            }
            if let Some(d) = o.redirect_uri.as_deref().and_then(redirect_destination) {
                push(&d);
            }
        }
        Some(AuthDef::Snaplii(_)) => {
            if let Some(h) = url_host(crate::auth::snaplii::TOKEN_URL) {
                push(&h);
            }
        }
        None => {}
    }
    out
}

/// Summarize a definition as a vault applies it (`def` is the admitted
/// definition; its policy is reduced to the parts that tighten here).
pub fn summarize(def: &ServiceDef) -> DefSummary {
    let (applied, _) = def.clone().for_vault();
    let mut s = DefSummary {
        destinations: definition_destinations(&applied),
        pkce_off: applied.oauth2().is_some_and(|o| o.pkce == Some(false)),
        ..Default::default()
    };
    if let Some(p) = &applied.policy {
        s.rules = p.rules.iter().map(rule_summary).collect();
        if let Some(d) = &p.defaults {
            s.read = d.read.map(|l| l.to_string());
            s.write = d.write.map(|l| l.to_string());
            s.ttl = d.ttl;
        }
    }
    for (name, shape) in &applied.requests {
        let mut vars: Vec<String> = shape.scope.clone();
        vars.sort();
        vars.dedup();
        if !vars.is_empty() {
            s.scopes.insert(name.clone(), vars);
        }
    }
    s
}

fn strictness(level: Option<&str>) -> u8 {
    level
        .and_then(AccessLevel::parse)
        .map(|l| l.restrictiveness())
        .unwrap_or(0)
}

fn is_ask(level: Option<&str>) -> bool {
    level.and_then(AccessLevel::parse) == Some(AccessLevel::Ask)
}

/// How long an `ask` approval lasts: the window set, else the default one.
fn window(ttl: Option<u64>) -> u64 {
    ttl.unwrap_or(crate::proxy::handler::DEFAULT_ASK_TTL)
}

fn window_text(ttl: Option<u64>) -> String {
    match ttl {
        Some(t) => format!("{}s", t),
        None => format!(
            "not set ({}s by default)",
            crate::proxy::handler::DEFAULT_ASK_TTL
        ),
    }
}

/// What changes from `old` to `new` (both keyed by service id).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    /// Destinations in `new` that no service of `old` had.
    pub new_destinations: Vec<String>,
    /// What a service in both now lets through more easily: a rule or default
    /// that is gone or decides less strictly, an `ask` approval that lasts
    /// longer, a request variable an approval no longer binds, PKCE turned
    /// off.
    pub loosens: Vec<String>,
}

pub fn diff(old: &BTreeMap<String, DefSummary>, new: &BTreeMap<String, DefSummary>) -> Diff {
    let mut d = Diff::default();
    let old_hosts: BTreeSet<String> = old
        .values()
        .flat_map(|s| s.destinations.iter().map(|h| h.to_ascii_lowercase()))
        .collect();
    let mut seen = BTreeSet::new();
    for s in new.values() {
        for h in &s.destinations {
            let low = h.to_ascii_lowercase();
            if !old_hosts.contains(&low) && seen.insert(low) {
                d.new_destinations.push(h.clone());
            }
        }
    }
    for (id, n) in new {
        match old.get(id) {
            None => d.added.push(id.clone()),
            Some(o) if o != n => d.changed.push(id.clone()),
            Some(_) => {}
        }
    }
    for (id, o) in old {
        let Some(n) = new.get(id) else {
            d.removed.push(id.clone());
            continue;
        };
        loosened(id, o, n, &mut d.loosens);
    }
    d
}

/// What `n` lets through more easily than `o` (one service), as lines.
fn loosened(id: &str, o: &DefSummary, n: &DefSummary, out: &mut Vec<String>) {
    for r in &o.rules {
        // The strictest rule of the new definition deciding the same requests.
        let now = n
            .rules
            .iter()
            .filter(|x| x.key == r.key)
            .max_by_key(|x| strictness(Some(&x.level)));
        match now {
            None => out.push(format!("{}: {} (removed)", id, r.text)),
            Some(x) if strictness(Some(&x.level)) < strictness(Some(&r.level)) => {
                out.push(format!("{}: {} (now {})", id, r.text, x.level))
            }
            Some(x)
                if is_ask(Some(&r.level))
                    && is_ask(Some(&x.level))
                    && window(x.ttl) > window(r.ttl) =>
            {
                out.push(format!(
                    "{}: {}, approval lasts {} (now {})",
                    id,
                    r.text,
                    window_text(r.ttl),
                    window_text(x.ttl)
                ))
            }
            Some(_) => {}
        }
    }
    for (dir, was, now) in [("read", &o.read, &n.read), ("write", &o.write, &n.write)] {
        if strictness(now.as_deref()) < strictness(was.as_deref()) {
            out.push(format!(
                "{}: default {} {} (now {})",
                id,
                dir,
                was.as_deref().unwrap_or(""),
                now.as_deref().unwrap_or("not set")
            ));
        }
    }
    let asks = |s: &DefSummary| is_ask(s.read.as_deref()) || is_ask(s.write.as_deref());
    if asks(o) && asks(n) && window(n.ttl) > window(o.ttl) {
        out.push(format!(
            "{}: default approval lasts {} (now {})",
            id,
            window_text(o.ttl),
            window_text(n.ttl)
        ));
    }
    for (req, vars) in &o.scopes {
        let now = n.scopes.get(req);
        for v in vars {
            if !now.is_some_and(|n| n.contains(v)) {
                out.push(format!(
                    "{}: request {} no longer binds {} to an approval",
                    id, req, v
                ));
            }
        }
    }
    if n.pkce_off && !o.pkce_off {
        out.push(format!("{}: PKCE: off (was on)", id));
    }
}

// ── service-add ──────────────────────────────────────────────────────────────

/// How the daemon established where a `service-add`'s definitions come from,
/// stamped on the card (`source_check`) at op creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCheck {
    /// The GitHub source was fetched again at its pinned commit on this
    /// device and its definitions match the request's.
    Fetched,
    /// A local folder: only the requester read it.
    LocalFolder,
    /// GitHub could not be reached (or did not answer) to check it.
    NotReached,
}

impl SourceCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceCheck::Fetched => "fetched",
            SourceCheck::LocalFolder => "local",
            SourceCheck::NotReached => "not-reached",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            SourceCheck::Fetched,
            SourceCheck::LocalFolder,
            SourceCheck::NotReached,
        ]
        .into_iter()
        .find(|c| c.as_str() == s)
    }

    /// The card's source line: a fact only when this device checked it,
    /// otherwise what the requester stated, said as such.
    pub fn source_line(self, source: &ServiceSource) -> String {
        match self {
            SourceCheck::Fetched => format!(
                "{} (fetched again on your device: the definitions match)",
                source.display()
            ),
            SourceCheck::LocalFolder => format!(
                "{}, as stated by the requester (a local folder cannot be checked)",
                source.display()
            ),
            SourceCheck::NotReached => format!(
                "{}, as stated by the requester (GitHub could not be reached to check it)",
                source.display()
            ),
        }
    }
}

/// The `service-add` card. Fields (all present, possibly empty):
/// - `ids`: the services this approval stores, sorted.
/// - `from`: the source and its pinned commit, as a fact when this device
///   fetched it again, else as the requester stated it
///   ([`SourceCheck::source_line`]); `source_check` says which.
/// - `destinations`: every host that receives their credentials or OAuth
///   artifacts.
/// - `oauth`: OAuth flows without PKCE (`<id>: PKCE: off`).
/// - `tightens`: the rules they apply (`<id>: <rule>: <level>`).
/// - `replaces`: services already stored from this source, replaced.
/// - `removes`: services stored from this source that it no longer has.
/// - `new_destinations`: destinations none of the replaced services had
///   (empty on a first add).
/// - `loosens`: what a replaced service now lets through more easily
///   ([`Diff::loosens`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCard {
    pub ids: Vec<String>,
    pub from: String,
    pub source_check: SourceCheck,
    pub destinations: Vec<String>,
    pub oauth: Vec<String>,
    pub tightens: Vec<String>,
    pub replaces: Vec<String>,
    pub removes: Vec<String>,
    pub new_destinations: Vec<String>,
    pub loosens: Vec<String>,
}

const ADD_LISTS: [&str; 8] = [
    "ids",
    "destinations",
    "oauth",
    "tightens",
    "replaces",
    "removes",
    "new_destinations",
    "loosens",
];

impl AddCard {
    fn lists(&self) -> [&Vec<String>; 8] {
        [
            &self.ids,
            &self.destinations,
            &self.oauth,
            &self.tightens,
            &self.replaces,
            &self.removes,
            &self.new_destinations,
            &self.loosens,
        ]
    }

    /// Write the card into an op scope, over any requester-supplied values.
    pub fn stamp(&self, scope: &mut Value) -> Result<(), String> {
        let o = scope
            .as_object_mut()
            .ok_or("op.act.scope must be a JSON object")?;
        for (k, v) in ADD_LISTS.iter().zip(self.lists()) {
            o.insert((*k).into(), json!(v));
        }
        o.insert("from".into(), json!(self.from));
        o.insert("source_check".into(), json!(self.source_check.as_str()));
        Ok(())
    }

    /// The first field where the signed card in `scope` differs from `self`.
    pub fn first_difference(&self, scope: &Value) -> Option<&'static str> {
        for (k, v) in ADD_LISTS.iter().zip(self.lists()) {
            if scope.get(*k) != Some(&json!(v)) {
                return Some(k);
            }
        }
        if scope.get("from") != Some(&json!(self.from)) {
            return Some("from");
        }
        if scope.get("source_check") != Some(&json!(self.source_check.as_str())) {
            return Some("source_check");
        }
        None
    }
}

/// The services already stored from `source`'s identity. A conflict copy is
/// not one of them: it is resolved in the console, never updated or removed
/// with its source.
pub fn stored_from<'a>(
    current: &'a BTreeMap<String, StoredService>,
    identity: &str,
) -> BTreeMap<&'a String, &'a StoredService> {
    current
        .iter()
        .filter(|(id, _)| !crate::storage::item::is_conflict_copy_name(id))
        .filter(|(_, e)| e.source().is_some_and(|s| s.identity() == identity))
        .collect()
}

/// The card for storing `snapshot` (service id → admitted definition) from
/// `source` (established as `check` says) into a vault holding `current`, or
/// why it cannot be stored: an id that is a built-in service, an id another
/// source (or an entry added before sources) already holds, a source already
/// added when this is not an update, or one not added when it is.
pub fn add_card(
    snapshot: &BTreeMap<String, ServiceDef>,
    source: &ServiceSource,
    check: SourceCheck,
    update: bool,
    current: &BTreeMap<String, StoredService>,
    reg: &ServiceRegistry,
) -> Result<AddCard, String> {
    let identity = source.identity();
    let shown = |id: &str| crate::util::terminal_safe(id).into_owned();
    for id in snapshot.keys() {
        if reg.get(id).is_some() {
            return Err(format!(
                "'{}' is a built-in service id; store it under another id with --id",
                shown(id)
            ));
        }
        if let Some(e) = current.get(id) {
            let other = e.source();
            if other.as_ref().map(|s| s.identity()) != Some(identity.clone()) {
                let from = match other {
                    Some(s) => s.display(),
                    None => "a definition added before sources".to_string(),
                };
                return Err(format!(
                    "'{}' is already in this vault from {}; store it under another id with --id, or remove that one first",
                    shown(id),
                    crate::util::terminal_safe(&from)
                ));
            }
        }
    }
    let mine = stored_from(current, &identity);
    let shown_source = crate::util::terminal_safe(&identity).into_owned();
    if !update && !mine.is_empty() {
        return Err(format!(
            "{} is already added; run `sc service update {}`",
            shown_source, shown_source
        ));
    }
    if update && mine.is_empty() {
        return Err(format!(
            "{} is not added; run `sc service add` first",
            shown_source
        ));
    }
    let old: BTreeMap<String, DefSummary> = mine
        .iter()
        .filter_map(|(id, e)| e.admit(id).ok().map(|d| ((*id).clone(), summarize(&d))))
        .collect();
    let new: BTreeMap<String, DefSummary> = snapshot
        .iter()
        .map(|(id, d)| (id.clone(), summarize(d)))
        .collect();
    let mut card = AddCard {
        ids: snapshot.keys().cloned().collect(),
        from: check.source_line(source),
        source_check: check,
        destinations: Vec::new(),
        oauth: Vec::new(),
        tightens: Vec::new(),
        replaces: Vec::new(),
        removes: Vec::new(),
        new_destinations: Vec::new(),
        loosens: Vec::new(),
    };
    for (id, s) in &new {
        for h in &s.destinations {
            if !card.destinations.iter().any(|x| x.eq_ignore_ascii_case(h)) {
                card.destinations.push(h.clone());
            }
        }
        if s.pkce_off {
            card.oauth.push(format!("{}: PKCE: off", id));
        }
        card.tightens
            .extend(s.rules.iter().map(|r| format!("{}: {}", id, r.text)));
        for (dir, l) in [("read", &s.read), ("write", &s.write)] {
            if let Some(l) = l {
                card.tightens
                    .push(format!("{}: default {}: {}", id, dir, l));
            }
        }
    }
    card.replaces = mine
        .keys()
        .filter(|id| snapshot.contains_key(id.as_str()))
        .map(|id| (*id).clone())
        .collect();
    card.removes = mine
        .keys()
        .filter(|id| !snapshot.contains_key(id.as_str()))
        .map(|id| (*id).clone())
        .collect();
    if !mine.is_empty() {
        let d = diff(&old, &new);
        card.new_destinations = d.new_destinations;
        card.loosens = d.loosens;
    }
    Ok(card)
}

// ── service-rm ───────────────────────────────────────────────────────────────

/// The `service-rm` card: `ids` removed (sorted), `from` (the source they
/// came from, empty for an entry added before sources), and `connections`
/// that still name one of them (they keep their secrets but lose the
/// service).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RmCard {
    pub ids: Vec<String>,
    pub from: String,
    pub connections: Vec<String>,
}

impl RmCard {
    pub fn stamp(&self, scope: &mut Value) -> Result<(), String> {
        if scope.is_null() {
            *scope = json!({});
        }
        let o = scope
            .as_object_mut()
            .ok_or("op.act.scope must be a JSON object")?;
        o.insert("ids".into(), json!(self.ids));
        o.insert("from".into(), json!(self.from));
        o.insert("connections".into(), json!(self.connections));
        Ok(())
    }

    pub fn first_difference(&self, scope: &Value) -> Option<&'static str> {
        if scope.get("ids") != Some(&json!(self.ids)) {
            Some("ids")
        } else if scope.get("from") != Some(&json!(self.from)) {
            Some("from")
        } else if scope.get("connections") != Some(&json!(self.connections)) {
            Some("connections")
        } else {
            None
        }
    }
}

/// The card for removing `target` (a service id, or a source identity such
/// as `github:owner/repo[:path]` / `local:<folder>`) from a vault holding
/// `current`; `uses(id)` lists the connections naming a service.
pub fn rm_card(
    target: &str,
    current: &BTreeMap<String, StoredService>,
    uses: impl Fn(&str) -> Vec<String>,
) -> Result<RmCard, String> {
    if crate::storage::item::is_conflict_copy_name(target) {
        return Err(format!(
            "'{}' is {}",
            crate::util::terminal_safe(target),
            crate::service::CONFLICT_COPY_REASON
        ));
    }
    let (ids, from): (Vec<String>, String) = if let Some(e) = current.get(target) {
        (
            vec![target.to_string()],
            e.source().map(|s| s.display()).unwrap_or_default(),
        )
    } else {
        let mine = stored_from(current, target);
        if mine.is_empty() {
            return Err(format!(
                "no service or source '{}' in this vault",
                crate::util::terminal_safe(target)
            ));
        }
        let from = mine
            .values()
            .find_map(|e| e.source().map(|s| s.display()))
            .unwrap_or_default();
        (mine.keys().map(|k| (*k).clone()).collect(), from)
    };
    let mut connections: Vec<String> = ids.iter().flat_map(|id| uses(id)).collect();
    connections.sort();
    connections.dedup();
    Ok(RmCard {
        ids,
        from,
        connections,
    })
}
