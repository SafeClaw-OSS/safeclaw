/// TOML-driven service registry (v4, phantom-only broker).
///
/// Each service is defined by a `service.toml` in `services/{id}/` (flat — the
/// dir name is the id; classification lives in the `tags` field, not layout).
/// A service declares what a minimal connection has — `hosts` + `secrets` —
/// plus the auth mechanism (`[auth]`, absent = static) and cosmetic helpers. No
/// routing/transport is declared: the phantom is the sole intent carrier and
/// the request already carries the real upstream URL.
pub mod gate;
pub mod limits;
pub mod source;

use crate::auth::oauth2::OAuthStyle;
use std::collections::HashMap;

// ── ServiceDef: parsed from service.toml (v4) ───────────────────────────────

/// A service TYPE, as the gate admitted it ([`gate::admit`], the only
/// constructor: the private field keeps every other module from building one,
/// and there is no `Deserialize`). The schema it was parsed from rejects stale
/// v3 sections and any tool-named section (`[git]`, `[docker]`): auth is a
/// MECHANISM, never a tool, and the only auth section is `[auth]`
/// (type-discriminated).
#[derive(Debug, Clone)]
pub struct ServiceDef {
    pub service: ServiceMeta,
    /// The auth MECHANISM — how the wire credential is produced from the
    /// stored secret(s). Discriminated by `type` (the same shape as OpenAPI
    /// `securitySchemes.type`). ABSENT = static: the stored secret IS the wire
    /// value, substituted verbatim wherever the agent's phantom names it.
    /// When present, the default phantom resolves to a MINTED short-lived
    /// token and the mechanism's input role (`mint_input_role`) is internal
    /// by construction and never injectable.
    pub auth: Option<AuthDef>,
    /// Optional agent-facing `setup` prose: service-specific guidance on where a
    /// phantom goes for this service's tools (a header, an env var, a URL) when
    /// run under `sc run --`. Plain text — no template tokens.
    pub setup: Option<String>,
    /// The definition's policy, compiled at the gate: its policy.toml, or the
    /// inline `[policy]` section (`[policy.levels]` / `[[policy.rules]]`) of a
    /// service.toml without one. `None` when it declares neither.
    pub policy: Option<ServicePolicy>,
    /// Request shapes (`[requests.<name>]`): the body/query fields this
    /// service's endpoints expose, which of them identify an action for
    /// binding (`scope`), and how to phrase them (`consent`). Opt-in — absent
    /// ⇒ the body is not part of any grant identity (Phase-1 behavior). See
    /// design/request-scope.md and [`RequestShape`].
    pub requests: HashMap<String, RequestShape>,
    /// Set only by the gate.
    _gate: (),
}

/// A definition's policy, compiled at the gate: the read/write floor when no
/// rule matches, and the rules in file order, each with a parsed level and a
/// compiled `body`.
#[derive(Debug, Clone, Default)]
pub struct ServicePolicy {
    /// `[default]` in policy.toml, `[policy.levels]` inline.
    pub defaults: Option<crate::core::policy::Levels>,
    pub rules: Vec<crate::core::policy::PolicyRule>,
}

impl ServicePolicy {
    /// The parts of this policy that can only tighten a decision, and a note
    /// for each part left out. A vault definition's policy is applied this
    /// way (tightening applies directly; loosening needs the owner's consent,
    /// which a definition any member can write does not carry): rules that
    /// decide `deny`, `ask` or `ask-always`, and a `[default]` read or write
    /// level other than `allow` (with its `ttl`). The decision then takes the
    /// stricter of the outcome with and without it
    /// ([`crate::core::policy::stricter`]).
    pub fn tightening(&self) -> (ServicePolicy, Vec<String>) {
        use crate::core::policy::{AccessLevel, Levels};
        const WHY: &str = "a vault service definition can only tighten policy; loosening is the owner's setting in the console";
        let mut notes = Vec::new();
        let mut rules = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            if matches!(r.level, Some(AccessLevel::Allow) | None) {
                let name =
                    r.id.as_deref()
                        .map(|id| format!("rule '{}'", id))
                        .unwrap_or_else(|| format!("[[policy.rules]] #{}", i + 1));
                notes.push(format!("{} (allow) is not applied: {}", name, WHY));
            } else {
                rules.push(r.clone());
            }
        }
        let defaults = self.defaults.as_ref().and_then(|d| {
            let keep = |dir: &str, l: Option<AccessLevel>, notes: &mut Vec<String>| match l {
                Some(AccessLevel::Allow) => {
                    notes.push(format!("default {} = allow is not applied: {}", dir, WHY));
                    None
                }
                other => other,
            };
            let read = keep("read", d.read, &mut notes);
            let write = keep("write", d.write, &mut notes);
            if read.is_none() && write.is_none() {
                if d.ttl.is_some() {
                    notes.push(format!(
                        "default ttl is not applied: the default levels it goes with are not ({})",
                        WHY
                    ));
                }
                return None;
            }
            Some(Levels {
                read,
                write,
                ttl: d.ttl,
            })
        });
        (ServicePolicy { defaults, rules }, notes)
    }
}

impl ServiceDef {
    /// This definition as a vault (`aux.services`) definition applies it: its
    /// policy reduced to [`ServicePolicy::tightening`], with a note for each
    /// part left out (`sc service validate` / `add` print them).
    pub fn for_vault(mut self) -> (ServiceDef, Vec<String>) {
        let mut notes = Vec::new();
        if let Some(p) = &self.policy {
            let (kept, n) = p.tightening();
            notes = n;
            self.policy = (!kept.rules.is_empty() || kept.defaults.is_some()).then_some(kept);
        }
        (self, notes)
    }
}

impl ServiceDef {
    /// The `[auth] type = "oauth2"` section, when that is this service's
    /// mechanism. Shorthand for the oauth-only call sites (consent flow,
    /// console wiring) so they don't each match on [`AuthDef`].
    pub fn oauth2(&self) -> Option<&OAuth2Def> {
        match self.auth.as_ref() {
            Some(AuthDef::Oauth2(o)) => Some(o),
            _ => None,
        }
    }

    /// The stored role that is the INPUT of a minted mechanism — the value the
    /// mint consumes (oauth2's refresh token, snaplii's api key). `Some` ⇔ the
    /// connection's wire credential is minted, and this role is internal by
    /// construction: a phantom naming it gets the precise never-injectable
    /// refusal. `None` for a static service.
    pub fn mint_input_role(&self) -> Option<String> {
        match self.auth.as_ref()? {
            AuthDef::Oauth2(o) => {
                let s = o.refresh_token.trim();
                (!s.is_empty()).then(|| s.to_string())
            }
            AuthDef::Snaplii(_) => self.first_secret(),
        }
    }

    fn first_secret(&self) -> Option<String> {
        self.service
            .secrets
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    /// Resolve the request into its matching `[requests]` shape and extract the
    /// declared vars — the join point that feeds both a policy `when` and the
    /// approval binding/consent. `None` when no shape matches (⇒ no vars, an
    /// empty scope: the Phase-1 path-only grant). Selection is deterministic
    /// (see below); shapes should not overlap. Body is parsed as JSON
    /// once; a non-JSON body or a pointer that misses leaves that var undefined
    /// (per P3, an undefined var makes a `when` simply not fire, and it is
    /// omitted from the bound set).
    pub fn extract_request_scope(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        body: Option<&str>,
    ) -> Option<RequestScope> {
        // Deterministic selection: `requests` is a HashMap, so iterate its keys
        // in a STABLE (sorted) order — otherwise two overlapping shapes would
        // pick a random winner per process, making the bound digest unstable
        // (a legit replay could hash a different shape than approve did →
        // spurious re-prompt). Shapes should not overlap; this makes "they
        // shouldn't, but if they do" harmless and repeatable.
        let mut names: Vec<&String> = self.requests.keys().collect();
        names.sort();
        let (shape_name, shape) = names.into_iter().find_map(|n| {
            let s = &self.requests[n];
            s.match_pattern
                .iter()
                .any(|p| crate::core::policy::pattern_matches(p, method, path))
                .then_some((n, s))
        })?;
        let body_json: Option<serde_json::Value> = body.and_then(|b| serde_json::from_str(b).ok());
        let mut vars = crate::core::policy::VarMap::new();
        for (name, def) in &shape.vars {
            if let Some(v) = def.resolve(body_json.as_ref(), query) {
                // Bare name for the common single-shape case; qualified
                // `shape.name` so a rule spanning several shapes can disambiguate.
                vars.insert(format!("{}.{}", shape_name, name), v.clone());
                vars.insert(name.clone(), v);
            }
        }
        // The bound subset: scope vars that actually resolved, sorted for a
        // stable digest. An unresolved scope var is simply omitted (approve and
        // redeem both omit it, so the identity stays consistent). A large value
        // (a whole email with an attachment) is bound by DIGEST, not verbatim —
        // otherwise it would bloat the op that travels the approval relay
        // (approve.rs would 413). approve and redeem apply the SAME cap, so the
        // grant identity is unchanged; only the display degrades to a summary.
        let mut bound: Vec<(String, String)> = shape
            .scope
            .iter()
            .filter_map(|k| vars.get(k).map(|v| (k.clone(), cap_bound_value(v))))
            .collect();
        bound.sort_by(|a, b| a.0.cmp(&b.0));
        let mut declared: Vec<String> = shape.vars.keys().cloned().collect();
        declared.sort();
        Some(RequestScope {
            vars,
            bound,
            consent: shape.consent.clone(),
            shape: shape_name.clone(),
            declared,
            binds: shape.scope.clone(),
        })
    }

    /// The stored secret role that backs this service's credential: the mint
    /// input role for a minted service, else its first `secrets` entry. `None`
    /// when it declares neither. A pure projection over the def — the SINGLE
    /// source of truth for "which vault role holds this service's secret", so a
    /// registry service and a vault-custom service resolve identically. Callers
    /// that only have a `service_id` and a registry go through
    /// [`service_env_key`]; callers that may face a custom service resolve the
    /// `ServiceDef` first (custom `.or_else(registry)`) and call this directly.
    pub fn env_role(&self) -> Option<String> {
        if let Some(r) = self.mint_input_role() {
            return Some(r);
        }
        self.service
            .secrets
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty())
            .map(|s| s.to_string())
    }
}

/// The `[auth]` section: which mechanism produces this service's wire
/// credential, discriminated by `type` — the same shape as OpenAPI's
/// `securitySchemes.type`. The rule that keeps this enum honest: a mechanism
/// whose wire format is STANDARDIZED (oauth2 — RFC 6749 fixes the vocabulary)
/// is declarative config; a bespoke envelope with no published vocabulary
/// (snaplii) is a code built-in and its variant carries no config, because
/// parameterizing an unstandardized wire would mean inventing a private DSL.
/// Absent `[auth]` = static (the 70% case): no mint, phantom substitutes the
/// stored secret verbatim.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthDef {
    /// OAuth 2.0 (RFC 6749): the stored refresh token mints access tokens at
    /// `token_url`. Fields are the RFC's own names, declared inline.
    Oauth2(OAuth2Def),
    /// Snaplii's bespoke key→JWT exchange (`auth::snaplii`). The envelope is
    /// unstandardized (JSON `{agent_id, api_key}` → JWT; no OAuth grant), so
    /// it lives in code; the variant is deliberately field-free.
    Snaplii(SnapliiDef),
}

/// `[auth] type = "snaplii"` carries no configuration — the exchange envelope
/// (URL, field names, response shape) is hard-coded in [`crate::auth::snaplii`]
/// and the input key is the service's first `secrets` role.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapliiDef {}

/// The oauth2 mechanism config. The section is SELF-SUFFICIENT: it
/// declares the endpoints + public client inline (`authorization_url`,
/// `token_url`, `client_id`, …) — the same shape whether it ships in-tree or is
/// user-authored (`aux.services`). There is no template/inheritance layer;
/// services sharing an OAuth client (the Google trio) simply repeat it.
/// `provider` is a pure display label ("Connect with Google").
///
/// Token slots use the RFC 6749 response field names: `refresh_token` maps the
/// durable refresh token to the vault secret KEY it is stored under (internal —
/// the mint reads it, no phantom exposes it); optional `id_token` maps a stored
/// OIDC id token likewise. The minted `access_token` is ephemeral (never
/// stored, never named) — it is what the default phantom resolves to. `exposes`
/// lists extra minted/derived roles surfaced as role-qualified phantoms (e.g.
/// openai-codex's `account_id`); `claims` maps such a role to its id_token
/// claim path (array of nested keys — a segment may itself contain dots or
/// slashes, e.g. a namespaced `https://api.openai.com/auth` claim). The flow
/// temps `code`/`code_verifier` are standard, not per-service — they live in
/// `aux.connecting.oauth2`, never here.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Def {
    /// Pure display label for the frontend's connect button ("Connect with
    /// Google"). Carries NO configuration; absent reads as "custom".
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// RFC 6749 `refresh_token` → the vault secret KEY the durable refresh token
    /// is stored under (e.g. `GMAIL_REFRESH_TOKEN`). Named explicitly (not
    /// derived) so a service declaring more than one secret is unambiguous.
    pub refresh_token: String,
    /// RFC 6749 `id_token` → the vault secret KEY a stored OIDC id token is
    /// written under. Only for providers that return a durable id token; absent
    /// for the common access+refresh flow.
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub exposes: Vec<String>,
    /// `exposes` role → its claim path in the exchange's id_token payload, as an
    /// ARRAY of nested object keys (a plain string path would be ambiguous —
    /// OIDC namespace keys contain `.`/`/` themselves). A role with no mapping
    /// falls back to a top-level claim of the same name.
    #[serde(default)]
    pub claims: HashMap<String, Vec<String>>,

    // ── Inline endpoints + public client ──
    /// CONNECT step endpoint (user consent).
    #[serde(default)]
    pub authorization_url: Option<String>,
    /// REFRESH + code-exchange endpoint.
    #[serde(default)]
    pub token_url: Option<String>,
    /// OAuth client_id (a PUBLIC client's id — safe to declare in a recipe).
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth client_secret. A literal secret in a definition is BY CONVENTION a
    /// PUBLIC client's (RFC 6749 §2.1) — non-confidential by the vendor's own
    /// design, like Google's Desktop client. A confidential secret must never
    /// sit in a recipe; that line is review-enforced (there is no client_type
    /// field to assert it — tooling stamped it automatically, so it proved
    /// nothing).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Whether the connect flow uses PKCE (RFC 7636). Defaults to `true`
    /// (every public client should).
    #[serde(default)]
    pub pkce: Option<bool>,
    /// The OAuth client's fixed redirect_uri. Falls back to
    /// [`DEFAULT_LOOPBACK_REDIRECT`].
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// Body style for the `/token` call: `form` (default) or `json` (Anthropic).
    #[serde(default)]
    pub oauth_style: Option<String>,
    /// Extra static query params for the consent URL — the per-vendor quirks
    /// (Google's `access_type=offline`/`prompt=consent`, codex's
    /// `codex_cli_simplified_flow=true`). Reserved protocol params (client_id,
    /// redirect_uri, scope, state, response_type, code_challenge*) are rejected
    /// by the validator — these are ADDITIONS, never overrides.
    #[serde(default)]
    pub authorize_params: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceMeta {
    pub id: String,
    pub name: String,
    /// Classification tags (lowercase-kebab, multiple allowed) — e.g. "ai",
    /// "app", "messaging", "payment". Replaces the old directory-derived single
    /// category. Dual use: browse/filter metadata on the registry wire, and
    /// policy tag-floor matching (`Policy.categories` keys; when several tags
    /// hit floors the most restrictive wins). Absent (per-vault custom
    /// services) = untagged: no tag floor applies, console buckets it as an
    /// app.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Anchored egress hosts — exact FQDNs or `*.suffix` wildcards (leftmost
    /// single label). The runtime anchor validates the destination against the
    /// exact entries (and pinned instances of the wildcards). Declared under the
    /// `[service]` table.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Stored secret role keys (`[A-Z0-9_]`). A phantom resolves to the value
    /// as-is; the injection SITE is the agent's (header/query/URL/Basic).
    /// Declared under the `[service]` table.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// If set, this service is grouped with the service whose id matches this value.
    /// Services sharing the same group are merged into one card in the UI.
    #[serde(default)]
    pub group: Option<String>,
    /// Optional, purely auxiliary: the page where a HUMAN mints/manages this
    /// service's secret (e.g. `https://crates.io/settings/tokens`). Pairs with
    /// `secrets` above. Display-only — consumers render it as a helper link
    /// (console "Open ... -> API tokens", CLI "Get a token: ..."); nothing ever
    /// FETCHES a secret from it, and it never participates in routing or
    /// policy. Must be http(s) when present (it is rendered as a link).
    #[serde(default)]
    pub secret_url: Option<String>,
    /// Help text returned by GET /{service}/help and rendered into safeclaw.md.
    /// Supports template variables: {{wallet.*}} resolved from vault service data.
    #[serde(default)]
    pub help: Option<String>,
    /// Activation mode: "auto" = starts automatically without credentials.
    /// Absent/None = requires user "connect" (provide API key / OAuth).
    #[serde(default)]
    pub activation: Option<String>,
    /// If true, exclude from `/registry` and `/v/{vid}/registry`. Use for
    /// services that are defined but not yet ready for agent discovery.
    #[serde(default)]
    pub hidden: bool,
}

/// The loopback redirect for desktop/PKCE OAuth clients when an `[oauth2]`
/// section doesn't pin its own `redirect_uri`. Matches the frontend
/// `DEFAULT_LOOPBACK_REDIRECT` so the consent request and the code→token
/// exchange always agree.
pub const DEFAULT_LOOPBACK_REDIRECT: &str = "http://127.0.0.1:8765/safeclaw/oauth/callback";

/// The loopback port of an OAuth redirect_uri — `Some(port)` only for an
/// `http://` URI whose host is a loopback NAME with an explicit port
/// (`http://127.0.0.1:8765/...`, `http://localhost:1455/...`). Anything else —
/// https, a real host, a default-port URI — is not a target our auto-catch
/// listener could serve, so `None`.
pub fn loopback_port(redirect_uri: &str) -> Option<u16> {
    let rest = redirect_uri.strip_prefix("http://")?;
    let authority = rest.split('/').next()?;
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        v6.split_once("]:")?
    } else {
        authority.rsplit_once(':')?
    };
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return None;
    }
    port.parse().ok()
}

/// A service's `[oauth2]` client/endpoint config with the defaults applied —
/// see `ServiceRegistry::resolve_oauth_config`.
#[derive(Debug, Clone)]
pub struct ResolvedOAuthConfig {
    pub token_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// The OAuth client's fixed redirect_uri (inline literal, or the loopback
    /// default). Sent in the daemon's code→token exchange so it matches the
    /// consent request the browser made.
    pub redirect_uri: String,
}

/// The OAuth wiring of a service's `[oauth2]` section, as broadcast on the
/// public `/registry` response — everything a frontend needs to START a
/// connect (consent URL) and to DISPLAY the wiring faithfully.
/// CONNECTIONS_AND_AUTH.md §4a.
///
/// This mirrors the definition 1:1 on purpose: a definition may only ever
/// contain PUBLIC-client material (a literal `client_secret` in a def is a
/// public client's by convention — see `OAuth2Def::client_secret`), so there
/// is nothing confidential to withhold — hiding fields here would only make
/// the console lie about what the toml says. The daemon still does the
/// code→token exchange locally; the browser only drives consent and seals the
/// resulting `{code, verifier}` into the vault.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectDescriptor {
    /// Display label ("Connect with Google"); "custom" when the def names none.
    pub provider: String,
    pub authorization_url: String,
    /// REFRESH + code-exchange endpoint (display/reference — the daemon uses it,
    /// the frontend never calls it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    pub client_id: String,
    /// The PUBLIC client's secret, when the def ships one (e.g. Google's
    /// Desktop client, non-confidential by design).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub pkce: bool,
    /// The OAuth client's fixed redirect_uri — the frontend builds the consent
    /// URL from this (not a hardcoded constant) so it always matches what the
    /// daemon sends at code→token exchange (CONNECTION_SCHEMA.md §5).
    pub redirect_uri: String,
    /// `/token` body style: `form` (default) or `json`.
    pub oauth_style: String,
    /// Extra static consent-URL query params (vendor quirks: Google's
    /// `access_type=offline`, codex's `codex_cli_simplified_flow=true`). The
    /// frontend appends these BEFORE setting the reserved protocol params, so
    /// they can never override client_id/redirect_uri/state/….
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub authorize_params: HashMap<String, String>,
}

// ── Request shapes: `[requests.<name>]` (design/request-scope.md) ──────────────

/// One request shape: a method+path matcher plus the body/query fields it
/// exposes (`vars`), which of them bind the grant (`scope`), and how to phrase
/// the action for a human (`consent`). `deny_unknown_fields` so a typo is a
/// parse error, not a silently-ignored field.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestShape {
    /// `"METHOD /path"` (or `"/path"`), or a list = OR. Same grammar / serde as
    /// a policy rule's `match`.
    #[serde(
        rename = "match",
        deserialize_with = "crate::core::policy::match_spec::deserialize"
    )]
    pub match_pattern: Vec<String>,
    /// `name → address`. A bare string addresses a body JSON Pointer; the table
    /// form `{ in = "query", at = "<param>" }` addresses a query parameter.
    #[serde(default)]
    pub vars: HashMap<String, VarDef>,
    /// The subset of `vars` whose VALUES bind the grant identity. Absent/empty ⇒
    /// nothing bound (P5). Whitelist only in v1.
    #[serde(default)]
    pub scope: Vec<String>,
    /// The approval-screen phrasing: a template over the bound vars, using the
    /// SAME `{{ vars.x | filter }}` pipe syntax as git-integration's
    /// `{{ secret.X | basic }}` (the Liquid/Jinja convention). Two shapes:
    ///   - plain interpolation — `"Buy from {{ vars.merchant }} for {{ vars.amount }}"`;
    ///   - a rich renderer via a filter — `"{{ vars.raw | email }}"` (the `email`
    ///     console filter decodes the bound base64url message into a card).
    /// One field, always a string; a filter names console code (declarative
    /// toml, code in the console — the same split as `[auth]`). Every referenced
    /// `vars.<name>` must be in `scope` (P4 show ⊆ bind, build-checked); a filter
    /// reads ONLY that bound value. Interpolated values are auto-escaped by the
    /// renderer (they come from the agent).
    #[serde(default)]
    pub consent: Option<String>,
}

/// One `{{ vars.<name> [| <filter>] }}` reference in a consent template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRef {
    pub var: String,
    pub filter: Option<String>,
}

/// Parse a consent template's `{{ vars.<name> [| <filter>] }}` references (the
/// same pipe grammar as git-integration's `{{ secret.X | basic }}`). Literal
/// text and malformed/prefix-less tokens are skipped. Used for both build
/// verification (var ⊆ scope) and the CLI's plain-text render.
pub fn consent_refs(template: &str) -> Vec<ConsentRef> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let inner = after[..end].trim();
        let mut parts = inner.splitn(2, '|');
        let expr = parts.next().unwrap_or("").trim();
        let filter = parts
            .next()
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty());
        if let Some(name) = expr.strip_prefix("vars.").map(str::trim) {
            if !name.is_empty() {
                out.push(ConsentRef {
                    var: name.to_string(),
                    filter,
                });
            }
        }
        rest = &after[end + 2..];
    }
    out
}

/// The `vars.<name>` names a consent template references — for the show ⊆ bind
/// build check.
pub fn consent_tokens(template: &str) -> Vec<String> {
    consent_refs(template).into_iter().map(|r| r.var).collect()
}

/// Where a var is addressed. OpenAPI's `in` convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VarLoc {
    Body,
    Query,
}

/// A var's address into the request. Untagged: a bare string is the common
/// case (a body JSON Pointer); the table form spells the location out.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum VarDef {
    /// Bare string = a JSON Pointer (RFC 6901) into the request BODY.
    BodyPointer(String),
    /// `{ in = "body"|"query", at = "<pointer-or-param>" }`.
    Located(VarAt),
}

/// The table form of a var address. `deny_unknown_fields` so a typo is a
/// parse error, not a silently-ignored field.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VarAt {
    #[serde(rename = "in")]
    pub location: VarLoc,
    pub at: String,
}

impl VarDef {
    /// Resolve this var's value (as a string) from the parsed body / raw query.
    /// `None` = absent / unparseable (an undefined var).
    fn resolve(&self, body: Option<&serde_json::Value>, query: Option<&str>) -> Option<String> {
        match self {
            VarDef::BodyPointer(ptr) => from_body(body, ptr),
            VarDef::Located(VarAt {
                location: VarLoc::Body,
                at,
            }) => from_body(body, at),
            VarDef::Located(VarAt {
                location: VarLoc::Query,
                at,
            }) => from_query(query, at),
        }
    }
}

fn from_body(body: Option<&serde_json::Value>, ptr: &str) -> Option<String> {
    json_scalar_to_string(body?.pointer(ptr)?)
}

fn from_query(query: Option<&str>, name: &str) -> Option<String> {
    let urldecode = |s: &str| {
        urlencoding::decode(s)
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| s.to_string())
    };
    query?.split('&').find_map(|pair| {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        (urldecode(k) == name).then(|| urldecode(it.next().unwrap_or("")))
    })
}

/// A JSON value → the string used for `when` comparison and grant binding. A
/// number renders via serde (`80` → `"80"`); a string is itself; a bool →
/// `"true"`/`"false"`; a container binds its compact JSON; null = undefined.
fn json_scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        other => serde_json::to_string(other).ok(),
    }
}

/// The result of resolving a request against its `[requests]` shape.
#[derive(Debug, Clone, Default)]
pub struct RequestScope {
    /// Every resolved var, `name → value` and `shape.name → value`. Fed to a
    /// policy `when`.
    pub vars: crate::core::policy::VarMap,
    /// The scope-bound `(name, value)` pairs, SORTED by name. What
    /// [`scope_digest`] hashes into the grant identity. Empty ⇒ nothing bound.
    pub bound: Vec<(String, String)>,
    /// The shape's consent template (`{{ vars.x | filter }}` syntax).
    pub consent: Option<String>,
    /// The matched shape's name (its `[requests.<name>]` key).
    pub shape: String,
    /// Every var the matched shape declares, resolved on this request or not.
    pub declared: Vec<String>,
    /// The matched shape's `scope`: the var names whose values bind an
    /// approval of a request on this path.
    pub binds: Vec<String>,
}

impl RequestScope {
    /// The digest of the bound values — the grant-identity extension.
    pub fn digest(&self) -> String {
        scope_digest(&self.bound)
    }
}

/// A bound value larger than this is bound by digest, not verbatim, so the op
/// that carries it (through the approval relay) stays small. 8 KiB keeps a
/// normal email/JSON field verbatim (the console renders it legibly) while a
/// message with a big attachment degrades to a summary instead of 413-ing.
const BOUND_VALUE_CAP: usize = 8 * 1024;

/// Cap a bound value: verbatim if small, else `sha256:<hex>#<len>` — applied
/// identically at op-create AND at redeem, so the grant identity is stable; the
/// console shows the marker when it can't render the (absent) full value.
fn cap_bound_value(v: &str) -> String {
    if v.len() <= BOUND_VALUE_CAP {
        v.to_string()
    } else {
        use sha2::{Digest, Sha256};
        format!("sha256:{:x}#{}", Sha256::digest(v.as_bytes()), v.len())
    }
}

/// A stable digest over the sorted `(var, value)` pairs a shape binds. `""` when
/// nothing is bound, so a request with no shape / empty scope collapses to the
/// Phase-1 `(conn, method, host, path)` key (no field binding). The approve
/// write and the redeem read compute this identically over the same pairs, so a
/// tampered field value yields a different key → a miss → a fresh prompt.
pub fn scope_digest(bound: &[(String, String)]) -> String {
    if bound.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    // Length-prefix each field so `(ab, c)` and `(a, bc)` can't collide.
    for (k, v) in bound {
        h.update((k.len() as u64).to_le_bytes());
        h.update(k.as_bytes());
        h.update((v.len() as u64).to_le_bytes());
        h.update(v.as_bytes());
    }
    format!("{:x}", h.finalize())
}

// ── Vault-custom definitions ──────────────────────────────────────────────────

/// Why a vault service entry named `"<id> (conflict copy)"` is not loaded:
/// the sync kept a second version of `<id>` beside the first.
pub const CONFLICT_COPY_REASON: &str = "a conflict copy: the service was changed in two places at once and both versions were kept; keep the one you want in the console";

/// A vault's own service definitions (`aux.services`, id → stored entry) as
/// the daemon brokers them: every entry the gate admits under its storage key
/// (so the key is the declared id), with its stored policy.toml if any, and
/// whose id is not a compiled one (a custom def never shadows a built-in),
/// with its policy reduced to the parts that tighten
/// ([`ServiceDef::for_vault`]). The skipped ids come back with the reason. The
/// unlock bootstrap loads exactly this set, so every other reader of
/// `aux.services` (the proxy, the console's registry view) agrees with what is
/// enforced.
pub fn vault_custom_services(
    aux_services: &std::collections::BTreeMap<String, source::StoredService>,
    reg: &ServiceRegistry,
) -> (HashMap<String, ServiceDef>, Vec<(String, String)>) {
    let mut defs = HashMap::new();
    let mut skipped = Vec::new();
    for (id, entry) in aux_services {
        if crate::storage::item::is_conflict_copy_name(id) {
            skipped.push((id.clone(), CONFLICT_COPY_REASON.to_string()));
            continue;
        }
        if reg.get(id).is_some() {
            skipped.push((id.clone(), "shadows a built-in id".to_string()));
            continue;
        }
        match entry.admit(id) {
            Ok(def) => {
                defs.insert(id.clone(), def.for_vault().0);
            }
            Err(problems) => {
                skipped.push((id.clone(), format!("rejected: {}", problems.join("; "))))
            }
        }
    }
    (defs, skipped)
}

/// The definitions a vault's connections resolve against: the vault's own
/// (custom) defs first, else the compiled registry, the same lookup the proxy
/// uses for a connection's service.
#[derive(Clone, Copy)]
pub struct ServiceDefs<'a> {
    pub reg: &'a ServiceRegistry,
    pub custom: &'a HashMap<String, ServiceDef>,
}

impl<'a> ServiceDefs<'a> {
    pub fn get(&self, id: &str) -> Option<&'a ServiceDef> {
        self.custom.get(id).or_else(|| self.reg.get(id))
    }

    /// Every service id a connection could name (compiled ∪ custom), sorted
    /// and deduplicated.
    pub fn ids(&self) -> Vec<&'a str> {
        let mut ids: Vec<&'a str> = self
            .reg
            .iter_sorted()
            .into_iter()
            .map(|(id, _)| id)
            .chain(self.custom.keys().map(String::as_str))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

// ── ServiceRegistry ───────────────────────────────────────────────────────────

pub struct ServiceRegistry {
    /// Every definition the gate admitted, with its policy (policy.toml or
    /// inline) compiled inside it.
    services: HashMap<String, ServiceDef>,
}

/// Read a definition file, refusing one over the size limit without reading
/// it whole (the gate re-checks the bytes it is given).
fn read_capped(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    file.take(limits::MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() > limits::MAX_FILE_BYTES {
        return Err(format!(
            "larger than the {}-byte limit",
            limits::MAX_FILE_BYTES
        ));
    }
    String::from_utf8(buf).map_err(|_| "not UTF-8".to_string())
}

/// One service directory's files: (id = directory name, service.toml,
/// optional policy.toml).
type ServiceDirFiles = (
    String,
    Result<String, String>,
    Option<Result<String, String>>,
);

impl ServiceRegistry {
    /// Load all service definitions in priority layers, each through the gate
    /// (a definition and its policy.toml are admitted or skipped together,
    /// never mixed across layers):
    /// 1. Compiled-in defaults (always loaded as base)
    /// 2. $SAFECLAW_DATA/services/ (runtime override for dev/deployment)
    /// 3. ~/.safeclaw/services/ (user-installed services, highest priority)
    pub fn load() -> Self {
        let mut services = HashMap::new();
        // id → the policy.toml text its admitted definition carries, so an
        // override directory without a policy.toml keeps the policy of the
        // definition it overrides.
        let mut policy_texts = HashMap::new();

        // Layer 1: compiled-in defaults (always loaded as base)
        Self::load_compiled_defaults(&mut services, &mut policy_texts);

        // Layer 2: $SAFECLAW_DATA/services/ override
        for files in Self::discover_service_dirs() {
            Self::admit_dir(files, &mut services, &mut policy_texts);
        }

        // Layer 3: ~/.safeclaw/services/ (user-installed, overrides everything)
        Self::load_user_services(&mut services, &mut policy_texts);

        tracing::info!("Loaded {} service definitions", services.len());
        Self { services }
    }

    /// Build a registry from ONLY the compiled-in (in-tree) services — no
    /// `$SAFECLAW_DATA` / user-installed overrides, no filesystem I/O. Used by
    /// offline tooling (`sc registry`) and CI to render the exact catalog a
    /// freshly-built daemon serves, without booting a server or reading any
    /// deployment state.
    pub fn compiled_only() -> Self {
        let mut services = HashMap::new();
        Self::load_compiled_defaults(&mut services, &mut HashMap::new());
        Self { services }
    }

    /// Admit one service directory's files through the gate, keyed by the
    /// directory name; a definition that fails is logged and skipped. A
    /// directory with no policy.toml and no inline `[policy]` that overrides
    /// a definition which had a policy.toml keeps that policy (admitted again,
    /// paired with the new service.toml, so every cross-check reruns); if the
    /// two no longer fit, the override is skipped and the earlier definition
    /// stays. True when the directory's definition was admitted.
    fn admit_dir(
        (id, service, policy): ServiceDirFiles,
        services: &mut HashMap<String, ServiceDef>,
        policy_texts: &mut HashMap<String, String>,
    ) -> bool {
        let shown = crate::util::terminal_safe(&id).into_owned();
        let skip = |problems: Vec<String>| {
            tracing::warn!("service {} skipped: {}", shown, problems.join("; "));
            false
        };
        let svc = match service {
            Ok(s) => s,
            Err(e) => return skip(vec![e]),
        };
        let own_policy = match policy {
            Some(Ok(p)) => Some(p),
            Some(Err(e)) => return skip(vec![format!("policy.toml: {}", e)]),
            None => None,
        };
        if let Some(p) = own_policy {
            return match gate::admit(Some(&id), &svc, Some(&p)) {
                Ok(def) => {
                    services.insert(id.clone(), def);
                    policy_texts.insert(id, p);
                    true
                }
                Err(problems) => skip(problems),
            };
        }
        let def = match gate::admit(Some(&id), &svc, None) {
            Ok(def) => def,
            Err(problems) => return skip(problems),
        };
        let kept = policy_texts
            .get(&id)
            .filter(|_| def.policy.is_none())
            .cloned();
        let Some(kept) = kept else {
            // Its own inline policy, or nothing to keep.
            policy_texts.remove(&id);
            services.insert(id, def);
            return true;
        };
        match gate::admit(Some(&id), &svc, Some(&kept)) {
            Ok(def) => {
                tracing::info!(
                    "service {}: the override has no policy.toml; keeping the policy of the definition it overrides",
                    shown
                );
                services.insert(id, def);
                true
            }
            Err(problems) => {
                tracing::warn!(
                    "service {} override skipped: it has no policy.toml and does not fit the policy it would keep ({}); the earlier definition stays",
                    shown,
                    problems.join("; ")
                );
                false
            }
        }
    }

    /// One directory's files, read under the size limit.
    fn read_dir_files(id: String, dir: &std::path::Path) -> ServiceDirFiles {
        let service =
            read_capped(&dir.join("service.toml")).map_err(|e| format!("service.toml: {}", e));
        let policy_path = dir.join("policy.toml");
        let policy = policy_path.exists().then(|| read_capped(&policy_path));
        (id, service, policy)
    }

    fn discover_service_dirs() -> Vec<ServiceDirFiles> {
        let mut results = vec![];

        // Check $SAFECLAW_DATA/services/ first (runtime override)
        if let Ok(data) = std::env::var("SAFECLAW_DATA") {
            let dir = std::path::Path::new(&data).join("services");
            if dir.is_dir() {
                Self::scan_dir(&dir, &mut results);
                if !results.is_empty() {
                    return results;
                }
            }
        }

        // Fallback: relative to binary (for dev / standalone installs)
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let dir = parent.join("services");
                if dir.is_dir() {
                    Self::scan_dir(&dir, &mut results);
                    if !results.is_empty() {
                        return results;
                    }
                }
            }
        }

        results
    }

    /// Scan for service.toml and policy.toml files. Supports both flat and nested layouts.
    fn scan_dir(base: &std::path::Path, results: &mut Vec<ServiceDirFiles>) {
        let Ok(entries) = std::fs::read_dir(base) else {
            return;
        };
        let dir_id = |p: &std::path::Path| {
            p.file_name()
                .and_then(|n| n.to_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Check if this directory itself has service.toml (flat layout)
            if path.join("service.toml").exists() {
                if let Some(id) = dir_id(&path) {
                    results.push(Self::read_dir_files(id, &path));
                }
                continue;
            }

            // Otherwise, scan one level deeper — tolerant reader for the
            // retired nested services/{category}/{id}/ layout (pre-tags
            // user-installed dirs may still carry it).
            let Ok(sub_entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for sub_entry in sub_entries.flatten() {
                let sub_path = sub_entry.path();
                if sub_path.is_dir() && sub_path.join("service.toml").exists() {
                    if let Some(id) = dir_id(&sub_path) {
                        results.push(Self::read_dir_files(id, &sub_path));
                    }
                }
            }
        }
    }

    /// Load user-installed services from ~/.safeclaw/services/.
    /// Skips directories with a `.disabled` marker file.
    fn load_user_services(
        services: &mut HashMap<String, ServiceDef>,
        policy_texts: &mut HashMap<String, String>,
    ) {
        let user_dir = match user_services_dir() {
            Some(d) if d.is_dir() => d,
            _ => return,
        };

        let Ok(entries) = std::fs::read_dir(&user_dir) else {
            return;
        };
        let mut count = 0u32;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Skip disabled services
            if path.join(".disabled").exists() {
                continue;
            }

            let id = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            if !path.join("service.toml").exists() {
                continue;
            }
            if Self::admit_dir(Self::read_dir_files(id, &path), services, policy_texts) {
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!(
                "Loaded {} user-installed services from {}",
                count,
                user_dir.display()
            );
        }
    }

    /// Compiled-in service definitions, admitted through the same gate as
    /// every other source (the compiled-defs tests hold each one to it).
    fn load_compiled_defaults(
        services: &mut HashMap<String, ServiceDef>,
        policy_texts: &mut HashMap<String, String>,
    ) {
        let policies: HashMap<&str, &str> = crate::generated_services::compiled_policy_tomls()
            .iter()
            .copied()
            .collect();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            match gate::admit(Some(id), toml_str, policies.get(id).copied()) {
                Ok(def) => {
                    services.insert(id.to_string(), def);
                    if let Some(p) = policies.get(id) {
                        policy_texts.insert(id.to_string(), p.to_string());
                    }
                }
                Err(problems) => {
                    tracing::error!("compiled service {} rejected: {}", id, problems.join("; "))
                }
            }
        }
    }

    /// Resolve a service by name. Returns None if not found.
    pub fn get(&self, service_name: &str) -> Option<&ServiceDef> {
        self.services.get(service_name)
    }

    /// Iterate all loaded service definitions, sorted by id for stable ordering.
    /// Used by the `/v/{vid}/registry` endpoint.
    pub fn iter_sorted(&self) -> Vec<(&str, &ServiceDef)> {
        let mut entries: Vec<(&str, &ServiceDef)> =
            self.services.iter().map(|(k, v)| (k.as_str(), v)).collect();
        entries.sort_by_key(|(k, _)| *k);
        entries
    }

    /// Classification tags for a service; empty for unknown ids and untagged
    /// (custom) services — no tag floor applies then, only the global floor.
    pub fn service_tags(&self, service_name: &str) -> &[String] {
        self.services
            .get(service_name)
            .map(|d| d.service.tags.as_slice())
            .unwrap_or(&[])
    }

    /// The stored secret role that backs a **registry** service's credential.
    /// Thin wrapper over [`ServiceDef::env_role`] — a registry-only lookup.
    /// A connection may reference a vault-custom service (`aux.services`) that
    /// is NOT in the compiled registry; such a caller must resolve the
    /// `ServiceDef` custom-awarely (registry `.or_else(custom_service)`) and
    /// call `def.env_role()` directly, or it will miss the custom def and fall
    /// back to the connection id — the bug this split removes.
    pub fn service_env_key(&self, service_id: &str) -> Option<String> {
        self.services.get(service_id).and_then(|d| d.env_role())
    }

    /// The `/token` body style for a service's `[oauth2]`: `oauth_style`,
    /// defaulting to `form`.
    pub fn oauth_style(&self, oauth: &OAuth2Def) -> OAuthStyle {
        match oauth.oauth_style.as_deref() {
            Some("json") => OAuthStyle::Json,
            _ => OAuthStyle::Form,
        }
    }

    /// A service's `[oauth2]` client/endpoint config with the defaults applied
    /// (loopback redirect_uri). A missing field is `None` (caller decides
    /// whether it's fatal).
    /// Ports the on-demand OAuth auto-catch listener may bind: the loopback
    /// targets announced by LOCALLY-INSTALLED service defs (compiled-in +
    /// `$SAFECLAW_DATA` + `~/.safeclaw/services`) plus the canonical default —
    /// today `{8765, 1455}` (google-suite default + openai_codex's registered
    /// callback). This is the SECURITY BOUNDARY for which ports a connect can
    /// open: vault-synced custom defs (`aux.services`) are deliberately NOT
    /// consulted, or vault write access would escalate into "bind arbitrary
    /// local ports on every device". A custom service still gets auto-catch —
    /// exactly when its redirect lands on a target some local def already
    /// announces (in practice: the canonical 8765 the custom form defaults to).
    pub fn loopback_allowlist(&self) -> std::collections::HashSet<u16> {
        let mut allowed: std::collections::HashSet<u16> = loopback_port(DEFAULT_LOOPBACK_REDIRECT)
            .into_iter()
            .collect();
        for def in self.services.values() {
            if let Some(oauth) = def.oauth2() {
                if let Some(port) = loopback_port(&self.resolve_oauth_config(oauth).redirect_uri) {
                    allowed.insert(port);
                }
            }
        }
        allowed
    }

    pub fn resolve_oauth_config(&self, oauth: &OAuth2Def) -> ResolvedOAuthConfig {
        ResolvedOAuthConfig {
            token_url: oauth.token_url.clone(),
            client_id: oauth.client_id.clone(),
            client_secret: oauth.client_secret.clone(),
            redirect_uri: oauth
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string()),
        }
    }

    /// The public OAuth wiring broadcast for `service_id` — see
    /// [`ConnectDescriptor`]. `None` when the service isn't oauth2 or its
    /// section lacks an authorization_url + client_id.
    pub fn connect_descriptor(&self, service_id: &str) -> Option<ConnectDescriptor> {
        let def = self.services.get(service_id)?;
        let oauth = def.oauth2()?;
        self.connect_descriptor_for(oauth)
    }

    /// [`Self::connect_descriptor`] for an `[oauth2]` section directly — shared
    /// with per-vault custom services that don't live in `self.services`.
    pub fn connect_descriptor_for(&self, oauth: &OAuth2Def) -> Option<ConnectDescriptor> {
        Some(ConnectDescriptor {
            provider: oauth
                .provider
                .clone()
                .unwrap_or_else(|| "custom".to_string()),
            authorization_url: oauth.authorization_url.clone()?,
            token_url: oauth.token_url.clone(),
            client_id: oauth.client_id.clone()?,
            client_secret: oauth.client_secret.clone(),
            scopes: oauth.scopes.clone(),
            pkce: oauth.pkce.unwrap_or(true),
            redirect_uri: oauth
                .redirect_uri
                .clone()
                .unwrap_or_else(|| DEFAULT_LOOPBACK_REDIRECT.to_string()),
            oauth_style: match oauth.oauth_style.as_deref() {
                Some("json") => "json".to_string(),
                _ => "form".to_string(),
            },
            authorize_params: oauth.authorize_params.clone(),
        })
    }

    /// A service's default read/write floor: its policy's `[default]`
    /// (policy.toml) or `[policy.levels]` (inline).
    pub fn default_policy_levels(&self, service_name: &str) -> Option<crate::core::policy::Levels> {
        self.services
            .get(service_name)?
            .policy
            .as_ref()?
            .defaults
            .clone()
    }

    /// A service's rules (policy.toml `[[rule]]` or inline `[[policy.rules]]`),
    /// compiled at the gate. `None` when it declares none.
    pub fn default_policy_rules(
        &self,
        service_name: &str,
    ) -> Option<&[crate::core::policy::PolicyRule]> {
        let rules = &self.services.get(service_name)?.policy.as_ref()?.rules;
        (!rules.is_empty()).then_some(rules.as_slice())
    }

    /// Return all service definitions (for catalog/UI use).
    pub fn all(&self) -> &HashMap<String, ServiceDef> {
        &self.services
    }
}

// ── User service directory ───────────────────────────────────────────────────

/// Returns ~/.safeclaw/services/ path, or None if home dir can't be resolved.
pub fn user_services_dir() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".safeclaw").join("services"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::policy::AccessLevel;

    fn reg(services: HashMap<String, ServiceDef>) -> ServiceRegistry {
        ServiceRegistry { services }
    }

    fn def(toml: &str) -> ServiceDef {
        gate::admit_toml(toml).unwrap_or_else(|e| panic!("fixture rejected: {:?}", e))
    }

    // ── inline [policy] (the policy.toml alternative) ────────────────────────

    const INLINE: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_KEY"]
[policy.levels]
read = "deny"
write = "ask-always"
[[policy.rules]]
method = "delete"
path_exact = "/v1/things/"
level = "ask"
"#;

    #[test]
    fn inline_policy_compiles_levels_and_rules() {
        let d = def(INLINE);
        let p = d.policy.as_ref().expect("inline policy");
        let sl = p.defaults.as_ref().unwrap();
        assert_eq!(sl.read, Some(AccessLevel::Deny));
        assert_eq!(sl.write, Some(AccessLevel::AskAlways));
        assert_eq!(p.rules.len(), 1);
        assert_eq!(
            p.rules[0].match_patterns,
            vec!["delete /v1/things".to_string()]
        );
        assert_eq!(p.rules[0].level, Some(AccessLevel::Ask));
        // A lowercase method word is a method at this rule source too.
        let mut services = HashMap::new();
        services.insert("acme".to_string(), d);
        let r = reg(services);
        let rules = r.default_policy_rules("acme").unwrap().to_vec();
        let access = crate::core::policy::evaluate(
            "DELETE",
            "/v1/things",
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            r.default_policy_levels("acme").as_ref(),
            &crate::core::policy::Policy::default(),
            &[],
        );
        assert_eq!(access, AccessLevel::Ask);
    }

    #[test]
    fn inline_policy_never_drops_a_rule() {
        // path_suffix was skipped by the old converter; now the whole
        // definition is rejected, as is an unknown level or field.
        for bad in [
            INLINE.replace("path_exact = \"/v1/things/\"", "path_suffix = \"/things\""),
            INLINE.replace("level = \"ask\"", "level = \"sometimes\""),
            INLINE.replace("read = \"deny\"", "read = \"nope\""),
            INLINE.replace("level = \"ask\"", "level = \"ask\"\nlabel = \"x\""),
            INLINE.replace("method = \"delete\"", "method = \"DEL ETE\""),
        ] {
            assert!(gate::admit_toml(&bad).is_err(), "{bad}");
        }
        // Declared twice (inline and policy.toml): rejected, never mixed.
        let file = "[default]\nread = \"allow\"\n";
        let e = gate::admit(None, INLINE, Some(file)).unwrap_err();
        assert!(e.iter().any(|m| m.contains("declared twice")), "{e:?}");
    }

    // ── a vault definition's policy only tightens ───────────────────────────

    const VAULT_DEF: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_KEY"]
[policy.levels]
read = "allow"
write = "ask"
ttl = 60
[[policy.rules]]
method = "DELETE"
path_exact = "/v1/things"
level = "deny"
[[policy.rules]]
method = "POST"
path_exact = "/v1/pay"
level = "allow"
"#;

    #[test]
    fn vault_definitions_keep_only_the_parts_that_tighten() {
        let (d, notes) = def(VAULT_DEF).for_vault();
        let p = d.policy.as_ref().unwrap();
        assert_eq!(p.rules.len(), 1, "the allow rule is not applied");
        assert_eq!(p.rules[0].level, Some(AccessLevel::Deny));
        let lv = p.defaults.as_ref().unwrap();
        assert_eq!(lv.read, None, "read = allow is not applied");
        assert_eq!(lv.write, Some(AccessLevel::Ask));
        assert_eq!(lv.ttl, Some(60));
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("#2 (allow)")), "{notes:?}");
        assert!(
            notes.iter().any(|n| n.contains("default read = allow")),
            "{notes:?}"
        );
        // The registry reader applies it, so the console shows what is enforced.
        let mut aux = std::collections::BTreeMap::new();
        aux.insert("acme".to_string(), VAULT_DEF.into());
        let (defs, _) = vault_custom_services(&aux, &ServiceRegistry::compiled_only());
        assert_eq!(defs["acme"].policy.as_ref().unwrap().rules.len(), 1);
        // Nothing that tightens: no policy at all.
        let loose = VAULT_DEF
            .replace("level = \"deny\"", "level = \"allow\"")
            .replace("write = \"ask\"", "write = \"allow\"");
        let (d, notes) = def(&loose).for_vault();
        assert!(d.policy.is_none());
        assert_eq!(notes.len(), 5, "{notes:?}");
    }

    #[test]
    fn override_without_policy_keeps_the_overridden_policy() {
        let compiled = ServiceRegistry::compiled_only();
        let mut services = compiled.services.clone();
        let mut texts: HashMap<String, String> = crate::generated_services::compiled_policy_tomls()
            .iter()
            .map(|(id, t)| (id.to_string(), t.to_string()))
            .collect();
        let svc = crate::generated_services::compiled_service_tomls()
            .iter()
            .find(|(id, _)| *id == "github")
            .unwrap()
            .1
            .replace("hosts = [", "hosts = [\"git.acme.example\", ");
        assert!(ServiceRegistry::admit_dir(
            ("github".into(), Ok(svc.clone()), None),
            &mut services,
            &mut texts
        ));
        let gh = &services["github"];
        assert!(gh.service.hosts.iter().any(|h| h == "git.acme.example"));
        let rules = &gh.policy.as_ref().expect("compiled policy kept").rules;
        assert!(rules.iter().any(|r| r.id.as_deref() == Some("delete-repo")));
        // An override whose own policy.toml is given uses it instead.
        let own =
            "[[rule]]\nid = \"only\"\nlabel = \"Only\"\nmatch = \"DELETE /x\"\nlevel = \"deny\"\n";
        assert!(ServiceRegistry::admit_dir(
            ("github".into(), Ok(svc.clone()), Some(Ok(own.to_string()))),
            &mut services,
            &mut texts
        ));
        assert_eq!(services["github"].policy.as_ref().unwrap().rules.len(), 1);
        // An override that no longer fits the kept policy is skipped whole.
        let mut services = compiled.services.clone();
        let mut texts: HashMap<String, String> = [(
            "github".to_string(),
            "[[rule]]\nid = \"w\"\nlabel = \"W\"\nmatch = \"POST /x\"\nwhen = \"vars.amount > 1\"\nlevel = \"deny\"\n".to_string(),
        )]
        .into_iter()
        .collect();
        assert!(!ServiceRegistry::admit_dir(
            ("github".into(), Ok(svc), None),
            &mut services,
            &mut texts
        ));
        assert!(!services["github"]
            .service
            .hosts
            .iter()
            .any(|h| h == "git.acme.example"));
    }

    #[test]
    fn compiled_circleci_policy_covers_every_slug_form() {
        use crate::core::policy::{evaluate, Policy};
        let r = ServiceRegistry::compiled_only();
        let rules = r.default_policy_rules("circleci").unwrap().to_vec();
        let eval = |m: &str, p: &str| {
            evaluate(
                m,
                p,
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                r.default_policy_levels("circleci").as_ref(),
                &Policy::default(),
                &["dev".into()],
            )
        };
        for slug in [
            "gh%2Forg%2Frepo",
            "gh/org%2Frepo",
            "gh%2Forg/repo",
            "gh/org/repo",
            "circleci/o-id/p-id",
        ] {
            for (m, tail) in [
                ("POST", "pipeline"),
                ("POST", "pipeline/run"),
                ("POST", "envvar"),
                ("POST", "schedule"),
                ("POST", "checkout-key"),
                ("PATCH", "settings"),
            ] {
                let path = format!("/api/v2/project/{}/{}", slug, tail);
                assert_eq!(eval(m, &path), AccessLevel::Ask, "{m} {path}");
            }
            // API v1.1 on the same host.
            for (m, tail) in [
                ("POST", ""),
                ("POST", "/build"),
                ("POST", "/tree/main"),
                ("POST", "/tree/feature%2Fx"),
                ("POST", "/tree/feature/x"),
                ("POST", "/42/retry"),
                ("POST", "/42/ssh"),
                ("POST", "/42/ssh-users"),
                ("POST", "/envvar"),
                ("POST", "/ssh-key"),
                ("POST", "/checkout-key"),
            ] {
                let path = format!("/api/v1.1/project/{}{}", slug, tail);
                assert_eq!(eval(m, &path), AccessLevel::Ask, "{m} {path}");
            }
            // Reads and removals ride the floor.
            let pipelines = format!("/api/v2/project/{}/pipeline", slug);
            assert_eq!(eval("GET", &pipelines), AccessLevel::Allow);
            let settings = format!("/api/v2/project/{}/settings", slug);
            assert_eq!(eval("GET", &settings), AccessLevel::Allow);
            let envvar = format!("/api/v2/project/{}/envvar/NAME", slug);
            assert_eq!(eval("DELETE", &envvar), AccessLevel::Allow);
            let v1_envvar = format!("/api/v1.1/project/{}/envvar/NAME", slug);
            assert_eq!(eval("DELETE", &v1_envvar), AccessLevel::Allow);
            assert_eq!(eval("GET", &v1_envvar), AccessLevel::Allow);
        }
        for (m, p) in [
            ("PUT", "/api/v2/context/c-1/environment-variable/TOKEN"),
            ("POST", "/api/v2/pipeline/continue"),
            ("POST", "/api/v2/workflow/w-1/rerun"),
            ("PATCH", "/api/v2/schedule/s-1"),
            (
                "POST",
                "/api/v2/projects/p-1/pipeline-definitions/d-1/triggers",
            ),
            ("PATCH", "/api/v2/projects/p-1/triggers/t-1"),
            ("POST", "/api/v2/workflow/w-1/approve/a-1"),
            ("POST", "/api/v2/projects/p-1/rollback"),
            ("POST", "/api/v2/projects/p-1/pipeline-definitions"),
            ("PATCH", "/api/v2/projects/p-1/pipeline-definitions/d-1"),
            ("PATCH", "/api/v2/org/o-1/oidc-custom-claims"),
            ("PATCH", "/api/v2/org/o-1/project/p-1/oidc-custom-claims"),
            ("DELETE", "/api/v2/context/c-1/restrictions/r-1"),
        ] {
            assert_eq!(eval(m, p), AccessLevel::Ask, "{m} {p}");
        }
        for (m, p) in [
            ("GET", "/api/v2/me"),
            ("GET", "/api/v2/projects/p-1/pipeline-definitions"),
            ("GET", "/api/v2/org/o-1/oidc-custom-claims"),
            ("POST", "/api/v2/context/c-1/restrictions"),
        ] {
            assert_eq!(eval(m, p), AccessLevel::Allow, "{m} {p}");
        }
    }

    // ── v4 service.toml parsing ──────────────────────────────────────────────

    #[test]
    fn parse_direct_service_hosts_and_secrets() {
        let toml_str = r#"
[service]
id = "github"
name = "GitHub"

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def = def(toml_str);
        assert_eq!(def.service.id, "github");
        assert_eq!(def.service.hosts, vec!["api.github.com", "github.com"]);
        assert_eq!(def.service.secrets, vec!["GITHUB_TOKEN"]);
        assert!(def.auth.is_none());
    }

    #[test]
    fn parse_oauth2_service() {
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"

hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]

[auth]
type = "oauth2"
provider = "google"
scopes = ["https://www.googleapis.com/auth/gmail.send"]
refresh_token = "GMAIL_REFRESH_TOKEN"
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        let o = def.oauth2().unwrap();
        assert_eq!(o.provider.as_deref(), Some("google"));
        assert_eq!(o.refresh_token, "GMAIL_REFRESH_TOKEN");
        assert_eq!(o.scopes.len(), 1);
        assert!(o.exposes.is_empty());
    }

    #[test]
    fn parse_oauth2_exposes() {
        let toml_str = r#"
[service]
id = "openai_codex"
name = "OpenAI Codex"

hosts = ["api.openai.com"]
secrets = ["OPENAI_CODEX_REFRESH_TOKEN"]

[auth]
type = "oauth2"
provider = "openai"
refresh_token = "OPENAI_CODEX_REFRESH_TOKEN"
exposes = ["account_id"]
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        assert_eq!(def.oauth2().unwrap().exposes, vec!["account_id"]);
    }

    #[test]
    fn parse_auth_snaplii_and_mint_roles() {
        let toml_str = r#"
[service]
id = "snaplii"
name = "Snaplii"
hosts = ["aipayment.snaplii.com"]
secrets = ["SNAPLII_API_KEY"]

[auth]
type = "snaplii"
"#;
        let def = def(toml_str);
        assert!(matches!(def.auth, Some(AuthDef::Snaplii(_))));
        assert!(def.oauth2().is_none());
        // The mint input (and thus env_role / never-injectable role) is the
        // first secrets entry.
        assert_eq!(def.mint_input_role().as_deref(), Some("SNAPLII_API_KEY"));
        assert_eq!(def.env_role().as_deref(), Some("SNAPLII_API_KEY"));
    }

    #[test]
    fn auth_section_rejects_unknown_type_and_legacy_oauth2_section() {
        // Unknown mechanism type fails at parse, never a silent static fallback.
        let bad = r#"
[service]
id = "x"
name = "X"
hosts = ["x.example.com"]

[auth]
type = "sigv4-someday"
"#;
        assert!(gate::admit_toml(bad).is_err());

        // The retired section name is an unknown field at the top level. The
        // error points at it by line and column; definition text is never
        // echoed.
        let legacy = r#"
[service]
id = "x"
name = "X"
hosts = ["x.example.com"]

[oauth2]
refresh_token = "K"
"#;
        let err = gate::admit_toml(legacy).unwrap_err().join("; ");
        assert!(
            err.contains("unknown field at line 7") && !err.contains("oauth2"),
            "error should point at the offending section: {}",
            err
        );
    }

    #[test]
    fn deny_unknown_fields_rejects_tool_and_v3_sections() {
        // A tool-named section is rejected — sections are auth MECHANISMS only.
        let git = r#"
[service]
id = "x"
name = "X"
hosts = ["x.com"]
[git]
helper = "sc"
"#;
        assert!(gate::admit_toml(git).is_err(), "[git] must be rejected");
        // A stale v3 `[[upstream]]` is rejected too.
        let v3 = r#"
[service]
id = "x"
name = "X"
[[upstream]]
id = "default"
url = "https://x.com"
"#;
        assert!(
            gate::admit_toml(v3).is_err(),
            "[[upstream]] must be rejected"
        );
    }

    #[test]
    fn oauth2_secret_drives_service_env_key() {
        let toml_str = r#"
[service]
id = "gmail"
name = "Gmail"
hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GMAIL_REFRESH_TOKEN"
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        let mut services = HashMap::new();
        services.insert("gmail".into(), def);
        let r = reg(services);
        assert_eq!(
            r.service_env_key("gmail").as_deref(),
            Some("GMAIL_REFRESH_TOKEN")
        );
    }

    #[test]
    fn direct_secret_drives_service_env_key() {
        let toml_str = r#"
[service]
id = "github"
name = "GitHub"
hosts = ["api.github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def = def(toml_str);
        let mut services = HashMap::new();
        services.insert("github".into(), def);
        let r = reg(services);
        assert_eq!(r.service_env_key("github").as_deref(), Some("GITHUB_TOKEN"));
    }

    #[test]
    fn custom_def_env_role_resolves_when_registry_misses() {
        // A vault-custom `[oauth2]` service (e.g. a user-added "gcp"): NOT in the
        // compiled registry. `service_env_key(id)` is a registry-only lookup, so
        // it returns None and the ask/approve path would fall back to the
        // connection id as the op `target` — the "secret 'gcp' not found" bug.
        // Resolving the def and calling `env_role()` directly is source-agnostic
        // and names the real refresh key.
        let toml_str = r#"
[service]
id = "gcp"
name = "Google Cloud"
hosts = ["compute.googleapis.com"]
secrets = ["GCP_REFRESH_TOKEN"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GCP_REFRESH_TOKEN"
authorization_url = "https://auth.example.com/authorize"
token_url = "https://auth.example.com/token"
client_id = "public-client"
"#;
        let def = def(toml_str);
        // The pure projection resolves regardless of where the def came from —
        // the single source of truth both the forward and approve paths share.
        assert_eq!(def.env_role().as_deref(), Some("GCP_REFRESH_TOKEN"));
        // A registry WITHOUT this custom service confirms the asymmetry the fix
        // removes: the id-based lookup misses, so a caller that may face a custom
        // service must go through the resolved def's `env_role`, never the
        // registry-only `service_env_key`.
        let r = reg(HashMap::new());
        assert_eq!(r.service_env_key("gcp"), None);
    }

    #[test]
    fn setup_block_parses_plain_prose() {
        let toml_str = r#"
setup = """
Put the phantom in the URL: sc run -- git clone https://x:__sc__github__@github.com/o/r
"""

[service]
id = "github"
name = "GitHub"
hosts = ["github.com"]
secrets = ["GITHUB_TOKEN"]
"#;
        let def = def(toml_str);
        let setup = def.setup.as_deref().unwrap();
        assert!(setup.contains("sc run --"));
    }

    // ── [oauth2] inline resolution ────────────────────────────────────────────

    #[test]
    fn oauth_style_defaults_form_inline_json_wins() {
        let r = reg(HashMap::new());
        let oauth = |style: Option<&str>| OAuth2Def {
            provider: None,
            scopes: vec![],
            refresh_token: "RT".into(),
            id_token: None,
            exposes: vec![],
            claims: HashMap::new(),
            authorization_url: None,
            token_url: None,
            client_id: None,
            client_secret: None,
            pkce: None,
            redirect_uri: None,
            oauth_style: style.map(|s| s.to_string()),
            authorize_params: HashMap::new(),
        };
        assert!(matches!(r.oauth_style(&oauth(None)), OAuthStyle::Form));
        assert!(matches!(
            r.oauth_style(&oauth(Some("form"))),
            OAuthStyle::Form
        ));
        assert!(matches!(
            r.oauth_style(&oauth(Some("json"))),
            OAuthStyle::Json
        ));
    }

    // ── compiled-in sanity (post-migration) ──────────────────────────────────

    #[test]
    fn compiled_services_parse_and_validate() {
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            let def = gate::admit(Some(id), toml_str, None)
                .unwrap_or_else(|e| panic!("service '{}' rejected: {:?}", id, e));
            // Non-hidden services must anchor at least one host.
            if !def.service.hidden {
                assert!(
                    !def.service.hosts.is_empty(),
                    "service '{}' declares no hosts",
                    id
                );
            }
            // [oauth2] is self-sufficient: every compiled oauth service must be
            // inline-complete (there is no template layer to fill gaps).
            if let Some(o) = def.oauth2() {
                assert!(
                    !o.refresh_token.is_empty(),
                    "service '{}' oauth2 has empty refresh_token",
                    id
                );
                assert!(
                    o.authorization_url.is_some(),
                    "service '{}' oauth2 missing authorization_url",
                    id
                );
                assert!(
                    o.token_url.is_some(),
                    "service '{}' oauth2 missing token_url",
                    id
                );
                assert!(
                    o.client_id.is_some(),
                    "service '{}' oauth2 missing client_id",
                    id
                );
            }
        }
    }

    #[test]
    fn compiled_codex_resolves_fully_inline() {
        let mut services = HashMap::new();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            if let Ok(def) = gate::admit_toml(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let r = reg(services);
        let oauth = r
            .get("openai_codex")
            .unwrap()
            .oauth2()
            .cloned()
            .expect("codex [auth] oauth2");
        let cfg = r.resolve_oauth_config(&oauth);
        assert_eq!(
            cfg.token_url.as_deref(),
            Some("https://auth.openai.com/oauth/token")
        );
        assert_eq!(
            cfg.client_id.as_deref(),
            Some("app_EMoamEEZ73f0CkXaXp7hrann")
        );
        assert!(cfg.client_secret.is_none(), "codex is pure PKCE");
        assert_eq!(cfg.redirect_uri, "http://localhost:1455/auth/callback");
        let d = r
            .connect_descriptor("openai_codex")
            .expect("codex descriptor");
        assert!(d.pkce);
        assert_eq!(d.provider, "openai");
        assert_eq!(
            d.authorize_params
                .get("codex_cli_simplified_flow")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            oauth.claims.get("account_id").map(Vec::as_slice),
            Some(
                &[
                    "https://api.openai.com/auth".to_string(),
                    "chatgpt_account_id".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn descriptor_labels_custom_when_no_provider() {
        let r = reg(HashMap::new());
        let mut oauth: OAuth2Def = toml::from_str(
            "refresh_token=\"RT\"\nauthorization_url=\"https://b.example/auth\"\nclient_id=\"cid\"\n[authorize_params]\nprompt=\"login\"\n",
        ).unwrap();
        let d = r.connect_descriptor_for(&oauth).unwrap();
        assert_eq!(d.provider, "custom");
        assert_eq!(d.client_id, "cid");
        assert_eq!(
            d.authorize_params.get("prompt").map(String::as_str),
            Some("login")
        );
        // A provider name is a pure label — it changes nothing but the label.
        oauth.provider = Some("g".into());
        let d2 = r.connect_descriptor_for(&oauth).unwrap();
        assert_eq!(d2.provider, "g");
        assert_eq!(d2.client_id, "cid");
    }

    #[test]
    fn compiled_google_trio_is_inline_complete_and_shares_one_client() {
        let mut services = HashMap::new();
        for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
            if let Ok(def) = gate::admit_toml(toml_str) {
                services.insert(id.to_string(), def);
            }
        }
        let r = reg(services);
        let mut client_ids = std::collections::HashSet::new();
        for id in ["gmail", "gdrive", "gcalendar"] {
            let oauth = r
                .get(id)
                .unwrap()
                .oauth2()
                .cloned()
                .unwrap_or_else(|| panic!("{} missing [oauth2]", id));
            assert_eq!(oauth.provider.as_deref(), Some("google"), "{}", id);
            let cfg = r.resolve_oauth_config(&oauth);
            assert_eq!(
                cfg.token_url.as_deref(),
                Some("https://oauth2.googleapis.com/token"),
                "{}",
                id
            );
            client_ids.insert(cfg.client_id.expect("client_id"));
            assert!(!oauth.scopes.is_empty(), "{} scopes", id);
        }
        assert_eq!(
            client_ids.len(),
            1,
            "the trio must share ONE Desktop client (rotate together)"
        );
    }

    #[test]
    fn connect_descriptor_for_gmail_mirrors_the_full_wiring() {
        // The descriptor is a 1:1 mirror of the def — a def can only hold
        // public-client material (validator), so nothing is withheld and the
        // console can display the wiring faithfully.
        let r = ServiceRegistry::load();
        let d = r.connect_descriptor("gmail").expect("gmail is oauth2");
        assert_eq!(d.provider, "google");
        assert!(d
            .authorization_url
            .starts_with("https://accounts.google.com/"));
        assert_eq!(
            d.token_url.as_deref(),
            Some("https://oauth2.googleapis.com/token")
        );
        assert!(d.client_id.ends_with(".apps.googleusercontent.com"));
        assert!(
            d.client_secret
                .as_deref()
                .is_some_and(|s| s.starts_with("GOCSPX-")),
            "the public Desktop client_secret is part of the wiring"
        );
        assert!(d.pkce);
        assert_eq!(d.oauth_style, "form");
        assert!(d.scopes.iter().any(|s| s.contains("gmail.send")));
        assert_eq!(
            d.authorize_params.get("access_type").map(String::as_str),
            Some("offline")
        );
    }

    #[test]
    fn connect_descriptor_none_for_non_oauth_service() {
        let r = ServiceRegistry::load();
        assert!(r.connect_descriptor("openai").is_none());
    }

    #[test]
    fn compiled_gmail_policy_resolves_risk_tiers() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("gmail")
            .expect("gmail policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(
                m,
                p,
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy,
                &["app".into()],
            )
        };
        assert_eq!(
            eval("GET", "/gmail/v1/users/me/messages"),
            AccessLevel::Allow
        );
        assert_eq!(
            eval("GET", "/gmail/v1/users/me/messages/abc123"),
            AccessLevel::Ask
        );
        assert_eq!(
            eval("POST", "/gmail/v1/users/me/messages/send"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("DELETE", "/gmail/v1/users/me/messages/abc123"),
            AccessLevel::AskAlways
        );
    }

    #[test]
    fn compiled_cratesio_policy_gates_publish_surface() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("cratesio")
            .expect("cratesio policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(
                m,
                p,
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy,
                &["app".into()],
            )
        };
        // Routine traffic rides the allow floor.
        assert_eq!(eval("GET", "/api/v1/me"), AccessLevel::Allow);
        assert_eq!(eval("GET", "/api/v1/crates"), AccessLevel::Allow);
        assert_eq!(
            eval("PUT", "/api/v1/crates/serde/follow"),
            AccessLevel::Allow
        );
        // Publish + version availability ask once per window.
        assert_eq!(eval("PUT", "/api/v1/crates/new"), AccessLevel::Ask);
        assert_eq!(
            eval("DELETE", "/api/v1/crates/serde/1.0.219/yank"),
            AccessLevel::Ask
        );
        assert_eq!(
            eval("PUT", "/api/v1/crates/serde/1.0.219/unyank"),
            AccessLevel::Ask
        );
        assert_eq!(
            eval("PATCH", "/api/v1/crates/serde/1.0.219"),
            AccessLevel::Ask
        );
        // Ownership + supply chain gate every time.
        assert_eq!(
            eval("PUT", "/api/v1/crates/serde/owners"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("DELETE", "/api/v1/crates/serde/owners"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("POST", "/api/v1/trusted_publishing/github_configs"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("PATCH", "/api/v1/crates/serde"),
            AccessLevel::AskAlways
        );
        // Publish approvals cover a workspace release train, not one crate.
        let publish = rules
            .iter()
            .find(|ru| ru.id.as_deref() == Some("publish"))
            .unwrap();
        assert_eq!(publish.ttl, Some(1800));
    }

    #[test]
    fn compiled_railway_policy_gates_only_destroys() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("railway")
            .expect("railway policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let eval = |body: &str| {
            // The whole API is one POST endpoint; the mutation name lives in the body.
            evaluate(
                "POST",
                "/graphql/v2",
                Some(body),
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy,
                &["app".into()],
            )
        };
        // Routine GraphQL (queries + non-destroy mutations) rides the allow floor.
        assert_eq!(
            eval(r#"{"query":"query { me { name } }"}"#),
            AccessLevel::Allow
        );
        assert_eq!(
            eval(r#"{"query":"mutation { serviceInstanceRedeploy(id: 1) }"}"#),
            AccessLevel::Allow
        );
        assert_eq!(
            eval(r#"{"query":"mutation { variableUpsert(input: {}) }"}"#),
            AccessLevel::Allow
        );
        // Each irreversible destroy is caught by mutation name (incl. the biggest,
        // workspaceDelete — every project under the workspace).
        assert_eq!(
            eval(r#"{"query":"mutation { workspaceDelete(id: \"w\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { projectDelete(id: \"p\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { serviceDelete(id: \"s\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { environmentDelete(id: \"e\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { volumeDelete(id: \"v\") }"}"#),
            AccessLevel::AskAlways
        );
        // Minting a durable token escapes the broker → gated.
        assert_eq!(
            eval(r#"{"query":"mutation { projectTokenCreate(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { apiTokenCreate(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
        // Access-posture changes (member/role/transfer/ssh key) → gated.
        assert_eq!(
            eval(r#"{"query":"mutation { projectMemberAdd(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { projectTransferInitiate(id: \"p\") }"}"#),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval(r#"{"query":"mutation { sshPublicKeyCreate(input: {}) }"}"#),
            AccessLevel::AskAlways
        );
    }

    #[test]
    fn compiled_supabase_policy_gates_only_project_delete() {
        use crate::core::policy::{evaluate, AccessLevel, Policy};
        let r = ServiceRegistry::load();
        let rules = r
            .default_policy_rules("supabase")
            .expect("supabase policy.toml must parse and yield rules")
            .to_vec();
        let policy = Policy::default();
        let eval = |m: &str, p: &str| {
            evaluate(
                m,
                p,
                None,
                &crate::core::policy::VarMap::new(),
                Some(&rules),
                None,
                &policy,
                &["app".into()],
            )
        };
        // Routine developer work — incl. arbitrary SQL — rides the allow floor.
        assert_eq!(eval("GET", "/v1/projects"), AccessLevel::Allow);
        assert_eq!(eval("POST", "/v1/projects"), AccessLevel::Allow);
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/database/query"),
            AccessLevel::Allow
        );
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/secrets"),
            AccessLevel::Allow
        );
        // A sub-resource delete (function, secret, branch) is recoverable → floor.
        assert_eq!(
            eval("DELETE", "/v1/projects/abcdef/functions/hello"),
            AccessLevel::Allow
        );
        // Editing/deleting a specific api-key is a deeper path → floor.
        assert_eq!(
            eval("PATCH", "/v1/projects/abcdef/api-keys/key1"),
            AccessLevel::Allow
        );
        // Deleting the whole project is the one irreversible catastrophe.
        assert_eq!(
            eval("DELETE", "/v1/projects/abcdef"),
            AccessLevel::AskAlways
        );
        // Minting a new API key escapes the broker → gated.
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/api-keys"),
            AccessLevel::AskAlways
        );
        // Opening the database to the network → gated on BOTH endpoints (no bypass).
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/network-restrictions/apply"),
            AccessLevel::AskAlways
        );
        assert_eq!(
            eval("PATCH", "/v1/projects/abcdef/network-restrictions"),
            AccessLevel::AskAlways
        );
        // Handing the project to another owner → gated.
        assert_eq!(
            eval("POST", "/v1/projects/abcdef/claim-token"),
            AccessLevel::AskAlways
        );
    }

    // ── [requests] extraction + scope digest (Phase 2) ───────────────────────

    fn snaplii_def() -> ServiceDef {
        gate::admit_toml(
            r#"
[service]
id = "snaplii"
name = "Snaplii"
hosts = ["aipayment.snaplii.com"]
secrets = ["SNAPLII_API_KEY"]
[auth]
type = "snaplii"
[requests.purchase]
match = "POST /v2/purchase"
vars.amount   = "/amount"
vars.merchant = "/merchant_id"
vars.force    = { in = "query", at = "force" }
scope   = ["amount", "merchant"]
consent = "Buy from {{ vars.merchant }} for {{ vars.amount }}"
"#,
        )
        .unwrap()
    }

    #[test]
    fn extract_resolves_body_and_query_vars() {
        let def = snaplii_def();
        let body = r#"{"amount": 80, "merchant_id": "m_1", "nonce": "xyz"}"#;
        let rs = def
            .extract_request_scope("POST", "/v2/purchase", Some("force=true"), Some(body))
            .expect("purchase shape matches");
        // Bare + qualified names both present, values stringified.
        assert_eq!(rs.vars.get("amount").map(String::as_str), Some("80"));
        assert_eq!(
            rs.vars.get("purchase.amount").map(String::as_str),
            Some("80")
        );
        assert_eq!(rs.vars.get("merchant").map(String::as_str), Some("m_1"));
        assert_eq!(rs.vars.get("force").map(String::as_str), Some("true"));
        // Bound = the scope subset, sorted; the query `force` and body `nonce`
        // are NOT bound (not in scope).
        assert_eq!(
            rs.bound,
            vec![
                ("amount".to_string(), "80".to_string()),
                ("merchant".to_string(), "m_1".to_string())
            ]
        );
        assert_eq!(
            rs.consent.as_deref(),
            Some("Buy from {{ vars.merchant }} for {{ vars.amount }}")
        );
        // The matched shape, for the connection-rule check.
        assert_eq!(rs.shape, "purchase");
        assert_eq!(rs.declared, vec!["amount", "force", "merchant"]);
        assert_eq!(rs.binds, vec!["amount", "merchant"]);
    }

    #[test]
    fn extract_none_on_no_match_and_undefined_vars_omitted() {
        let def = snaplii_def();
        // No shape matches a GET → None (Phase-1 path-only grant).
        assert!(def
            .extract_request_scope("GET", "/v2/balance", None, None)
            .is_none());
        // Missing body field → that var is simply absent (not an error).
        let rs = def
            .extract_request_scope("POST", "/v2/purchase", None, Some(r#"{"amount": 5}"#))
            .unwrap();
        assert_eq!(rs.vars.get("amount").map(String::as_str), Some("5"));
        assert!(rs.vars.get("merchant").is_none());
        // Only the resolved scope var is bound.
        assert_eq!(rs.bound, vec![("amount".to_string(), "5".to_string())]);
    }

    #[test]
    fn consent_is_one_template_with_pipe_filters() {
        // Plain interpolation: `{{ vars.x }}` → the referenced var names.
        let def = snaplii_def();
        let purchase = &def.requests["purchase"];
        assert_eq!(
            purchase.consent.as_deref(),
            Some("Buy from {{ vars.merchant }} for {{ vars.amount }}")
        );
        assert_eq!(
            consent_tokens(purchase.consent.as_deref().unwrap()),
            vec!["merchant", "amount"]
        );
        // A rich renderer is a FILTER in the same one template field — same
        // `{{ x | filter }}` grammar as git's `{{ secret.X | basic }}`.
        let refs = consent_refs("{{ vars.raw | email }}");
        assert_eq!(
            refs,
            vec![ConsentRef {
                var: "raw".into(),
                filter: Some("email".into())
            }]
        );
        // A filter still counts its var for show ⊆ bind.
        assert_eq!(consent_tokens("{{ vars.raw | email }}"), vec!["raw"]);
        // A token without the `vars.` prefix is ignored (left literal).
        assert!(consent_tokens("hello {{ merchant }}").is_empty());
    }

    #[test]
    fn scope_digest_stable_and_tamper_sensitive() {
        // The $80/$180 guarantee at the digest level: same bound values → same
        // digest (order-independent); a changed value → a different digest; a
        // field NOT in scope (a nonce) never affects it.
        let d80 = scope_digest(&[
            ("amount".into(), "80".into()),
            ("merchant".into(), "m_1".into()),
        ]);
        let d80_reordered = scope_digest(&[
            ("merchant".into(), "m_1".into()),
            ("amount".into(), "80".into()),
        ]);
        let d180 = scope_digest(&[
            ("amount".into(), "180".into()),
            ("merchant".into(), "m_1".into()),
        ]);
        // digest() sorts, so reordering the input pairs is irrelevant once sorted;
        // here we compare the raw fn on already-sorted inputs.
        assert_eq!(d80, d80);
        assert_ne!(d80, d180);
        assert_ne!(d80, d80_reordered); // raw fn is order-sensitive…
                                        // …which is why extract_request_scope always sorts before hashing:
        let def = snaplii_def();
        let a = def
            .extract_request_scope(
                "POST",
                "/v2/purchase",
                None,
                Some(r#"{"amount":80,"merchant_id":"m_1"}"#),
            )
            .unwrap();
        let b = def
            .extract_request_scope(
                "POST",
                "/v2/purchase",
                Some("force=1"),
                Some(r#"{"merchant_id":"m_1","amount":80,"nonce":"Q"}"#),
            )
            .unwrap();
        assert_eq!(
            a.digest(),
            b.digest(),
            "same bound values (nonce/query ignored) → same digest"
        );
        let c = def
            .extract_request_scope(
                "POST",
                "/v2/purchase",
                None,
                Some(r#"{"amount":180,"merchant_id":"m_1"}"#),
            )
            .unwrap();
        assert_ne!(
            a.digest(),
            c.digest(),
            "changed amount → different digest → re-prompt"
        );
        // Empty scope collapses to "" (the Phase-1 key).
        assert_eq!(scope_digest(&[]), "");
    }

    #[test]
    fn large_bound_value_is_digested_not_verbatim() {
        // A big field (a whole email) binds by digest so the op stays small —
        // and the digest is still deterministic and tamper-sensitive.
        let big = "x".repeat(BOUND_VALUE_CAP + 100);
        let capped = cap_bound_value(&big);
        assert!(
            capped.starts_with("sha256:"),
            "large value → digest marker, got {capped}"
        );
        assert!(capped.len() < 100, "marker is small, not the whole value");
        // Small values stay verbatim.
        assert_eq!(cap_bound_value("hello"), "hello");
        // Same big value → same marker (stable identity); a changed one differs.
        assert_eq!(cap_bound_value(&big), capped);
        assert_ne!(cap_bound_value(&"y".repeat(BOUND_VALUE_CAP + 100)), capped);
    }
}
