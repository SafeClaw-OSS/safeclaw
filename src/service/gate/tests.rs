use super::*;

const GITHUB: &str = r#"
[service]
id = "github"
name = "GitHub"

hosts = ["api.github.com", "github.com"]
secrets = ["GITHUB_TOKEN"]
"#;

fn ok(toml: &str) -> ServiceDef {
    admit(None, toml, None).unwrap_or_else(|e| panic!("expected admit, got {:?}", e))
}

fn rejected(toml: &str) -> Vec<String> {
    admit(None, toml, None).expect_err("expected rejection")
}

fn rejected_with(toml: &str, policy: &str) -> Vec<String> {
    admit(None, toml, Some(policy)).expect_err("expected rejection")
}

fn mentions(errs: &[String], needle: &str) -> bool {
    errs.iter().any(|e| e.contains(needle))
}

// ── compiled-in definitions ──────────────────────────────────────────────────

/// Every compiled service, with its policy.toml, passes the gate under its
/// directory name: the build-time check for in-tree definitions (a `when`
/// var that is not declared and bound, an unknown level, a bad regex, ...
/// fails the suite here).
#[test]
fn compiled_services_pass_validator() {
    let policies: HashMap<&str, &str> = crate::generated_services::compiled_policy_tomls()
        .iter()
        .copied()
        .collect();
    for (id, toml_str) in crate::generated_services::compiled_service_tomls() {
        let def = admit(Some(id), toml_str, policies.get(id).copied())
            .unwrap_or_else(|e| panic!("compiled service '{}' rejected: {:?}", id, e));
        // Every body regex is compiled at load.
        for rule in def.policy.iter().flat_map(|p| p.rules.iter()) {
            if let Some(b) = &rule.body {
                assert!(b.error().is_none(), "{id}: {:?}", b);
            }
            assert!(rule.level.is_some(), "{id}: every rule decides");
        }
    }
    for (id, _) in crate::generated_services::compiled_policy_tomls() {
        assert!(
            crate::generated_services::compiled_service_tomls()
                .iter()
                .any(|(s, _)| s == id),
            "policy.toml for '{}' has no service.toml",
            id
        );
    }
    let reg = crate::service::ServiceRegistry::compiled_only();
    assert_eq!(
        reg.all().len(),
        crate::generated_services::compiled_service_tomls().len(),
        "the registry loads every compiled service"
    );
}

// ── one gate: storage key = declared id ──────────────────────────────────────

#[test]
fn key_must_equal_declared_id() {
    assert!(admit(Some("github"), GITHUB, None).is_ok());
    let e = admit(Some("gitlab"), GITHUB, None).unwrap_err();
    assert!(
        mentions(&e, "stored as 'gitlab' but declares id 'github'"),
        "{e:?}"
    );
    // The vault reader applies it: a def stored under another key is skipped.
    let mut aux = std::collections::BTreeMap::new();
    aux.insert(
        "mine".to_string(),
        GITHUB.replace("\"github\"", "\"other\""),
    );
    let reg = crate::service::ServiceRegistry::compiled_only();
    let (defs, skipped) = crate::service::vault_custom_services(&aux, &reg);
    assert!(defs.is_empty());
    assert!(skipped[0].1.contains("declares id 'other'"), "{skipped:?}");
}

// ── service.toml schema (moved from the old validator) ───────────────────────

#[test]
fn valid_direct_service() {
    ok(GITHUB);
}

#[test]
fn oauth2_must_be_inline_complete() {
    let label_only = r#"
[service]
id = "gmail"
name = "Gmail"
hosts = ["gmail.googleapis.com"]
secrets = ["GMAIL_REFRESH_TOKEN"]
[auth]
type = "oauth2"
provider = "google"
refresh_token = "GMAIL_REFRESH_TOKEN"
"#;
    rejected(label_only);
}

const ACME_OAUTH: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_REFRESH_TOKEN"]
[auth]
type = "oauth2"
authorization_url = "https://auth.acme.dev/authorize"
token_url = "https://auth.acme.dev/token"
client_id = "acme-public"
refresh_token = "ACME_REFRESH_TOKEN"
"#;

#[test]
fn inline_oauth2_is_self_sufficient() {
    ok(ACME_OAUTH);
    let labeled = ACME_OAUTH.replace(
        "type = \"oauth2\"",
        "type = \"oauth2\"\nprovider = \"acme\"",
    );
    ok(&labeled);
    rejected(&ACME_OAUTH.replace("token_url = \"https://auth.acme.dev/token\"\n", ""));
    rejected(&ACME_OAUTH.replace("https://auth.acme.dev/token", "http://auth.acme.dev/token"));
    let secret = ACME_OAUTH.replace(
        "client_id = \"acme-public\"",
        "client_id = \"acme-public\"\nclient_secret = \"shh\"",
    );
    ok(&secret);
    // The retired client_type assertion is an unknown field.
    rejected(&secret.replace(
        "client_secret = \"shh\"",
        "client_secret = \"shh\"\nclient_type = \"public\"",
    ));
    // oauth_style is form or json, nothing else.
    ok(&ACME_OAUTH.replace(
        "client_id = \"acme-public\"",
        "client_id = \"acme-public\"\noauth_style = \"json\"",
    ));
    let e = rejected(&ACME_OAUTH.replace(
        "client_id = \"acme-public\"",
        "client_id = \"acme-public\"\noauth_style = \"xml\"",
    ));
    assert!(mentions(&e, "oauth_style 'xml' is unknown"), "{e:?}");
}

#[test]
fn oauth2_claims_and_authorize_params_are_checked() {
    let base = format!("{ACME_OAUTH}exposes = [\"account_id\"]\n");
    ok(&format!(
        "{base}[auth.claims]\naccount_id = [\"ns\", \"leaf\"]\n"
    ));
    rejected(&format!("{base}[auth.claims]\nother = [\"x\"]\n"));
    rejected(&format!("{base}[auth.claims]\naccount_id = []\n"));
    ok(&format!(
        "{base}[auth.authorize_params]\nfoo_flag = \"true\"\n"
    ));
    rejected(&format!(
        "{base}[auth.authorize_params]\nredirect_uri = \"https://evil.example\"\n"
    ));
}

#[test]
fn rejects_tool_named_and_v3_sections() {
    let e = rejected(&format!("{}\n[git]\nhelper = \"x\"\n", GITHUB));
    assert!(mentions(&e, "parse error"), "{e:?}");
    let v3 = "[service]\nid = \"x\"\nname = \"X\"\n[[upstream]]\nid = \"default\"\nurl = \"https://x.com\"\n";
    assert!(mentions(&rejected(v3), "parse error"));
}

#[test]
fn unknown_fields_are_rejected_everywhere() {
    // A typo in [service] (it used to be silently ignored there).
    let e = rejected(&GITHUB.replace("secrets =", "secret ="));
    assert!(mentions(&e, "unknown field `secret`"), "{e:?}");
    // [requests] shape, and the table form of a var.
    let req =
        "[requests.buy]\nmatch = \"POST /buy\"\nvars.amount = \"/amount\"\nscope = [\"amount\"]\n";
    ok(&format!("{GITHUB}{req}"));
    rejected(&format!("{GITHUB}{req}scopes = [\"amount\"]\n"));
    rejected(&format!(
        "{GITHUB}[requests.buy]\nmatch = \"POST /buy\"\nvars.f = {{ in = \"query\", at = \"f\", as = \"int\" }}\n"
    ));
    // policy.toml: top level, [default], [[rule]].
    let rule =
        "[[rule]]\nid = \"del\"\nlabel = \"Delete\"\nmatch = \"DELETE /x\"\nlevel = \"ask\"\n";
    assert!(admit(None, GITHUB, Some(rule)).is_ok());
    rejected_with(GITHUB, &format!("{rule}[extra]\na = 1\n"));
    rejected_with(
        GITHUB,
        &format!("[default]\nread = \"allow\"\nwirte = \"deny\"\n{rule}"),
    );
    rejected_with(
        GITHUB,
        &rule.replace("level = \"ask\"", "level = \"ask\"\nlevl = \"deny\""),
    );
}

#[test]
fn host_rules() {
    let ok_toml = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.com", "*.openai.azure.com"]
secrets = ["ACME_TOKEN"]
"#;
    ok(ok_toml);
    for (from, to) in [
        ("\"*.openai.azure.com\"", "\"*\""),
        ("\"*.openai.azure.com\"", "\"*.com\""),
        ("\"*.openai.azure.com\"", "\"*.10.0.0.1\""),
        ("\"*.openai.azure.com\"", "\"a.*.azure.com\""),
        ("\"api.acme.com\"", "\"https://api.acme.com\""),
        ("\"api.acme.com\"", "\"api.acme.com/v1\""),
        ("\"api.acme.com\"", "\"api.acme.com:443\""),
    ] {
        rejected(&ok_toml.replace(from, to));
    }
}

#[test]
fn rejects_private_loopback_and_noncanonical_hosts() {
    for bad in [
        "10.0.0.5",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "localhost",
        "2130706433",
        "0x7f.1",
        "0177.0.0.1",
        "127.1",
    ] {
        let e = rejected(&GITHUB.replace("\"api.github.com\"", &format!("\"{}\"", bad)));
        assert!(
            mentions(&e, "not an egress target") || mentions(&e, "non-canonical"),
            "{bad}: {e:?}"
        );
    }
    // Names are not special-cased: a self-hosted `.internal` service is fine.
    ok(&GITHUB.replace("\"api.github.com\"", "\"metadata.google.internal\""));
    ok(&GITHUB.replace("\"api.github.com\"", "\"vault.corp.internal\""));
}

#[test]
fn urls_are_parsed_by_the_client_parser_and_refuse_userinfo() {
    for (from, to) in [
        (
            "https://auth.acme.dev/token",
            "https://user@auth.acme.dev/token",
        ),
        ("https://auth.acme.dev/token", "https://2130706433/token"),
        ("https://auth.acme.dev/token", "https://127.0.0.1/token"),
        (
            "https://auth.acme.dev/authorize",
            "https://u:p@auth.acme.dev/authorize",
        ),
    ] {
        rejected(&ACME_OAUTH.replace(from, to));
    }
    let redirect = |u: &str| {
        ACME_OAUTH.replace(
            "client_id = \"acme-public\"",
            &format!("client_id = \"acme-public\"\nredirect_uri = \"{}\"", u),
        )
    };
    ok(&redirect("http://127.0.0.1:8765/safeclaw/oauth/callback"));
    rejected(&redirect("http://me@127.0.0.1:8765/cb"));
    rejected(&redirect("javascript:alert(1)"));
}

#[test]
fn rejects_bad_service_id_and_roles() {
    for id in ["Git Hub", "git__hub", "git-hub", ""] {
        let e = rejected(&GITHUB.replace("id = \"github\"", &format!("id = \"{}\"", id)));
        assert!(mentions(&e, "not valid"), "{id}: {e:?}");
    }
    let e = rejected(&GITHUB.replace("\"GITHUB_TOKEN\"", "\"github-token\""));
    assert!(mentions(&e, "env key"));
    let e = rejected(&GITHUB.replace("name = \"GitHub\"", "name = \" \""));
    assert!(mentions(&e, "name must not be empty"));
}

#[test]
fn secret_url_optional_and_web_only() {
    let with = GITHUB.replace(
        "secrets = [\"GITHUB_TOKEN\"]",
        "secrets = [\"GITHUB_TOKEN\"]\nsecret_url = \"https://github.com/settings/tokens?type=beta\"",
    );
    ok(&with);
    let e = rejected(&with.replace(
        "https://github.com/settings/tokens?type=beta",
        "javascript:alert(1)",
    ));
    assert!(mentions(&e, "secret_url"));
    rejected(&with.replace("https://github.com/", "https://me@github.com/"));
}

#[test]
fn tags_group_and_activation() {
    ok(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\ntags = [\"app\", \"code-hosting\"]",
    ));
    for bad in [
        "[\"App\"]",
        "[\"code_hosting\"]",
        "[\"-app\"]",
        "[\"\"]",
        "[\"app\", \"app\"]",
    ] {
        let e = rejected(&GITHUB.replace(
            "name = \"GitHub\"",
            &format!("name = \"GitHub\"\ntags = {}", bad),
        ));
        assert!(mentions(&e, "tag"), "{bad}");
    }
    ok(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\nactivation = \"auto\"\ngroup = \"gitlab\"",
    ));
    rejected(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\nactivation = \"always\"",
    ));
    rejected(&GITHUB.replace(
        "name = \"GitHub\"",
        "name = \"GitHub\"\ngroup = \"Git Lab\"",
    ));
}

// ── [requests] ───────────────────────────────────────────────────────────────

const REQ_SERVICE: &str = r#"
[service]
id = "pay"
name = "Pay"
hosts = ["api.pay.com"]
secrets = ["PAY_KEY"]
[requests.purchase]
match = "POST /buy"
vars.amount = "/amount"
scope = ["amount"]
consent = "Spend {{ vars.amount }}"
"#;

#[test]
fn requests_shapes_are_checked() {
    ok(REQ_SERVICE);
    let e = rejected(&REQ_SERVICE.replace("{{ vars.amount }}", "{{ vars.secret }}"));
    assert!(mentions(&e, "consent references '{secret}'"), "{e:?}");
    let e =
        rejected(&REQ_SERVICE.replace("scope = [\"amount\"]", "scope = [\"amount\", \"ghost\"]"));
    assert!(
        mentions(&e, "'ghost', which is not a declared var"),
        "{e:?}"
    );
    let e =
        rejected(&REQ_SERVICE.replace("scope = [\"amount\"]", "scope = [\"amount\", \"amount\"]"));
    assert!(mentions(&e, "more than once"));
    let e = rejected(&REQ_SERVICE.replace("vars.amount = \"/amount\"", "vars.amount = \"amount\""));
    assert!(mentions(&e, "must be a JSON Pointer"));
    // A match that could never match a request.
    for bad in ["/buy?x=1", "buy", "POST  buy", "POST /a/**/b", "/a b"] {
        let e = rejected(
            &REQ_SERVICE.replace("match = \"POST /buy\"", &format!("match = \"{}\"", bad)),
        );
        assert!(mentions(&e, "match"), "{bad}: {e:?}");
    }
    rejected(&REQ_SERVICE.replace("match = \"POST /buy\"", "match = []"));
}

#[test]
fn consent_filters_are_the_ones_the_console_implements() {
    let raw = |consent: &str| {
        format!(
            "[service]\nid = \"m\"\nname = \"M\"\nhosts = [\"api.m.com\"]\n[requests.send]\nmatch = \"POST /send\"\nvars.raw = \"/raw\"\nscope = [\"raw\"]\nconsent = \"{}\"\n",
            consent
        )
    };
    ok(&raw("{{ vars.raw | email }}"));
    ok(&raw("Send {{vars.raw}} now"));
    let e = rejected(&raw("{{ vars.raw | html }}"));
    assert!(
        mentions(&e, "consent filter 'html' is unknown (known: email)"),
        "{e:?}"
    );
    // A token the console's grammar does not read is refused, not left literal.
    for bad in [
        "{{ raw }}",
        "{{ vars.a-b }}",
        "{{ vars.raw",
        "{{ secret.raw | basic }}",
    ] {
        rejected(&raw(bad));
    }
}

// ── policy.toml ──────────────────────────────────────────────────────────────

const RULE: &str = r#"
[[rule]]
id = "big"
label = "Big purchase"
match = "POST /buy"
when = "vars.amount > 80"
level = "ask-always"
"#;

#[test]
fn policy_rules_are_recognized_whole_or_rejected() {
    let def = admit(None, REQ_SERVICE, Some(RULE)).expect("valid policy");
    let rule = &def.policy.as_ref().unwrap().rules[0];
    assert_eq!(rule.level, Some(AccessLevel::AskAlways));
    for (from, to, why) in [
        (
            "level = \"ask-always\"",
            "level = \"sometimes\"",
            "level 'sometimes' is unknown",
        ),
        ("level = \"ask-always\"\n", "", "declares no level"),
        ("vars.amount > 80", "amount is big", "not a valid condition"),
        (
            "vars.amount > 80",
            "vars.total > 80",
            "references var 'total'",
        ),
        (
            "label = \"Big purchase\"",
            "label = \"  \"",
            "label must not be empty",
        ),
        ("id = \"big\"", "id = \"Big One\"", "the id must be"),
        (
            "match = \"POST /buy\"",
            "match = \"POST /buy?x\"",
            "may not contain",
        ),
    ] {
        let e = rejected_with(REQ_SERVICE, &RULE.replace(from, to));
        assert!(mentions(&e, why), "{to}: {e:?}");
    }
    let dup = format!("{RULE}{RULE}");
    assert!(mentions(
        &rejected_with(REQ_SERVICE, &dup),
        "used by more than one rule"
    ));
    let bad_default = format!("[default]\nread = \"allow\"\nwrite = \"maybe\"\n{RULE}");
    assert!(mentions(
        &rejected_with(REQ_SERVICE, &bad_default),
        "level 'maybe' is unknown"
    ));
}

#[test]
fn when_var_must_be_bound() {
    let svc = REQ_SERVICE.replace(
        "vars.amount = \"/amount\"",
        "vars.amount = \"/amount\"\nvars.risk = \"/risk\"",
    );
    let policy = RULE.replace("vars.amount > 80", "vars.risk == \\\"high\\\"");
    let e = rejected_with(&svc, &policy);
    assert!(mentions(&e, "not in any shape's `scope`"), "{e:?}");
}

#[test]
fn body_regex_compiles_at_load_or_rejects() {
    let rule = |body: &str| {
        format!(
            "[[rule]]\nid = \"pub\"\nlabel = \"Make public\"\nmatch = \"PATCH /repos/*/*\"\nbody = '{}'\nlevel = \"ask-always\"\n",
            body
        )
    };
    let def = admit(None, GITHUB, Some(&rule("\"private\"\\s*:\\s*false"))).unwrap();
    assert!(def.policy.unwrap().rules[0]
        .body
        .as_ref()
        .unwrap()
        .error()
        .is_none());
    let e = rejected_with(GITHUB, &rule("(unclosed"));
    assert!(mentions(&e, "body regex"), "{e:?}");
    let e = rejected_with(GITHUB, &rule(&"a".repeat(MAX_BODY_PATTERN_BYTES + 1)));
    assert!(mentions(&e, "body is 1025 bytes"), "{e:?}");
    // Compiled size is bounded explicitly.
    let e = rejected_with(GITHUB, &rule("(\\w{50}){50}"));
    assert!(mentions(&e, "body regex"), "{e:?}");
}

#[test]
fn ask_on_the_body_where_a_shape_binds_is_rejected() {
    let body_rule = |level: &str, m: &str| {
        format!(
            "[[rule]]\nid = \"gift\"\nlabel = \"Gift cards\"\nmatch = \"{m}\"\nbody = \"gift\"\nlevel = \"{level}\"\n"
        )
    };
    for level in ["ask", "ask-always"] {
        for m in ["POST /buy", "/buy", "POST /*", "/**", "post /buy"] {
            let e = rejected_with(REQ_SERVICE, &body_rule(level, m));
            assert!(
                mentions(&e, "[requests.purchase] covers"),
                "{level} {m}: {e:?}"
            );
        }
        // Another path, or another method: no shape covers it.
        assert!(admit(None, REQ_SERVICE, Some(&body_rule(level, "POST /refund"))).is_ok());
        assert!(admit(None, REQ_SERVICE, Some(&body_rule(level, "GET /buy"))).is_ok());
    }
    // allow / deny mint no approval: a body may decide them anywhere.
    for level in ["allow", "deny"] {
        assert!(admit(None, REQ_SERVICE, Some(&body_rule(level, "POST /buy"))).is_ok());
    }
}

#[test]
fn rule_method_word_is_case_insensitive() {
    let policy = "[[rule]]\nid = \"del\"\nlabel = \"Delete repo\"\nmatch = \"delete /repos/*/*\"\nlevel = \"deny\"\n";
    let def = admit(None, GITHUB, Some(policy)).unwrap();
    let rules = def.policy.unwrap().rules;
    let decide = |m: &str, p: &str| {
        crate::core::policy::evaluate(
            m,
            p,
            None,
            &crate::core::policy::VarMap::new(),
            Some(&rules),
            None,
            &crate::core::policy::Policy::default(),
            &[],
        )
    };
    assert_eq!(decide("DELETE", "/repos/o/r"), AccessLevel::Deny);
    assert_eq!(decide("GET", "/repos/o/r"), AccessLevel::Allow);
}

// ── limits ───────────────────────────────────────────────────────────────────

#[test]
fn limits_reject_oversized_definitions() {
    let pad = format!("{GITHUB}# {}\n", "x".repeat(MAX_FILE_BYTES));
    assert!(mentions(&rejected(&pad), "the limit is"));
    let e = rejected_with(GITHUB, &format!("# {}\n", "x".repeat(MAX_FILE_BYTES)));
    assert!(mentions(&e, "policy.toml is"));

    let long = GITHUB.replace(
        "name = \"GitHub\"",
        &format!("name = \"{}\"", "n".repeat(MAX_STRING_BYTES + 1)),
    );
    assert!(mentions(&rejected(&long), "service.name is"));
    let setup = format!(
        "setup = \"\"\"\n{}\n\"\"\"\n{GITHUB}",
        "s".repeat(MAX_PROSE_BYTES + 1)
    );
    assert!(mentions(&rejected(&setup), "setup is"));

    let hosts: Vec<String> = (0..=MAX_HOSTS)
        .map(|i| format!("\"h{}.example.com\"", i))
        .collect();
    let many = GITHUB.replace(
        "hosts = [\"api.github.com\", \"github.com\"]",
        &format!("hosts = [{}]", hosts.join(", ")),
    );
    assert!(mentions(&rejected(&many), "hosts has"));

    let rules: String = (0..=MAX_RULES)
        .map(|i| {
            format!(
                "[[rule]]\nid = \"r{i}\"\nlabel = \"R\"\nmatch = \"GET /r{i}\"\nlevel = \"ask\"\n"
            )
        })
        .collect();
    assert!(mentions(&rejected_with(GITHUB, &rules), "rules has"));

    let pats: Vec<String> = (0..=MAX_MATCH_PATTERNS)
        .map(|i| format!("\"/p{}\"", i))
        .collect();
    let rule = format!(
        "[[rule]]\nid = \"m\"\nlabel = \"M\"\nmatch = [{}]\nlevel = \"ask\"\n",
        pats.join(", ")
    );
    assert!(mentions(&rejected_with(GITHUB, &rule), "match has"));
}

// ── display strings ──────────────────────────────────────────────────────────

#[test]
fn control_and_bidi_characters_are_rejected_and_never_echoed() {
    for (field, value) in [
        ("name", "Git\\u001b[31mHub"),
        ("name", "Git\\u0085Hub"),
        ("name", "Git\\u202eHub"),
        ("name", "Git\\u2066Hub"),
        ("name", "Git\\nHub"),
    ] {
        let toml = GITHUB.replace("name = \"GitHub\"", &format!("{} = \"{}\"", field, value));
        let e = rejected(&toml);
        assert!(mentions(&e, "control or bidi character"), "{value}: {e:?}");
        for m in &e {
            assert!(!m.chars().any(crate::util::is_unsafe_display_char), "{m:?}");
        }
    }
    // A rule label in policy.toml, and a table key.
    let label = "[[rule]]\nid = \"x\"\nlabel = \"Delete\\u200f repo\"\nmatch = \"DELETE /x\"\nlevel = \"ask\"\n";
    assert!(mentions(&rejected_with(GITHUB, label), "rule[0].label"));
    let key = format!("{ACME_OAUTH}[auth.authorize_params]\n\"a\\u001bb\" = \"1\"\n");
    assert!(mentions(&rejected(&key), "a key in auth.authorize_params"));
    // `setup` may carry \n and \t, nothing else.
    ok(&format!("setup = \"line one\\n\\tline two\"\n{GITHUB}"));
    let e = rejected(&format!("setup = \"ring\\u0007\"\n{GITHUB}"));
    assert!(mentions(&e, "only \\n and \\t are allowed"), "{e:?}");
    // A raw control character in the file fails the TOML parse; the message
    // that quotes the line is sanitized.
    let raw = GITHUB.replace("name = \"GitHub\"", "name = \"GitHub\"\n# \u{1b}[2J");
    if let Err(e) = admit(None, &raw, None) {
        for m in e {
            assert!(!m.contains('\u{1b}'), "{m:?}");
        }
    }
}

#[test]
fn problems_are_capped() {
    let hosts: Vec<String> = (0..MAX_HOSTS)
        .map(|i| format!("\"10.0.0.{}\"", i))
        .collect();
    let toml = GITHUB.replace(
        "hosts = [\"api.github.com\", \"github.com\"]",
        &format!("hosts = [{}]", hosts.join(", ")),
    );
    let e = rejected(&toml);
    assert_eq!(e.len(), MAX_REPORTED_PROBLEMS + 1);
    assert!(e.last().unwrap().contains("more problems"));
}

mod corpus;
