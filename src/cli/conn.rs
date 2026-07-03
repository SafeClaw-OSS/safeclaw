//! Shared creation of RAW connections (`service: None` + anchored hosts) for
//! `sc set --host` and `sc connect`, plus the `aux.services` write for
//! `sc service add`. One place enforces the id + host rules so the two verbs
//! can't drift, and one place mutates the sealed `aux` value in a way that
//! preserves every other key.

use serde_json::{json, Value};

use crate::service::validate::host_egress_allowed;

/// A connection id / phantom `<conn>` segment: `[a-z0-9_]`, starts
/// alphanumeric, no `__` (the phantom delimiter). Same rule the resolver and
/// service-id validator use.
pub fn valid_conn_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || s.contains("__") {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A secret role KEY on a connection: env-style `[A-Za-z0-9_]`, non-empty, not
/// starting with a digit, no `__` (its lowercase becomes a phantom role
/// segment).
pub fn valid_role(s: &str) -> bool {
    if s.is_empty() || s.contains("__") {
        return false;
    }
    let first_ok = s
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false);
    first_ok && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validate a raw connection's anchor host: an exact FQDN — no scheme / path /
/// port, no wildcard, and not a private / metadata / loopback target. (Raw
/// connections pin exact FQDNs; `*.suffix` lives only in a curated service
/// definition where a human confirms the pin.)
pub fn validate_raw_host(h: &str) -> Result<(), String> {
    let h = h.trim();
    if h.is_empty() {
        return Err("host cannot be empty".into());
    }
    if h.contains("://") || h.contains('/') || h.contains("{{") {
        return Err(format!("host '{}' must be a bare domain (no scheme/path)", h));
    }
    if h.contains(':') {
        return Err(format!("host '{}' must not carry a port", h));
    }
    if h.contains('*') {
        return Err(format!(
            "host '{}' — wildcards aren't allowed on a raw connection; anchor an exact domain",
            h
        ));
    }
    if !host_egress_allowed(h) {
        return Err(format!(
            "host '{}' is loopback / private / metadata — not a valid egress target",
            h
        ));
    }
    Ok(())
}

/// Insert (or replace) a raw connection into the vault `aux` value, preserving
/// every other aux key. `hosts` are the anchored exact FQDNs. The written shape
/// (`{ "hosts": [...] }`, `service` omitted) deserializes to
/// `Connection { service: None, hosts: Some(..) }`.
pub fn insert_raw_connection(aux: &mut Value, conn_id: &str, hosts: &[String]) {
    ensure_object(aux);
    let obj = aux.as_object_mut().unwrap();
    let conns = obj.entry("connections").or_insert_with(|| json!({}));
    if !conns.is_object() {
        *conns = json!({});
    }
    conns
        .as_object_mut()
        .unwrap()
        .insert(conn_id.to_string(), json!({ "hosts": hosts }));
}

/// Store a custom service definition (verbatim v4 toml source) under
/// `aux.services[<id>]`, preserving every other aux key.
pub fn insert_custom_service(aux: &mut Value, id: &str, toml_source: &str) {
    ensure_object(aux);
    let obj = aux.as_object_mut().unwrap();
    let svcs = obj.entry("services").or_insert_with(|| json!({}));
    if !svcs.is_object() {
        *svcs = json!({});
    }
    svcs.as_object_mut()
        .unwrap()
        .insert(id.to_string(), Value::String(toml_source.to_string()));
}

fn ensure_object(aux: &mut Value) {
    if !aux.is_object() {
        *aux = json!({});
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_id_rules() {
        assert!(valid_conn_id("github"));
        assert!(valid_conn_id("github_work"));
        assert!(valid_conn_id("s3"));
        assert!(!valid_conn_id("GitHub")); // uppercase
        assert!(!valid_conn_id("git__hub")); // double underscore
        assert!(!valid_conn_id("git-hub")); // hyphen
        assert!(!valid_conn_id("_x")); // must start alphanumeric
        assert!(!valid_conn_id(""));
    }

    #[test]
    fn role_rules() {
        assert!(valid_role("GITHUB_TOKEN"));
        assert!(valid_role("api_token"));
        assert!(!valid_role("1TOKEN")); // starts with digit
        assert!(!valid_role("A__B")); // double underscore
        assert!(!valid_role("A B")); // space
    }

    #[test]
    fn raw_host_rejects_unsafe() {
        assert!(validate_raw_host("api.stripe.com").is_ok());
        assert!(validate_raw_host("https://api.stripe.com").is_err());
        assert!(validate_raw_host("api.stripe.com/x").is_err());
        assert!(validate_raw_host("api.stripe.com:443").is_err());
        assert!(validate_raw_host("*.stripe.com").is_err());
        assert!(validate_raw_host("localhost").is_err());
        assert!(validate_raw_host("169.254.169.254").is_err());
        assert!(validate_raw_host("10.0.0.5").is_err());
    }

    #[test]
    fn insert_raw_preserves_other_aux_keys() {
        let mut aux = json!({ "version": 4, "stores": { "native-secrets": {} } });
        insert_raw_connection(&mut aux, "stripe_key", &["api.stripe.com".to_string()]);
        assert_eq!(aux["version"], 4);
        assert!(aux["stores"].is_object());
        assert_eq!(
            aux["connections"]["stripe_key"]["hosts"][0],
            "api.stripe.com"
        );
        // No `service` key (None ⇒ raw).
        assert!(aux["connections"]["stripe_key"].get("service").is_none());
    }

    #[test]
    fn insert_custom_service_preserves_aux() {
        let mut aux = json!({ "version": 4, "connections": { "a": { "hosts": ["x.com"] } } });
        insert_custom_service(&mut aux, "myapi", "[service]\nid=\"myapi\"\n");
        assert_eq!(aux["services"]["myapi"], "[service]\nid=\"myapi\"\n");
        assert!(aux["connections"]["a"].is_object());
    }
}
