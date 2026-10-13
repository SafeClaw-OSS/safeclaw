use std::collections::BTreeMap;

use super::card::{add_card, diff, rm_card, summarize, SourceCheck};
use super::github::{self, FetchError, GitHubApi, GitObject};
use super::tar::{read_tarball, read_tarball_with};
use super::*;

const ACME: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_TOKEN"]
"#;

const ACME_POLICY: &str = r#"
[[rule]]
id = "no-delete"
label = "Delete a thing"
match = "DELETE /v1/things/*"
level = "deny"

[[rule]]
id = "pay"
label = "Pay"
match = "POST /v1/pay"
level = "ask"
"#;

fn svc(id: &str, host: &str) -> String {
    format!(
        "[service]\nid = \"{}\"\nname = \"{}\"\nhosts = [\"{}\"]\nsecrets = [\"TOKEN\"]\n",
        id, id, host
    )
}

fn gh(repo: &str, commit: char) -> ServiceSource {
    ServiceSource::Github {
        repo: repo.into(),
        path: None,
        git_ref: None,
        commit: commit.to_string().repeat(40),
    }
}

// ── source arguments ─────────────────────────────────────────────────────────

#[test]
fn parse_source_forms() {
    assert!(matches!(parse_source("./x"), Ok(SourceSpec::Local(_))));
    assert!(matches!(parse_source("/abs/x"), Ok(SourceSpec::Local(_))));
    assert!(matches!(parse_source("../x"), Ok(SourceSpec::Local(_))));
    assert!(matches!(parse_source("."), Ok(SourceSpec::Local(_))));
    assert_eq!(
        parse_source("github:Acme-Co/tools.git:services/acme").unwrap(),
        SourceSpec::GitHub(GitHubSpec {
            owner: "Acme-Co".into(),
            repo: "tools".into(),
            path: Some("services/acme".into()),
        })
    );
    assert_eq!(
        parse_source("git:acme/tools").unwrap(),
        SourceSpec::GitHub(GitHubSpec {
            owner: "acme".into(),
            repo: "tools".into(),
            path: None,
        })
    );
    assert_eq!(
        parse_source("acme/thing").unwrap(),
        SourceSpec::Registry {
            owner: "acme".into(),
            slug: "thing".into()
        }
    );
    assert_eq!(
        parse_source("github").unwrap(),
        SourceSpec::Name("github".into())
    );
    for other in [
        "https://gitlab.com/acme/tools",
        "https://github.com/acme/tools",
        "git:https://gitlab.com/a/b",
        "git@github.com:acme/tools.git",
        "gitlab:acme/tools",
    ] {
        let e = parse_source(other).unwrap_err();
        assert!(e.contains("only GitHub sources"), "{other}: {e}");
    }
    // Charset and repository escape.
    for bad in [
        "github:-acme/tools",
        "github:ac me/tools",
        "github:acme/..",
        "github:acme/tools:../etc",
        "github:acme/tools:a/./b",
        "github:acme/tools:a//b",
        "github:acme",
    ] {
        assert!(parse_source(bad).is_err(), "{bad}");
    }
}

#[test]
fn ref_charset() {
    for ok in [
        "main",
        "v1.0.0",
        "release/2026-10",
        &"a".repeat(40),
        "a1b2c3d",
    ] {
        assert!(github::check_ref(ok).is_ok(), "{ok}");
    }
    for bad in [
        "", "-x", "/x", ".x", "a..b", "x.lock", "x/", "a b", "a?b", "a%2fb", "a/.b", "x//y",
    ] {
        assert!(github::check_ref(bad).is_err(), "{bad}");
    }
    assert!(github::is_full_commit(&"0123456789abcdef".repeat(3)[..40]));
    assert!(!github::is_full_commit(&"A".repeat(40)));
    assert!(!github::is_full_commit("abc"));
}

// ── the stored form ──────────────────────────────────────────────────────────

#[test]
fn old_string_entries_still_load() {
    let legacy: StoredService = serde_json::from_value(serde_json::json!(ACME)).unwrap();
    let p = legacy.parts().unwrap();
    assert_eq!(p.service, ACME);
    assert!(p.policy.is_none() && p.source.is_none());
    // An unchanged entry is not rewritten: it serializes back as the string.
    assert_eq!(
        serde_json::to_value(&legacy).unwrap(),
        serde_json::json!(ACME)
    );

    // A vault holding both shapes loads both, the object one with its policy.
    let aux: crate::storage::plaintext::VaultAux = serde_json::from_value(serde_json::json!({
        "version": 4, "stores": {}, "store_order": [],
        "services": {
            "acme": ACME,
            "beta": { "service": svc("beta", "api.beta.dev"), "policy": ACME_POLICY.replace("/v1/things/*", "/v2/*"),
                      "source": { "kind": "github", "repo": "acme/tools", "commit": "a".repeat(40) } },
        }
    }))
    .unwrap();
    let reg = crate::service::ServiceRegistry::compiled_only();
    let (defs, skipped) = crate::service::vault_custom_services(&aux.services, &reg);
    assert!(skipped.is_empty(), "{skipped:?}");
    assert!(defs.contains_key("acme") && defs.contains_key("beta"));
    assert_eq!(defs["beta"].policy.as_ref().unwrap().rules.len(), 2);
    assert_eq!(aux.services["beta"].source(), Some(gh("acme/tools", 'a')));
}

#[test]
fn stored_object_form_round_trips_and_rejects_unknowns() {
    let src = ServiceSource::Local {
        name: "my-api".into(),
    };
    let e = StoredService::new(ACME.into(), Some(ACME_POLICY.into()), Some(src.clone()));
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(
        v["source"],
        serde_json::json!({ "kind": "local", "name": "my-api" })
    );
    let back: StoredService = serde_json::from_value(v).unwrap();
    assert_eq!(back.parts().unwrap().source, Some(src));
    assert!(back.admit("acme").is_ok());

    for bad in [
        serde_json::json!({ "service": ACME, "extra": 1 }),
        serde_json::json!({ "policy": "x" }),
        serde_json::json!({ "service": ACME, "source": { "kind": "gitlab", "repo": "a/b" } }),
        serde_json::json!({ "service": ACME, "source": { "kind": "github", "repo": "a/b", "commit": "main" } }),
        serde_json::json!({ "service": ACME, "source": { "kind": "local", "name": "a/b" } }),
        serde_json::json!(42),
    ] {
        let e: StoredService = serde_json::from_value(bad.clone()).unwrap();
        assert!(e.parts().is_err(), "{bad}");
    }
    // An unreadable entry is skipped with its reason; the others still load.
    let mut aux = BTreeMap::new();
    aux.insert("acme".to_string(), StoredService::from(ACME));
    aux.insert(
        "bad".to_string(),
        serde_json::from_value(serde_json::json!({ "service": ACME, "x": 1 })).unwrap(),
    );
    let (defs, skipped) = crate::service::vault_custom_services(
        &aux,
        &crate::service::ServiceRegistry::compiled_only(),
    );
    assert!(defs.contains_key("acme"));
    assert!(skipped[0].1.contains("unknown field"), "{skipped:?}");
}

#[test]
fn source_identity_and_display() {
    let a = ServiceSource::Github {
        repo: "Acme/Tools".into(),
        path: Some("svc".into()),
        git_ref: Some("main".into()),
        commit: "b".repeat(40),
    };
    assert_eq!(a.identity(), "github:acme/tools:svc");
    assert!(a.display().contains(&"b".repeat(40)));
    assert_eq!(
        GitHubSpec {
            owner: "ACME".into(),
            repo: "tools".into(),
            path: Some("svc".into())
        }
        .identity(),
        "github:acme/tools:svc"
    );
    assert_eq!(
        ServiceSource::Local { name: "x".into() }.identity(),
        "local:x"
    );
}

// ── local folders ────────────────────────────────────────────────────────────

fn write(p: &std::path::Path, s: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, s).unwrap();
}

#[test]
fn local_single_and_collection() {
    let d = tempfile::tempdir().unwrap();
    write(&d.path().join("one/service.toml"), ACME);
    write(&d.path().join("one/policy.toml"), ACME_POLICY);
    let f = read_local(&d.path().join("one")).unwrap();
    assert!(f.single);
    assert_eq!(f.defs[""].1.as_deref(), Some(ACME_POLICY));

    write(
        &d.path().join("many/services/a1/service.toml"),
        &svc("a1", "a.dev"),
    );
    write(
        &d.path().join("many/services/b2/service.toml"),
        &svc("b2", "b.dev"),
    );
    write(&d.path().join("many/services/b2/policy.toml"), ACME_POLICY);
    write(&d.path().join("many/services/README.md"), "not a service");
    write(&d.path().join("many/README.md"), "ignored");
    let f = read_local(&d.path().join("many")).unwrap();
    assert!(!f.single);
    assert_eq!(f.defs.keys().collect::<Vec<_>>(), ["a1", "b2"]);
    let a = admit_files(&f, None).unwrap();
    assert_eq!(a.len(), 2);

    // A folder under services/ without a service.toml is a problem.
    std::fs::create_dir_all(d.path().join("many/services/c3")).unwrap();
    let e = read_local(&d.path().join("many")).unwrap_err();
    assert!(e[0].contains("services/c3 has no service.toml"), "{e:?}");

    // Both layouts at once, or neither: refused.
    write(&d.path().join("both/service.toml"), ACME);
    write(&d.path().join("both/services/a/service.toml"), ACME);
    assert!(read_local(&d.path().join("both")).unwrap_err()[0].contains("both"));
    std::fs::create_dir_all(d.path().join("empty")).unwrap();
    assert!(read_local(&d.path().join("empty")).unwrap_err()[0].contains("no service.toml"));
}

#[test]
fn local_oversized_file_is_refused_without_reading_it() {
    let d = tempfile::tempdir().unwrap();
    let big = format!(
        "{}\n# {}\n",
        ACME,
        "x".repeat(crate::service::limits::MAX_FILE_BYTES)
    );
    write(&d.path().join("service.toml"), &big);
    let e = read_local(d.path()).unwrap_err();
    assert!(e[0].contains("the limit is"), "{e:?}");
    assert!(!e[0].contains("xxxx"), "content is never echoed");
}

#[cfg(unix)]
#[test]
fn local_symlinks_are_never_followed() {
    let d = tempfile::tempdir().unwrap();
    let outside = d.path().join("outside.toml");
    write(&outside, ACME);
    // A symlinked service.toml.
    std::fs::create_dir_all(d.path().join("s1")).unwrap();
    std::os::unix::fs::symlink(&outside, d.path().join("s1/service.toml")).unwrap();
    let e = read_local(&d.path().join("s1")).unwrap_err();
    assert!(e[0].contains("symbolic link"), "{e:?}");
    // A symlinked folder under services/.
    write(&d.path().join("real/service.toml"), ACME);
    std::fs::create_dir_all(d.path().join("s2/services")).unwrap();
    std::os::unix::fs::symlink(d.path().join("real"), d.path().join("s2/services/acme")).unwrap();
    let e = read_local(&d.path().join("s2")).unwrap_err();
    assert!(
        e.iter()
            .any(|p| p.contains("services/acme is a symbolic link")),
        "{e:?}"
    );
    // A symlinked source root.
    std::os::unix::fs::symlink(d.path().join("real"), d.path().join("link")).unwrap();
    assert!(read_local(&d.path().join("link")).unwrap_err()[0].contains("symbolic link"));
    // A symlinked services/ folder.
    std::fs::create_dir_all(d.path().join("s3")).unwrap();
    std::os::unix::fs::symlink(d.path().join("s2/services"), d.path().join("s3/services")).unwrap();
    assert!(read_local(&d.path().join("s3")).is_err());
}

// ── admission ────────────────────────────────────────────────────────────────

#[test]
fn admit_renames_a_single_service_only() {
    let one = SourceFiles {
        defs: [(
            String::new(),
            (ACME.to_string(), Some(ACME_POLICY.to_string())),
        )]
        .into(),
        single: true,
    };
    let a = admit_files(&one, Some("acme_work")).unwrap();
    assert_eq!(a[0].id, "acme_work");
    assert_eq!(a[0].def.service.id, "acme_work");
    // The stored text declares the new id, so the vault reader admits it under it.
    assert!(gate::admit(Some("acme_work"), &a[0].service, a[0].policy.as_deref()).is_ok());
    assert!(admit_files(&one, Some("Bad Id")).is_err());

    let many = SourceFiles {
        defs: [
            ("a1".to_string(), (svc("a1", "a.dev"), None)),
            ("b2".to_string(), (svc("b2", "b.dev"), None)),
        ]
        .into(),
        single: false,
    };
    let e = admit_files(&many, Some("x")).unwrap_err();
    assert!(e[0].contains("single service"), "{e:?}");
}

#[test]
fn admit_is_all_or_nothing() {
    let many = SourceFiles {
        defs: [
            ("a1".to_string(), (svc("a1", "a.dev"), None)),
            ("b2".to_string(), (svc("b2", "169.254.169.254"), None)),
            // The folder name must equal the declared id.
            ("c3".to_string(), (svc("other", "c.dev"), None)),
        ]
        .into(),
        single: false,
    };
    let e = admit_files(&many, None).unwrap_err();
    assert!(e.iter().any(|p| p.starts_with("services/b2:")), "{e:?}");
    assert!(e.iter().any(|p| p.starts_with("services/c3:")), "{e:?}");
    assert!(!e.iter().any(|p| p.starts_with("services/a1")), "{e:?}");
}

#[test]
fn gate_refuses_ttl_over_one_year() {
    use crate::service::limits::MAX_TTL_SECONDS;
    let rule = |ttl: u64| {
        format!(
            "[[rule]]\nid = \"r\"\nlabel = \"R\"\nmatch = \"POST /x\"\nlevel = \"ask\"\nttl = {}\n",
            ttl
        )
    };
    assert!(gate::admit(None, ACME, Some(&rule(MAX_TTL_SECONDS))).is_ok());
    let e = gate::admit(None, ACME, Some(&rule(MAX_TTL_SECONDS + 1))).unwrap_err();
    assert!(
        e[0].contains("rule 'r'") && e[0].contains("over the limit"),
        "{e:?}"
    );
    let default = format!(
        "[default]\nwrite = \"ask\"\nttl = {}\n",
        MAX_TTL_SECONDS + 1
    );
    let e = gate::admit(None, ACME, Some(&default)).unwrap_err();
    assert!(
        e[0].contains("[default]") && e[0].contains("one year"),
        "{e:?}"
    );
    let inline = format!(
        "{}\n[policy.levels]\nwrite = \"ask\"\nttl = {}\n",
        ACME,
        MAX_TTL_SECONDS + 1
    );
    assert!(gate::admit(None, &inline, None).is_err());
}

// ── tarballs ─────────────────────────────────────────────────────────────────

/// A minimal ustar writer for test archives: (path, type flag, data, link).
pub(crate) fn tar_gz(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut raw = Vec::new();
    for (path, kind, data) in entries {
        raw.extend_from_slice(&header(path, *kind, data.len() as u64));
        raw.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        raw.extend(std::iter::repeat_n(0u8, pad));
    }
    raw.extend(std::iter::repeat_n(0u8, 1024));
    gz(&raw)
}

fn gz(raw: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(raw).unwrap();
    e.finish().unwrap()
}

fn header(path: &str, kind: u8, size: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    let p = path.as_bytes();
    assert!(p.len() <= 100, "test paths fit the name field");
    h[..p.len()].copy_from_slice(p);
    h[100..107].copy_from_slice(b"0000644");
    h[124..135].copy_from_slice(format!("{:011o}", size).as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = kind;
    if kind == b'2' {
        h[157..168].copy_from_slice(b"/etc/passwd");
    }
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|b| *b as u64).sum();
    h[148..155].copy_from_slice(format!("{:06o}\0", sum).as_bytes());
    h
}

/// A pax `x` header record carrying `path` ("<len> path=<value>\n", where
/// <len> counts its own digits).
fn pax_path(path: &str) -> Vec<u8> {
    let body = format!(" path={}\n", path);
    let mut len = body.len() + 1;
    loop {
        let total = body.len() + len.to_string().len();
        if total == len {
            break;
        }
        len = total;
    }
    format!("{}{}", len, body).into_bytes()
}

#[test]
fn tarball_collection_and_sub_path() {
    let pol = ACME_POLICY.as_bytes();
    let a1 = svc("a1", "a.dev");
    let gz = tar_gz(&[
        ("o-r-abc/", b'5', b""),
        ("o-r-abc/README.md", b'0', b"hello"),
        ("o-r-abc/services/", b'5', b""),
        ("o-r-abc/services/a1/", b'5', b""),
        ("o-r-abc/services/a1/service.toml", b'0', a1.as_bytes()),
        ("o-r-abc/services/a1/policy.toml", b'0', pol),
        ("o-r-abc/services/a1/notes.md", b'0', b"ignored"),
        ("o-r-abc/one/service.toml", b'0', ACME.as_bytes()),
    ]);
    let f = read_tarball(&gz, None).unwrap();
    assert!(!f.single);
    assert_eq!(f.defs["a1"], (a1.clone(), Some(ACME_POLICY.to_string())));
    let f = read_tarball(&gz, Some("one")).unwrap();
    assert!(f.single);
    assert_eq!(f.defs[""].0, ACME);
    let f = read_tarball(&gz, Some("services/a1")).unwrap();
    assert!(f.single);
    let e = read_tarball(&gz, Some("nope")).unwrap_err();
    assert!(e[0].contains("not a folder"), "{e:?}");
}

#[test]
fn tarball_pax_long_path() {
    let deep = format!("o-r-abc/{}/service.toml", "d".repeat(120));
    let pax = pax_path(&deep);
    let gz = tar_gz(&[
        (
            "pax_global_header",
            b'g',
            b"52 comment=0123456789abcdef0123456789abcdef01234567\n",
        ),
        ("o-r-abc/PaxHeaders/x", b'x', &pax),
        ("ignored-name", b'0', ACME.as_bytes()),
    ]);
    let f = read_tarball(&gz, Some(&"d".repeat(120))).unwrap();
    assert_eq!(f.defs[""].0, ACME);
}

#[test]
fn tarball_symlink_hardlink_and_device_are_not_read() {
    for kind in [b'2', b'1', b'3'] {
        let gz = tar_gz(&[
            ("o-r-abc/services/evil/", b'5', b""),
            ("o-r-abc/services/evil/service.toml", kind, b""),
        ]);
        let e = read_tarball(&gz, None).unwrap_err();
        assert!(
            e[0].contains("services/evil/service.toml") && e[0].contains("only regular files"),
            "{kind}: {e:?}"
        );
        assert!(!e.iter().any(|p| p.contains("passwd")), "{e:?}");
    }
    // A symlink elsewhere is just skipped.
    let gz = tar_gz(&[
        ("o-r-abc/link", b'2', b""),
        ("o-r-abc/service.toml", b'0', ACME.as_bytes()),
    ]);
    assert!(read_tarball(&gz, None).is_ok());
}

#[test]
fn tarball_dotdot_and_absolute_paths_reject_the_archive() {
    for path in [
        "o-r-abc/../services/x/service.toml",
        "o-r-abc/services/../../etc/x",
        "/etc/service.toml",
        "..",
    ] {
        let gz = tar_gz(&[
            ("o-r-abc/service.toml", b'0', ACME.as_bytes()),
            (path, b'0', ACME.as_bytes()),
        ]);
        let e = read_tarball(&gz, None).unwrap_err();
        assert!(
            e[0].contains("leaves its folder") || e[0].contains("absolute path"),
            "{path}: {e:?}"
        );
    }
    // In a pax path too.
    let pax = pax_path("o-r-abc/../service.toml");
    let gz = tar_gz(&[("x", b'x', &pax), ("y", b'0', ACME.as_bytes())]);
    assert!(read_tarball(&gz, None).unwrap_err()[0].contains("leaves its folder"));
}

#[test]
fn tarball_oversized_entry_is_refused_unread() {
    let big = vec![b'x'; crate::service::limits::MAX_FILE_BYTES + 1];
    let gz = tar_gz(&[("o-r-abc/service.toml", b'0', &big)]);
    let e = read_tarball(&gz, None).unwrap_err();
    assert!(e[0].contains("the limit is"), "{e:?}");
    assert!(!e[0].contains("xxxx"));
    // A large file at any other path is read through, not kept.
    let gz = tar_gz(&[
        ("o-r-abc/blob.bin", b'0', &big),
        ("o-r-abc/service.toml", b'0', ACME.as_bytes()),
    ]);
    assert!(read_tarball(&gz, None).is_ok());
}

#[test]
fn tarball_too_many_entries_and_unpacked_size() {
    let names: Vec<String> = (0..60).map(|i| format!("o-r-abc/f{}", i)).collect();
    let mut entries: Vec<(&str, u8, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), b'0', &b"x"[..]))
        .collect();
    entries.push(("o-r-abc/service.toml", b'0', ACME.as_bytes()));
    let gz = tar_gz(&entries);
    let e = read_tarball_with(&gz, None, MAX_TARBALL_UNPACKED_BYTES, 50).unwrap_err();
    assert!(e[0].contains("more than 50 entries"), "{e:?}");
    assert!(read_tarball_with(&gz, None, MAX_TARBALL_UNPACKED_BYTES, 100).is_ok());
    // A highly compressible blob unpacking past the cap.
    let zeros = vec![0u8; 256 * 1024];
    let gz = tar_gz(&[("o-r-abc/zeros", b'0', &zeros)]);
    let e = read_tarball_with(&gz, None, 64 * 1024, 100).unwrap_err();
    assert!(e[0].contains("unpacks to more than"), "{e:?}");
}

#[test]
fn tarball_duplicates_corruption_and_garbage() {
    let gz = tar_gz(&[
        ("o-r-abc/service.toml", b'0', ACME.as_bytes()),
        ("o-r-abc/service.toml", b'0', ACME.as_bytes()),
    ]);
    assert!(read_tarball(&gz, None).unwrap_err()[0].contains("twice"));
    let mut raw = header("o-r-abc/service.toml", b'0', 4).to_vec();
    raw[0] ^= 1; // breaks the checksum
    raw.extend(vec![0u8; 2048]);
    assert!(read_tarball(&gz_bytes(&raw), None).unwrap_err()[0].contains("corrupt"));
    assert!(read_tarball(b"not gzip at all", None).is_err());
    // Truncated: a header promising more data than there is.
    let mut raw = header("o-r-abc/service.toml", b'0', 4096).to_vec();
    raw.extend(vec![b'a'; 100]);
    assert!(read_tarball(&gz_bytes(&raw), None).is_err());
    // Not UTF-8.
    let gz = tar_gz(&[("o-r-abc/service.toml", b'0', &[0xff, 0xfe, 0x00])]);
    assert!(read_tarball(&gz, None).unwrap_err()[0].contains("not UTF-8"));
}

fn gz_bytes(raw: &[u8]) -> Vec<u8> {
    gz(raw)
}

#[test]
fn tarball_random_bytes_never_panic() {
    let base = tar_gz(&[
        (
            "o-r-abc/services/a1/service.toml",
            b'0',
            svc("a1", "a.dev").as_bytes(),
        ),
        (
            "o-r-abc/services/a1/policy.toml",
            b'0',
            ACME_POLICY.as_bytes(),
        ),
    ]);
    let mut raw = Vec::new();
    {
        use std::io::Read;
        flate2::read::GzDecoder::new(&base[..])
            .read_to_end(&mut raw)
            .unwrap();
    }
    let mut seed: u64 = 0x9e3779b97f4a7c15;
    for _ in 0..300 {
        let mut m = raw.clone();
        for _ in 0..8 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let i = (seed as usize) % m.len();
            m[i] = (seed >> 32) as u8;
        }
        let _ = read_tarball(&gz(&m), None);
        let _ = read_tarball(&gz(&m[..(seed as usize) % m.len()]), None);
    }
}

// ── GitHub (a fake API: tests never reach GitHub) ────────────────────────────

struct FakeGitHub {
    default: &'static str,
    /// The repository's own refs (`heads/<b>`, `tags/<t>`) → their object.
    refs: BTreeMap<&'static str, GitObject>,
    /// Annotated tag objects → their target.
    tags: BTreeMap<String, GitObject>,
    /// What GitHub resolves any other ref or commit id to.
    commits: BTreeMap<&'static str, String>,
    tarball: Vec<u8>,
    asked: std::sync::Mutex<Vec<String>>,
}

impl GitHubApi for FakeGitHub {
    async fn default_branch(&self, _o: &str, _r: &str) -> Result<String, FetchError> {
        Ok(self.default.into())
    }
    async fn git_ref(
        &self,
        _o: &str,
        _r: &str,
        path: &str,
    ) -> Result<Option<GitObject>, FetchError> {
        self.asked.lock().unwrap().push(format!("ref {}", path));
        Ok(self.refs.get(path).cloned())
    }
    async fn tag_target(&self, _o: &str, _r: &str, sha: &str) -> Result<GitObject, FetchError> {
        self.tags
            .get(sha)
            .cloned()
            .ok_or_else(|| FetchError::Answered(format!("tag {} not found", sha)))
    }
    async fn commit_of(&self, _o: &str, _r: &str, git_ref: &str) -> Result<String, FetchError> {
        self.asked.lock().unwrap().push(format!("commits {}", git_ref));
        self.commits
            .get(git_ref)
            .cloned()
            .ok_or_else(|| FetchError::Answered(format!("ref '{}' not found", git_ref)))
    }
    async fn tarball(&self, _o: &str, _r: &str, commit: &str) -> Result<Vec<u8>, FetchError> {
        self.asked
            .lock()
            .unwrap()
            .push(format!("tarball {}", commit));
        Ok(self.tarball.clone())
    }
}

fn commit(c: char) -> GitObject {
    GitObject::Commit(c.to_string().repeat(40))
}

/// `main` (the default branch) at a; the annotated tag `v1.2.0` at b; a
/// branch `cafe` (hex digits only) at e; a branch named like a full commit
/// id at e; `dup` a branch at a and a tag at b. GitHub's commits endpoint
/// resolves commit ids and a pull ref.
fn fake() -> FakeGitHub {
    let c40 = "c".repeat(40);
    FakeGitHub {
        default: "main",
        refs: [
            ("heads/main", commit('a')),
            ("tags/v1.2.0", GitObject::Tag("7".repeat(40))),
            ("heads/cafe", commit('e')),
            ("heads/1111111111111111111111111111111111111111", commit('e')),
            ("heads/dup", commit('a')),
            ("tags/dup", commit('b')),
        ]
        .into(),
        tags: [("7".repeat(40), commit('b'))].into(),
        commits: [
            ("cafe", "f".repeat(40)),
            ("cccccccc", c40.clone()),
            ("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", c40.to_ascii_uppercase()),
            ("short", "abc".into()),
            ("pull/1/head", "d".repeat(40)),
        ]
        .into(),
        tarball: tar_gz(&[("o-r-x/service.toml", b'0', ACME.as_bytes())]),
        asked: Default::default(),
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

#[test]
fn github_ref_branch_tag_and_commit_are_pinned() {
    let api = fake();
    let spec = GitHubSpec {
        owner: "acme".into(),
        repo: "tools".into(),
        path: None,
    };
    // No --ref: the default branch's head.
    let (_, s) = block_on(github::fetch(&api, &spec, None)).unwrap();
    assert_eq!(s, gh("acme/tools", 'a'));
    // A branch, an annotated tag (peeled), a full ref name, a hex-only branch
    // name (a branch before a commit id), a commit id, another ref: each
    // resolved to a full commit and pinned, the ref recorded as asked.
    for (r, want) in [
        ("main", 'a'),
        ("v1.2.0", 'b'),
        ("refs/heads/main", 'a'),
        ("refs/tags/v1.2.0", 'b'),
        ("cafe", 'e'),
        ("cccccccc", 'c'),
        ("pull/1/head", 'd'),
    ] {
        let (files, s) = block_on(github::fetch(&api, &spec, Some(r))).unwrap();
        assert!(files.single);
        let ServiceSource::Github {
            git_ref, commit, ..
        } = s
        else {
            panic!()
        };
        assert_eq!(commit, want.to_string().repeat(40), "{r}");
        assert_eq!(git_ref.as_deref(), Some(r));
    }
    // The tarball is fetched at the resolved commit, never at the ref.
    assert!(api
        .asked
        .lock()
        .unwrap()
        .iter()
        .filter(|a| a.starts_with("tarball"))
        .all(|a| a.len() == "tarball ".len() + 40));
    // Uppercase hex is normalized; a short answer is refused.
    let (_, s) = block_on(github::fetch(
        &api,
        &spec,
        Some("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
    ))
    .unwrap();
    assert!(matches!(s, ServiceSource::Github { commit, .. } if commit == "c".repeat(40)));
    assert!(block_on(github::fetch(&api, &spec, Some("short"))).is_err());
    // A name that is a branch and a tag at different commits is refused.
    let e = block_on(github::fetch(&api, &spec, Some("dup"))).unwrap_err();
    assert!(e[0].contains("both a branch and a tag"), "{e:?}");
    // A ref outside the charset never reaches the API.
    let before = api.asked.lock().unwrap().len();
    assert!(block_on(github::fetch(&api, &spec, Some("../x"))).is_err());
    assert_eq!(api.asked.lock().unwrap().len(), before);
}

#[test]
fn github_urls_are_built_from_checked_names() {
    assert_eq!(
        github::commit_url("https://api.github.com", "acme", "tools", "release/1"),
        "https://api.github.com/repos/acme/tools/commits/release/1"
    );
    assert_eq!(
        github::tarball_url(
            "https://codeload.github.com",
            "acme",
            "tools",
            &"a".repeat(40)
        ),
        format!(
            "https://codeload.github.com/acme/tools/tar.gz/{}",
            "a".repeat(40)
        )
    );
    assert_eq!(
        github::repo_url("https://api.github.com", "acme", "tools"),
        "https://api.github.com/repos/acme/tools"
    );
    assert_eq!(
        github::git_ref_url("https://api.github.com", "acme", "tools", "tags/v1"),
        "https://api.github.com/repos/acme/tools/git/ref/tags/v1"
    );
    assert_eq!(
        github::git_tag_url("https://api.github.com", "acme", "tools", &"7".repeat(40)),
        format!("https://api.github.com/repos/acme/tools/git/tags/{}", "7".repeat(40))
    );
}

// ── cards ────────────────────────────────────────────────────────────────────

fn admitted(id: &str, service: &str, policy: Option<&str>) -> crate::service::ServiceDef {
    gate::admit(Some(id), service, policy).unwrap()
}

#[test]
fn add_card_lists_destinations_rules_and_refuses_collisions() {
    let reg = crate::service::ServiceRegistry::compiled_only();
    let oauth = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev", "*.files.acme.dev"]
secrets = ["ACME_REFRESH"]

[auth]
type = "oauth2"
refresh_token = "ACME_REFRESH"
authorization_url = "https://login.acme.dev/authorize"
token_url = "https://token.acme.dev/oauth/token"
client_id = "public"
"#;
    let snap: BTreeMap<_, _> = [(
        "acme".to_string(),
        admitted("acme", oauth, Some(ACME_POLICY)),
    )]
    .into();
    let src = gh("acme/tools", 'a');
    let current = BTreeMap::new();
    let c = add_card(&snap, &src, SourceCheck::Fetched, false, &current, &reg).unwrap();
    assert_eq!(c.ids, ["acme"]);
    assert_eq!(
        c.destinations,
        [
            "api.acme.dev",
            "*.files.acme.dev",
            "token.acme.dev",
            "login.acme.dev"
        ],
        "every declared host, the token endpoint's and the authorization page's"
    );
    assert_eq!(
        c.tightens,
        [
            "acme: Delete a thing [DELETE /v1/things/*]: deny",
            "acme: Pay [POST /v1/pay]: ask"
        ],
        "each label beside what the rule matches"
    );
    assert!(c.from.contains(&"a".repeat(40)));
    assert!(c.from.contains("checked on your device"));
    assert!(c.oauth.is_empty(), "PKCE is on by default");
    assert!(c.new_destinations.is_empty() && c.loosens.is_empty());
    // Not checked here: the source is what the requester stated, said as such.
    for check in [
        SourceCheck::LocalFolder,
        SourceCheck::NotReached,
        SourceCheck::NotBranchOrTag,
    ] {
        let c = add_card(&snap, &src, check, false, &current, &reg).unwrap();
        assert!(c.from.contains("as stated by the requester"), "{}", c.from);
        assert!(!c.from.contains("checked on your device"));
        let mut scope = serde_json::json!({});
        c.stamp(&mut scope).unwrap();
        assert_eq!(scope["source_check"], check.as_str());
        assert_eq!(SourceCheck::parse(check.as_str()), Some(check));
    }

    // A built-in id.
    let gh_def: BTreeMap<_, _> = [(
        "github".to_string(),
        admitted("github", &svc("github", "api.github.com"), None),
    )]
    .into();
    assert!(
        add_card(&gh_def, &src, SourceCheck::Fetched, false, &current, &reg)
            .unwrap_err()
            .contains("built-in")
    );
    // An id another source, or an entry from before sources, already holds.
    let mut current = BTreeMap::new();
    current.insert(
        "acme".to_string(),
        StoredService::new(ACME.into(), None, Some(gh("other/repo", 'b'))),
    );
    let e = add_card(&snap, &src, SourceCheck::Fetched, false, &current, &reg).unwrap_err();
    assert!(
        e.contains("already in this vault from github:other/repo"),
        "{e}"
    );
    current.insert("acme".to_string(), StoredService::from(ACME));
    assert!(
        add_card(&snap, &src, SourceCheck::Fetched, false, &current, &reg)
            .unwrap_err()
            .contains("added before sources")
    );
    // The same source again: add refuses, update requires it.
    current.insert(
        "acme".to_string(),
        StoredService::new(ACME.into(), None, Some(gh("Acme/Tools", 'b'))),
    );
    assert!(
        add_card(&snap, &src, SourceCheck::Fetched, false, &current, &reg)
            .unwrap_err()
            .contains("already added")
    );
    assert!(add_card(&snap, &src, SourceCheck::Fetched, true, &current, &reg).is_ok());
    assert!(add_card(
        &snap,
        &src,
        SourceCheck::Fetched,
        true,
        &BTreeMap::new(),
        &reg
    )
    .unwrap_err()
    .contains("not added"));
}

/// A first add's card shows what each rule matches beside its label, and
/// every approval window the definition states, the default value's too (a
/// rule's own window overrides a shorter one the owner set).
#[test]
fn first_add_card_shows_match_patterns_and_stated_windows() {
    let reg = crate::service::ServiceRegistry::compiled_only();
    let default_ttl = crate::proxy::handler::DEFAULT_ASK_TTL;
    let policy = format!(
        "[default]\nwrite = \"ask\"\nttl = 3600\n\n[[rule]]\nid = \"pay\"\nlabel = \"Pay\"\nmatch = \"POST /v1/pay\"\nlevel = \"ask\"\nttl = 86400\n\n[[rule]]\nid = \"refund\"\nlabel = \"Refund\"\nmatch = [\"POST /v1/refund\", \"POST /v1/refund/*\"]\nlevel = \"ask\"\nttl = {default_ttl}\n\n[[rule]]\nid = \"no-delete\"\nlabel = \"Delete\"\nmatch = \"DELETE /v1/*\"\nlevel = \"deny\"\n"
    );
    let snap: BTreeMap<_, _> = [("acme".to_string(), admitted("acme", ACME, Some(&policy)))].into();
    let c = add_card(
        &snap,
        &gh("acme/tools", 'a'),
        SourceCheck::Fetched,
        false,
        &BTreeMap::new(),
        &reg,
    )
    .unwrap();
    assert_eq!(
        c.tightens,
        [
            "acme: Pay [POST /v1/pay]: ask, approval lasts 86400s",
            format!("acme: Refund [POST /v1/refund | POST /v1/refund/*]: ask, approval lasts {default_ttl}s").as_str(),
            "acme: Delete [DELETE /v1/*]: deny",
            "acme: default write: ask",
            "acme: default approval lasts 3600s",
        ],
        "{:?}",
        c.tightens
    );
    // A rule deciding on the body alone shows that as what it matches.
    let body_only = "[[rule]]\nid = \"refunds\"\nlabel = \"Refunds\"\nmatch = []\nbody = \"refund\"\nlevel = \"deny\"\n";
    let snap: BTreeMap<_, _> =
        [("acme".to_string(), admitted("acme", ACME, Some(body_only)))].into();
    let c = add_card(
        &snap,
        &gh("acme/tools", 'a'),
        SourceCheck::Fetched,
        false,
        &BTreeMap::new(),
        &reg,
    )
    .unwrap();
    assert_eq!(c.tightens, ["acme: Refunds [body~refund]: deny"]);
}

#[test]
fn update_card_highlights_new_hosts_loosened_rules_and_removals() {
    let reg = crate::service::ServiceRegistry::compiled_only();
    let src_old = gh("acme/tools", 'a');
    let mut current = BTreeMap::new();
    current.insert(
        "a1".to_string(),
        StoredService::new(
            svc("a1", "a.dev"),
            Some(ACME_POLICY.into()),
            Some(src_old.clone()),
        ),
    );
    current.insert(
        "b2".to_string(),
        StoredService::new(svc("b2", "b.dev"), None, Some(src_old)),
    );
    // New snapshot: a1 sends to one more host, its deny is now ask, its ask is gone;
    // b2 is dropped.
    let a1_new = "[service]\nid = \"a1\"\nname = \"a1\"\nhosts = [\"a.dev\", \"exfil.example\"]\nsecrets = [\"TOKEN\"]\n";
    let pol_new = "[[rule]]\nid = \"no-delete\"\nlabel = \"Delete a thing\"\nmatch = \"DELETE /v1/things/*\"\nlevel = \"ask\"\n";
    let snap: BTreeMap<_, _> = [("a1".to_string(), admitted("a1", a1_new, Some(pol_new)))].into();
    let c = add_card(
        &snap,
        &gh("acme/tools", 'b'),
        SourceCheck::Fetched,
        true,
        &current,
        &reg,
    )
    .unwrap();
    assert_eq!(c.replaces, ["a1"]);
    assert_eq!(c.removes, ["b2"]);
    assert_eq!(c.new_destinations, ["exfil.example"]);
    assert!(
        c.loosens
            .contains(&"a1: Delete a thing: deny (now ask)".to_string()),
        "{:?}",
        c.loosens
    );
    assert!(
        c.loosens.contains(&"a1: Pay: ask (removed)".to_string()),
        "{:?}",
        c.loosens
    );

    // The signed card must match: a stamped scope round-trips, any edit is caught.
    let mut scope = serde_json::json!({});
    c.stamp(&mut scope).unwrap();
    assert_eq!(c.first_difference(&scope), None);
    scope["new_destinations"] = serde_json::json!([]);
    assert_eq!(c.first_difference(&scope), Some("new_destinations"));
}

#[test]
fn diff_flags_loosened_defaults_and_ignores_tightening() {
    let old = summarize(&admitted(
        "a1",
        &svc("a1", "a.dev"),
        Some("[default]\nwrite = \"deny\"\n"),
    ));
    let looser = summarize(&admitted(
        "a1",
        &svc("a1", "a.dev"),
        Some("[default]\nwrite = \"ask\"\n"),
    ));
    let d = diff(
        &[("a1".to_string(), old.clone())].into(),
        &[("a1".to_string(), looser)].into(),
    );
    assert_eq!(d.loosens, ["a1: default write deny (now ask)"]);
    assert_eq!(d.changed, ["a1"]);
    // Tightening, or a new rule, is not a loosening.
    let tighter = summarize(&admitted(
        "a1",
        &svc("a1", "a.dev"),
        Some("[default]\nwrite = \"deny\"\n[[rule]]\nid = \"x\"\nlabel = \"X\"\nmatch = \"GET /x\"\nlevel = \"deny\"\n"),
    ));
    let d = diff(
        &[("a1".to_string(), old)].into(),
        &[("a1".to_string(), tighter)].into(),
    );
    assert!(d.loosens.is_empty() && d.new_destinations.is_empty());
}

#[test]
fn rm_card_by_id_and_by_source() {
    let mut current = BTreeMap::new();
    let src = gh("acme/tools", 'a');
    current.insert(
        "a1".to_string(),
        StoredService::new(svc("a1", "a.dev"), None, Some(src.clone())),
    );
    current.insert(
        "b2".to_string(),
        StoredService::new(svc("b2", "b.dev"), None, Some(src.clone())),
    );
    current.insert("old".to_string(), StoredService::from(svc("old", "o.dev")));
    let uses = |id: &str| {
        if id == "b2" {
            vec!["work".to_string()]
        } else {
            vec![]
        }
    };
    let c = rm_card("github:acme/tools", &current, uses).unwrap();
    assert_eq!(c.ids, ["a1", "b2"]);
    assert_eq!(c.connections, ["work"]);
    assert_eq!(c.from, src.display());
    let c = rm_card("old", &current, uses).unwrap();
    assert_eq!(
        (c.ids.as_slice(), c.from.as_str()),
        (&["old".to_string()][..], "")
    );
    assert!(rm_card("nope", &current, uses).is_err());
}

#[test]
fn id_rename_collisions_are_refused() {
    let reg = crate::service::ServiceRegistry::compiled_only();
    let one = SourceFiles {
        defs: [(String::new(), (ACME.to_string(), None))].into(),
        single: true,
    };
    let src = gh("acme/tools", 'a');
    let snap = |id: &str| -> BTreeMap<String, crate::service::ServiceDef> {
        admit_files(&one, Some(id))
            .unwrap()
            .into_iter()
            .map(|a| (a.id, a.def))
            .collect()
    };
    // --id onto a built-in id.
    assert!(add_card(
        &snap("github"),
        &src,
        SourceCheck::Fetched,
        false,
        &BTreeMap::new(),
        &reg
    )
    .unwrap_err()
    .contains("built-in"));
    // --id onto an id another source holds.
    let mut current = BTreeMap::new();
    current.insert(
        "taken".to_string(),
        StoredService::new(svc("taken", "t.dev"), None, Some(gh("other/repo", 'b'))),
    );
    assert!(add_card(
        &snap("taken"),
        &src,
        SourceCheck::Fetched,
        false,
        &current,
        &reg
    )
    .unwrap_err()
    .contains("already in this vault"));
    // A free id is stored under the new name.
    let c = add_card(
        &snap("acme_work"),
        &src,
        SourceCheck::Fetched,
        false,
        &current,
        &reg,
    )
    .unwrap();
    assert_eq!(c.ids, ["acme_work"]);
}

// ── what the card and the update diff show ──────────────────────────────────

const OAUTH_BASE: &str = r#"
[service]
id = "acme"
name = "Acme"
hosts = ["api.acme.dev"]
secrets = ["ACME_REFRESH"]

[auth]
type = "oauth2"
refresh_token = "ACME_REFRESH"
authorization_url = "https://login.acme.dev/authorize"
token_url = "https://token.acme.dev/oauth/token"
client_id = "public"
"#;

#[test]
fn card_lists_every_host_an_oauth_artifact_reaches_and_pkce_off() {
    let with = |extra: &str| summarize(&admitted("acme", &format!("{OAUTH_BASE}{extra}"), None));
    // A redirect off this device receives the code: listed.
    let s = with("redirect_uri = \"https://cb.partner.example/oauth\"\npkce = false\n");
    assert_eq!(
        s.destinations,
        [
            "api.acme.dev",
            "token.acme.dev",
            "login.acme.dev",
            "cb.partner.example"
        ]
    );
    assert!(s.pkce_off);
    // Loopback and out-of-band redirects stay on this device: not listed.
    for local in [
        "http://127.0.0.1:8765/cb",
        "http://localhost:9000/cb",
        "http://[::1]:9000/cb",
        "urn:ietf:wg:oauth:2.0:oob",
    ] {
        let s = with(&format!("redirect_uri = \"{local}\"\n"));
        assert_eq!(s.destinations.len(), 3, "{local}: {:?}", s.destinations);
        assert!(!s.pkce_off);
    }
    // An app's own scheme: the app registered for it receives the code.
    let s = with("redirect_uri = \"com.acme.app:/oauth\"\n");
    assert_eq!(
        s.destinations.last().map(String::as_str),
        Some("com.acme.app:")
    );

    // The card shows PKCE: off.
    let reg = crate::service::ServiceRegistry::compiled_only();
    let def = admitted("acme", &format!("{OAUTH_BASE}pkce = false\n"), None);
    let snap: BTreeMap<_, _> = [("acme".to_string(), def)].into();
    let c = add_card(
        &snap,
        &gh("acme/tools", 'a'),
        SourceCheck::Fetched,
        false,
        &BTreeMap::new(),
        &reg,
    )
    .unwrap();
    assert_eq!(c.oauth, ["acme: PKCE: off"]);
}

#[test]
fn update_flags_longer_approval_windows_unbound_scope_vars_and_pkce_off() {
    let svc_req = |scope: &str, extra: &str| {
        format!(
            "{OAUTH_BASE}{extra}\n[requests.buy]\nmatch = \"POST /v1/pay\"\nvars.amount = \"/amount\"\nvars.merchant = \"/merchant\"\nscope = [{scope}]\n"
        )
    };
    let pol = |rule_ttl: &str, default_ttl: &str| {
        format!(
            "[default]\nwrite = \"ask\"\n{default_ttl}\n[[rule]]\nid = \"pay\"\nlabel = \"Pay\"\nmatch = \"POST /v1/pay\"\nlevel = \"ask\"\n{rule_ttl}\n"
        )
    };
    let old = summarize(&admitted(
        "acme",
        &svc_req("\"amount\", \"merchant\"", ""),
        Some(&pol("ttl = 60", "ttl = 300")),
    ));
    let new = summarize(&admitted(
        "acme",
        &svc_req("\"amount\"", "pkce = false"),
        Some(&pol("ttl = 86400", "ttl = 3600")),
    ));
    let d = diff(
        &[("acme".to_string(), old.clone())].into(),
        &[("acme".to_string(), new)].into(),
    );
    assert_eq!(
        d.loosens,
        [
            "acme: Pay: ask, approval lasts 60s (now 86400s)",
            "acme: default approval lasts 300s (now 3600s)",
            "acme: request buy no longer binds merchant to an approval",
            "acme: PKCE: off (was on)",
        ]
    );
    // An unset window is the default one: setting it shorter is not looser,
    // setting it longer is.
    let unset = summarize(&admitted(
        "acme",
        &svc_req("\"amount\", \"merchant\"", ""),
        Some(&pol("", "")),
    ));
    let shorter = summarize(&admitted(
        "acme",
        &svc_req("\"amount\", \"merchant\"", ""),
        Some(&pol("ttl = 60", "ttl = 60")),
    ));
    let d = diff(
        &[("acme".to_string(), unset.clone())].into(),
        &[("acme".to_string(), shorter)].into(),
    );
    assert!(d.loosens.is_empty(), "{:?}", d.loosens);
    let longer = summarize(&admitted(
        "acme",
        &svc_req("\"amount\", \"merchant\"", ""),
        Some(&pol("ttl = 7200", "")),
    ));
    let d = diff(
        &[("acme".to_string(), unset)].into(),
        &[("acme".to_string(), longer)].into(),
    );
    assert_eq!(
        d.loosens,
        ["acme: Pay: ask, approval lasts not set (900s by default) (now 7200s)"]
    );

    // They reach the update card's `loosens`.
    let reg = crate::service::ServiceRegistry::compiled_only();
    let src = gh("acme/tools", 'a');
    let mut current = BTreeMap::new();
    current.insert(
        "acme".to_string(),
        StoredService::new(
            svc_req("\"amount\", \"merchant\"", ""),
            Some(pol("ttl = 60", "")),
            Some(src.clone()),
        ),
    );
    let snap: BTreeMap<_, _> = [(
        "acme".to_string(),
        admitted(
            "acme",
            &svc_req("\"amount\"", ""),
            Some(&pol("ttl = 600", "")),
        ),
    )]
    .into();
    let c = add_card(
        &snap,
        &gh("acme/tools", 'b'),
        SourceCheck::Fetched,
        true,
        &current,
        &reg,
    )
    .unwrap();
    assert_eq!(
        c.loosens,
        [
            "acme: Pay: ask, approval lasts 60s (now 600s)",
            "acme: request buy no longer binds merchant to an approval",
        ]
    );
}

// ── the daemon's own check of a GitHub source ───────────────────────────────

/// GitHub out of reach (`None`), or answering every read with `Some(status)`.
struct OfflineGitHub(Option<u16>);

impl OfflineGitHub {
    fn fail(&self) -> FetchError {
        match self.0 {
            None => FetchError::Unreachable("offline".into()),
            Some(status) => github::status_problem(status, "github:acme/tools"),
        }
    }
}

impl GitHubApi for OfflineGitHub {
    async fn default_branch(&self, _o: &str, _r: &str) -> Result<String, FetchError> {
        Err(self.fail())
    }
    async fn git_ref(
        &self,
        _o: &str,
        _r: &str,
        _p: &str,
    ) -> Result<Option<GitObject>, FetchError> {
        Err(self.fail())
    }
    async fn tag_target(&self, _o: &str, _r: &str, _s: &str) -> Result<GitObject, FetchError> {
        Err(self.fail())
    }
    async fn commit_of(&self, _o: &str, _r: &str, _g: &str) -> Result<String, FetchError> {
        Err(self.fail())
    }
    async fn tarball(&self, _o: &str, _r: &str, _c: &str) -> Result<Vec<u8>, FetchError> {
        Err(self.fail())
    }
}

#[test]
fn verify_fetches_the_pinned_commit_and_compares_every_definition() {
    let carried =
        |defs: &[(&str, String, Option<&str>)]| -> BTreeMap<String, (String, Option<String>)> {
            defs.iter()
                .map(|(id, s, p)| (id.to_string(), (s.clone(), p.map(str::to_string))))
                .collect()
        };
    let src = gh("acme/tools", 'c');
    // A single service folder at the commit (the fake serves ACME), the
    // default branch's head.
    let at_c = |f: FakeGitHub| FakeGitHub {
        refs: [("heads/main", commit('c'))].into(),
        ..f
    };
    let api = at_c(fake());
    let ok = carried(&[("acme", ACME.to_string(), None)]);
    assert_eq!(
        block_on(github::verify(&api, &src, &ok)),
        Ok(SourceCheck::Fetched)
    );
    assert!(api
        .asked
        .lock()
        .unwrap()
        .contains(&format!("tarball {}", "c".repeat(40))));
    // Stored under another id with --id: compared after the same rename.
    let renamed = carried(&[(
        "acme_work",
        rename_service(ACME, "acme_work").unwrap(),
        None,
    )]);
    assert_eq!(
        block_on(github::verify(&api, &src, &renamed)),
        Ok(SourceCheck::Fetched)
    );
    // Anything else than what the commit holds: refused.
    for bad in [
        carried(&[("acme", ACME.replace("api.acme.dev", "api.other.dev"), None)]),
        carried(&[("acme", ACME.to_string(), Some(ACME_POLICY))]),
        carried(&[
            ("acme", ACME.to_string(), None),
            ("b2", svc("b2", "b.dev"), None),
        ]),
    ] {
        let e = block_on(github::verify(&api, &src, &bad)).unwrap_err();
        assert!(e.contains("not what github:acme/tools"), "{e}");
    }
    // A collection: every folder must match, no more and no less.
    let coll = at_c(FakeGitHub {
        tarball: tar_gz(&[
            (
                "o-r-x/services/a1/service.toml",
                b'0',
                svc("a1", "a.dev").as_bytes(),
            ),
            (
                "o-r-x/services/b2/service.toml",
                b'0',
                svc("b2", "b.dev").as_bytes(),
            ),
            (
                "o-r-x/services/b2/policy.toml",
                b'0',
                ACME_POLICY.as_bytes(),
            ),
        ]),
        ..fake()
    });
    let both = carried(&[
        ("a1", svc("a1", "a.dev"), None),
        ("b2", svc("b2", "b.dev"), Some(ACME_POLICY)),
    ]);
    assert_eq!(
        block_on(github::verify(&coll, &src, &both)),
        Ok(SourceCheck::Fetched)
    );
    let one = carried(&[("a1", svc("a1", "a.dev"), None)]);
    assert!(block_on(github::verify(&coll, &src, &one)).is_err());
    // No answer at all (a transport error, none in time): said so on the
    // card, not refused.
    assert_eq!(
        block_on(github::verify(&OfflineGitHub(None), &src, &ok)),
        Ok(SourceCheck::NotReached)
    );
    // Any answer without the data (not found, refused, a server or proxy
    // error): refused.
    for status in [404u16, 422, 401, 403, 429, 407, 408, 500, 503] {
        let e = block_on(github::verify(&OfflineGitHub(Some(status)), &src, &ok)).unwrap_err();
        assert!(e.contains("nothing was stored"), "{status}: {e}");
    }
    let local = ServiceSource::Local {
        name: "mine".into(),
    };
    assert_eq!(
        block_on(github::verify(&OfflineGitHub(None), &local, &ok)),
        Ok(SourceCheck::LocalFolder)
    );
}

/// A GitHub source is checked only at the head of one of the repository's
/// own branches or tags: the stated branch or tag (absent: the default
/// branch; an annotated tag peeled) must point at the pinned commit, else it
/// is refused, naming the ref, before anything is fetched. A ref that is no
/// branch or tag of the repository (a commit id, a pull ref, an unknown name)
/// is not checked, and the card says the source is as the requester stated
/// it. A hex-only or commit-shaped name that is a branch is checked as one.
/// The card shows the ref.
#[test]
fn verify_requires_the_ref_head_to_be_the_pinned_commit() {
    let ok: BTreeMap<String, (String, Option<String>)> =
        [("acme".to_string(), (ACME.to_string(), None))].into();
    let pinned = |git_ref: Option<&str>, c: char| ServiceSource::Github {
        repo: "acme/tools".into(),
        path: None,
        git_ref: git_ref.map(str::to_string),
        commit: c.to_string().repeat(40),
    };
    let fetched = |api: &FakeGitHub| {
        api.asked
            .lock()
            .unwrap()
            .iter()
            .any(|a| a.starts_with("tarball"))
    };
    let api = fake();
    let e = block_on(github::verify(&api, &pinned(None, 'c'), &ok)).unwrap_err();
    assert!(
        e.contains(&format!("the default branch is at {}", "a".repeat(40))),
        "{e}"
    );
    let e = block_on(github::verify(&api, &pinned(Some("v1.2.0"), 'c'), &ok)).unwrap_err();
    assert!(
        e.contains(&format!("'v1.2.0' is at {}", "b".repeat(40))),
        "{e}"
    );
    let e = block_on(github::verify(&api, &pinned(Some("dup"), 'a'), &ok)).unwrap_err();
    assert!(e.contains("both a branch and a tag"), "{e}");
    assert!(
        !fetched(&api),
        "nothing fetched at a commit no branch or tag points at"
    );
    // The ref's head at the pin: checked.
    for (r, c) in [
        (Some("v1.2.0"), 'b'),
        (Some("refs/tags/v1.2.0"), 'b'),
        (None, 'a'),
        (Some("refs/heads/main"), 'a'),
        (Some("cafe"), 'e'),
        (Some("1111111111111111111111111111111111111111"), 'e'),
    ] {
        assert_eq!(
            block_on(github::verify(&api, &pinned(r, c), &ok)),
            Ok(SourceCheck::Fetched),
            "{r:?}"
        );
    }
    // No branch or tag of the repository: as stated, nothing fetched.
    let api = fake();
    for (r, c) in [
        ("cccccccc", 'c'),
        (&*"c".repeat(40), 'c'),
        ("pull/1/head", 'd'),
        ("refs/pull/1/head", 'd'),
        ("no-such-ref", 'c'),
    ] {
        assert_eq!(
            block_on(github::verify(&api, &pinned(Some(r), c), &ok)),
            Ok(SourceCheck::NotBranchOrTag),
            "{r}"
        );
    }
    assert!(!fetched(&api));
    // A `refs/` name outside heads and tags asks GitHub nothing.
    let before = api.asked.lock().unwrap().len();
    assert_eq!(
        block_on(github::verify(&api, &pinned(Some("refs/pull/7/head"), 'd'), &ok)),
        Ok(SourceCheck::NotBranchOrTag)
    );
    assert_eq!(api.asked.lock().unwrap().len(), before);

    // The card names the ref.
    let reg = crate::service::ServiceRegistry::compiled_only();
    let snap: BTreeMap<_, _> = [("acme".to_string(), admitted("acme", ACME, None))].into();
    let card = |src: &ServiceSource, check| {
        add_card(&snap, src, check, false, &BTreeMap::new(), &reg)
            .unwrap()
            .from
    };
    let from = card(&pinned(Some("v1.2.0"), 'b'), SourceCheck::Fetched);
    assert!(from.contains("github:acme/tools (v1.2.0) @ "), "{from}");
    assert!(from.contains("'v1.2.0' is at this commit"), "{from}");
    let from = card(&pinned(None, 'a'), SourceCheck::Fetched);
    assert!(
        from.contains("(default branch)") && from.contains("the default branch is at this commit")
    );
    let from = card(&pinned(Some("pull/1/head"), 'd'), SourceCheck::NotBranchOrTag);
    assert!(
        from.contains("as stated by the requester")
            && from.contains("(pull/1/head)")
            && from.contains("'pull/1/head' is neither"),
        "{from}"
    );
}

/// The definition digest takes each part length-prefixed and the policy
/// tagged present or absent, so different (service, policy) pairs differ.
#[test]
fn definition_digest_is_injective() {
    let d = definition_digest;
    assert_ne!(d("a\0b", None), d("a", Some("b")));
    assert_ne!(d("a", Some("")), d("a", None));
    assert_ne!(d("ab", Some("c")), d("a", Some("bc")));
    assert_eq!(d("a", Some("b")), d("a", Some("b")));
}

// ── local folders: special files and the openat walk ───────────────────────

#[cfg(unix)]
#[test]
fn local_fifo_is_refused_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(d.path().join("service.toml"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !made {
        eprintln!("mkfifo unavailable; skipped");
        return;
    }
    // Opened non-blocking and refused on fstat: the read never waits for a writer.
    let e = read_local(d.path()).unwrap_err();
    assert!(e[0].contains("service.toml is not a regular file"), "{e:?}");
    // The same under a collection.
    let d2 = tempfile::tempdir().unwrap();
    write(
        &d2.path().join("services/a1/service.toml"),
        &svc("a1", "a.dev"),
    );
    std::process::Command::new("mkfifo")
        .arg(d2.path().join("services/a1/policy.toml"))
        .status()
        .unwrap();
    let e = read_local(d2.path()).unwrap_err();
    assert!(
        e.iter()
            .any(|p| p.contains("services/a1/policy.toml is not a regular file")),
        "{e:?}"
    );
}

#[cfg(unix)]
#[test]
fn local_walk_opens_each_component_without_following_links() {
    use super::local::{Folder, Opened};
    let d = tempfile::tempdir().unwrap();
    write(&d.path().join("real/one/service.toml"), ACME);
    // A link on the path the user typed is theirs: resolved once, then walked.
    std::os::unix::fs::symlink(d.path().join("real"), d.path().join("via")).unwrap();
    let f = read_local(&d.path().join("via/one")).unwrap();
    assert!(f.single);
    // Inside the source, every component is opened relative to its parent
    // with O_NOFOLLOW: a link is reported as one, never entered or read.
    let root = Folder::open_root(&d.path().join("real")).ok().unwrap();
    std::os::unix::fs::symlink(d.path().join("real/one"), d.path().join("real/two")).unwrap();
    assert!(matches!(root.folder("two"), Opened::Link));
    assert!(matches!(root.folder("one"), Opened::Found(_)));
    assert!(matches!(root.folder("absent"), Opened::Absent));
    std::os::unix::fs::symlink(
        d.path().join("real/one/service.toml"),
        d.path().join("real/linked.toml"),
    )
    .unwrap();
    assert!(matches!(root.file("linked.toml"), Opened::Link));
    let Opened::Found(one) = root.folder("one") else {
        panic!()
    };
    assert!(matches!(one.file("service.toml"), Opened::Found(_)));
    assert!(
        matches!(root.file("one"), Opened::Found(_)),
        "opened, then refused by fstat"
    );
    let Opened::Found(dir_as_file) = root.file("one") else {
        panic!()
    };
    assert_eq!(
        super::local::read_text(dir_as_file).unwrap_err(),
        "is not a regular file"
    );
}
