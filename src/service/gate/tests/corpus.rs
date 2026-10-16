//! Evidence that no definition text can crash or stall the gate: a
//! deterministic corpus (truncations, deep nesting, oversized counts, random
//! bytes, seeded mutations of every compiled-in definition) fed through
//! [`admit`], asserting it never panics and every input finishes in bounded
//! time. The same entry point is the cargo-fuzz target under `fuzz/`.

use super::super::admit;
use crate::service::limits::*;
use std::time::{Duration, Instant};

/// xorshift64*: a fixed, dependency-free generator so the corpus is the same
/// on every run and every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Fragments a mutation splices in: TOML structure, the gate's own grammar,
/// and the characters it must refuse.
const TOKENS: &[&str] = &[
    "[",
    "]",
    "[[",
    "]]",
    "{",
    "}",
    "=",
    "\"",
    "'",
    "\"\"\"",
    "\\",
    "\\u",
    "\n",
    "#",
    ",",
    ".",
    "*",
    "**",
    "/",
    "?",
    "{{",
    "}}",
    "|",
    "vars.",
    "\u{1b}[31m",
    "\u{202e}",
    "\u{2066}",
    "\u{85}",
    "\u{0}",
    "\r",
    "\t",
    "2130706433",
    "0x7f.1",
    "127.0.0.1",
    "localhost",
    "user@",
    "https://",
    "(",
    ")",
    "(a*)*",
    "\\w{99}",
    "ask",
    "ask-always",
    "deny",
    "allow",
    "level",
    "match",
    "body",
    "when",
    "id",
    "label",
    "[service]",
    "[auth]",
    "[requests.x]",
    "[[rule]]",
    "[default]",
    "[policy]",
    "type = \"oauth2\"",
    "9999999999999999999999",
    "-1",
    "true",
    "1979-05-27T07:32:00Z",
    "\u{fffd}",
    "\u{10ffff}",
];

fn mutate(src: &str, rng: &mut Rng) -> String {
    let mut s: Vec<u8> = src.as_bytes().to_vec();
    let edits = 1 + rng.below(4);
    for _ in 0..edits {
        let at = rng.below(s.len() + 1);
        match rng.below(6) {
            // Flip one byte.
            0 if !s.is_empty() => {
                let i = at.min(s.len() - 1);
                s[i] ^= 1 << rng.below(8);
            }
            // Delete a run.
            1 if !s.is_empty() => {
                let end = (at + 1 + rng.below(32)).min(s.len());
                s.drain(at.min(end)..end);
            }
            // Duplicate a run (repeated keys, tables, rules).
            2 if !s.is_empty() => {
                let start = at.min(s.len() - 1);
                let end = (start + 1 + rng.below(256)).min(s.len());
                let run = s[start..end].to_vec();
                s.splice(end..end, run);
            }
            // Insert a fragment.
            _ => {
                let tok = TOKENS[rng.below(TOKENS.len())].as_bytes();
                s.splice(at..at, tok.iter().copied());
            }
        }
    }
    String::from_utf8_lossy(&s).into_owned()
}

/// Every compiled definition: (id, service.toml, policy.toml).
fn compiled() -> Vec<(&'static str, &'static str, Option<&'static str>)> {
    let policies: std::collections::HashMap<&str, &str> =
        crate::generated_services::compiled_policy_tomls()
            .iter()
            .copied()
            .collect();
    crate::generated_services::compiled_service_tomls()
        .iter()
        .map(|(id, svc)| (*id, *svc, policies.get(id).copied()))
        .collect()
}

/// Cut `src` at `n` evenly spaced char boundaries.
fn truncations(src: &str, n: usize) -> Vec<String> {
    let step = (src.len() / n).max(1);
    (0..src.len())
        .step_by(step)
        .map(|i| {
            let mut cut = i;
            while !src.is_char_boundary(cut) {
                cut -= 1;
            }
            src[..cut].to_string()
        })
        .collect()
}

fn structural() -> Vec<(String, Option<String>)> {
    let svc = "[service]\nid = \"x\"\nname = \"X\"\nhosts = [\"api.x.com\"]\n";
    // Deep nesting that still fits the byte limit, so the parser sees it.
    let deep = 30_000;
    let mut out: Vec<(String, Option<String>)> = vec![
        // Deep nesting: arrays, inline tables, dotted keys, table headers.
        (format!("a = {}{}", "[".repeat(deep), "]".repeat(deep)), None),
        (format!("a = {}1{}", "{b = ".repeat(deep / 6), "}".repeat(deep / 6)), None),
        (format!("{} = 1", vec!["a"; deep / 2].join(".")), None),
        (format!("[{}]", vec!["a"; deep / 2].join(".")), None),
        // Each line within the parser's depth, stacked: header, dotted key,
        // inline tables and arrays.
        (
            format!(
                "[{}]\n{} = {}{}{}\n",
                vec!["h"; 70].join("."),
                vec!["k"; 70].join("."),
                "{a = [".repeat(35),
                "1",
                "]}".repeat(35)
            ),
            None,
        ),
        (format!("{svc}[requests.{}]", vec!["a"; 5000].join(".")), None),
        (
            svc.to_string(),
            Some(format!("rule = {}{}", "[".repeat(deep), "]".repeat(deep))),
        ),
        (
            svc.to_string(),
            Some(format!("rule = [{}]", vec!["{}"; MAX_FILE_BYTES / 4].join(","))),
        ),
        // Oversized counts within the byte limit.
        (
            format!(
                "[service]\nid = \"x\"\nname = \"X\"\nhosts = [{}]\n",
                vec!["\"a.b.co\""; MAX_FILE_BYTES / 12].join(",")
            ),
            None,
        ),
        (
            format!(
                "{svc}secrets = [{}]\n",
                vec!["\"K\""; MAX_FILE_BYTES / 6].join(",")
            ),
            None,
        ),
        (
            svc.to_string(),
            Some("[[rule]]\nid = \"r\"\nlabel = \"R\"\nmatch = \"/x\"\nlevel = \"ask\"\n".repeat(MAX_FILE_BYTES / 64)),
        ),
        (
            svc.to_string(),
            Some(format!(
                "[[rule]]\nid = \"r\"\nlabel = \"R\"\nlevel = \"ask\"\nmatch = [{}]\n",
                vec!["\"/x\""; MAX_FILE_BYTES / 6].join(",")
            )),
        ),
        (
            svc.to_string(),
            // As many maximal regexes as fit, each over the compiled-size limit.
            Some(
                (0..MAX_FILE_BYTES / 1100)
                    .map(|i| {
                        format!(
                            "[[rule]]\nid = \"r{i}\"\nlabel = \"R\"\nmatch = \"/x\"\nlevel = \"ask\"\nbody = '{}'\n",
                            "(\\w{99}){99}".repeat(70)
                        )
                    })
                    .collect(),
            ),
        ),
        (
            format!(
                "{svc}[requests.r]\nmatch = \"/x\"\nscope = []\nvars = {{ {} }}\n",
                (0..3000).map(|i| format!("v{i} = \"/a\"")).collect::<Vec<_>>().join(", ")
            ),
            None,
        ),
        // Long strings and keys, and a file just over the limit.
        (format!("{svc}help = \"{}\"\n", "h".repeat(MAX_FILE_BYTES - 200)), None),
        (format!("\"{}\" = 1\n{svc}", "k".repeat(MAX_FILE_BYTES - 200)), None),
        (format!("{svc}# {}\n", "x".repeat(MAX_FILE_BYTES)), None),
        (format!("setup = \"\"\"{}\"\"\"\n{svc}", "\n".repeat(MAX_FILE_BYTES - 100)), None),
        // Many consent tokens.
        (
            format!(
                "{svc}[requests.r]\nmatch = \"/x\"\nvars.a = \"/a\"\nscope = [\"a\"]\nconsent = \"{}\"\n",
                "{{ vars.a | email }}".repeat(40)
            ),
            None,
        ),
        (String::new(), None),
        (String::new(), Some(String::new())),
    ];
    // Every C0, DEL and C1 control and every bidi control in a name.
    for c in (0u32..0x20)
        .chain(0x7f..0xa0)
        .chain([0x61c, 0x200e, 0x200f])
        .chain(0x202a..0x202f)
        .chain(0x2066..0x206a)
    {
        let ch = char::from_u32(c).unwrap();
        out.push((svc.replace("\"X\"", &format!("\"X\\u{:04x}\"", c)), None));
        out.push((svc.replace("X\"\n", &format!("X{}\"\n", ch)), None));
    }
    out
}

#[test]
fn gate_never_panics_and_stays_bounded_on_a_hostile_corpus() {
    let mut rng = Rng(0x5AFE_C1A4_0000_0001);
    let mut corpus: Vec<(String, Option<String>)> = structural();
    for (_, svc, pol) in compiled() {
        for t in truncations(svc, 24) {
            corpus.push((t, pol.map(str::to_string)));
        }
        if let Some(p) = pol {
            for t in truncations(p, 24) {
                corpus.push((svc.to_string(), Some(t)));
            }
        }
        for _ in 0..32 {
            corpus.push((mutate(svc, &mut rng), pol.map(str::to_string)));
            if let Some(p) = pol {
                corpus.push((svc.to_string(), Some(mutate(p, &mut rng))));
            }
        }
    }
    for _ in 0..512 {
        let len = rng.below(2048);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        corpus.push((String::from_utf8_lossy(&bytes).into_owned(), None));
    }

    let started = Instant::now();
    let mut slowest = (Duration::ZERO, 0usize);
    let mut admitted = 0usize;
    for (i, (svc, pol)) in corpus.iter().enumerate() {
        let t = Instant::now();
        let outcome = std::panic::catch_unwind(|| admit(None, svc, pol.as_deref()));
        let took = t.elapsed();
        let Ok(result) = outcome else {
            panic!(
                "the gate panicked on corpus input #{} (service {} bytes, policy {:?} bytes)",
                i,
                svc.len(),
                pol.as_ref().map(String::len)
            );
        };
        if let Err(problems) = &result {
            assert!(!problems.is_empty(), "#{i}: a rejection names its problems");
            assert!(problems.len() <= MAX_REPORTED_PROBLEMS + 1, "#{i}");
            for p in problems {
                assert!(
                    !p.chars()
                        .any(|c| c != '\n' && c != '\t' && crate::util::is_unsafe_display_char(c)),
                    "#{i}: problem text carries a control character: {p:?}"
                );
            }
        } else {
            admitted += 1;
        }
        if took > slowest.0 {
            slowest = (took, i);
        }
    }
    let total = started.elapsed();
    eprintln!(
        "gate corpus: {} inputs, {} admitted, total {:?}, slowest #{} {:?}",
        corpus.len(),
        admitted,
        total,
        slowest.1,
        slowest.0
    );
    // Generous for an unoptimized test build on a loaded machine; a
    // super-linear path in the parser or a check blows far past it.
    assert!(
        slowest.0 < Duration::from_secs(10),
        "corpus input #{} took {:?}",
        slowest.1,
        slowest.0
    );
}
