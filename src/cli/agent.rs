//! `sc agent` — the agents on this machine. Each agent is an AIK (Ed25519,
//! `ag_` id) whose seed lives in `~/.safeclaw/agents/<name>/identity` (0600)
//! and never enters the agent's env. The agent proves possession of it on every
//! request to the daemon (`scpop1` proofs, minted by `sc run`'s transport
//! shim); there is no agent bearer key (trust-reset design D8).
//!
//! `sc agent add` admits the AIK by code, the same flow as `sc login` with kind
//! `agent` (contract 5): the approver ticks the vaults it may use in the
//! console, which signs one authorized-agents record per vault. The daemon
//! honors those records only when signed by its own person or by a vault owner
//! (design D6), so what an agent may reach is decided in the console, never by
//! this command.

use crate::cli::active::load as load_config;
use crate::cli::admit::{
    agent_fields, confirm, person_change_warning, post_and_wait, require_confirmable, Target,
};
use crate::config::{AgentAddArgs, AgentRmArgs, AgentSubcommand};
use crate::crypto::admission::AdmitCode;
use crate::identity::IdKind;

pub async fn run(sub: AgentSubcommand, json: bool) -> Result<(), String> {
    match sub {
        AgentSubcommand::Add(a) => add(a).await,
        AgentSubcommand::Ls => ls(json),
        AgentSubcommand::Rm(a) => rm(a),
    }
}

/// An agent name is a directory name under `~/.safeclaw/agents/`: refuse
/// anything that could escape it or hide.
pub fn validate_name(name: &str) -> Result<(), String> {
    let bad = name.trim().is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name
            .chars()
            .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
        || name.len() > 64;
    if bad {
        return Err(format!(
            "invalid agent name {:?}: use 1-64 characters without '/', '\\' or a leading '.'",
            name
        ));
    }
    Ok(())
}

/// The pairing target of THIS machine: an agent is served by this machine's
/// daemon, so the machine must be paired first.
fn paired_target() -> Result<(Target, Option<String>), String> {
    let cfg = load_config().map_err(|e| format!("read config: {}", e))?;
    let backend = cfg
        .cloud_backend
        .filter(|s| !s.is_empty())
        .ok_or(crate::device::NOT_PAIRED)?
        .trim_end_matches('/')
        .to_string();
    let console = cfg
        .frontend_origin
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| crate::cli::active::derive_frontend_from_backend(&backend));
    Ok((Target { backend, console }, cfg.person))
}

async fn add(args: AgentAddArgs) -> Result<(), String> {
    validate_name(&args.name)?;
    // Fail fast when the account can't be confirmed (no terminal, no --yes):
    // before the AIK is minted or the admission is posted.
    require_confirmable("sc agent add", args.yes)?;
    let (target, own_person) = paired_target()?;
    let identity_path = crate::identity_file::agent_identity_path(&args.name)?;
    if identity_path.exists() {
        return Err(format!(
            "an agent named '{}' already exists on this machine ({}). Pick another name, \
             or `sc agent rm {}` first.",
            args.name,
            identity_path.display(),
            args.name
        ));
    }
    let cfg = load_config().unwrap_or_default();
    let broker_url = format!(
        "{}:{}",
        crate::cli::active::device_daemon_host(&cfg),
        crate::config::PROXY_PORT
    );

    // Mint the AIK. Persisted only after the approval verified and the user
    // confirmed, so a declined or expired admission leaves no identity file.
    let (seed, ag_id) = crate::identity_file::mint(IdKind::Agent);
    let (aik, _) = crate::identity_file::resolve(IdKind::Agent, &seed);
    let fields = agent_fields(aik.public_bytes(), &args.name);
    let code = AdmitCode::generate();
    let approved = post_and_wait(
        &target,
        &fields,
        &code,
        &format!("the agent '{}'", args.name),
    )
    .await?;

    if let Some(w) = person_change_warning(own_person.as_deref(), &approved.us) {
        eprintln!();
        eprintln!(
            "{}",
            w.replace(
                "this machine was previously paired to",
                "this machine is paired to"
            )
        );
    }
    eprintln!();
    if !confirm(
        &format!(
            "Admit the agent '{}' to {} ({})?",
            args.name, approved.email, approved.us
        ),
        args.yes,
    )? {
        return Err(format!(
            "not admitted: you declined the account. Nothing was saved; remove '{}' in the \
             console (Agents) if it shows up there.",
            args.name
        ));
    }
    crate::identity_file::write(&identity_path, IdKind::Agent, &seed)?;

    // The agent's env: two non-secret lines (the daemon's API face and the AIK
    // identity PATH). Safe to show and to append to the agent's env file.
    println!("SAFECLAW_BROKER_URL={}", broker_url);
    println!("SAFECLAW_AGENT_IDENTITY={}", identity_path.display());

    eprintln!(
        "\nAdmitted the agent '{}' ({}) to {} ({}).",
        args.name, ag_id, approved.email, approved.us
    );
    eprintln!(
        "Its SafeClaw env (two non-secret lines: the broker URL and its identity-file path) \
         went to stdout; append them to the env file your framework loads. It can use the \
         vaults ticked for it in the console (Agents)."
    );
    Ok(())
}

/// One local agent identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAgent {
    pub name: String,
    pub id: String,
}

/// The agent identities under `<home>/.safeclaw/agents/`, sorted by name.
/// Unreadable entries are listed with an empty id rather than hidden.
pub fn local_agents_in(dir: &std::path::Path) -> Vec<LocalAgent> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<LocalAgent> = rd
        .flatten()
        .filter(|e| e.path().join("identity").is_file())
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let id = crate::identity_file::load(&e.path().join("identity"))
                .ok()
                .filter(|l| l.kind == IdKind::Agent)
                .map(|l| l.id)
                .unwrap_or_default();
            LocalAgent { name, id }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn agents_dir() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot locate home dir".to_string())?;
    Ok(home.join(".safeclaw").join("agents"))
}

fn ls(json: bool) -> Result<(), String> {
    let agents = local_agents_in(&agents_dir()?);
    if json {
        let arr: Vec<serde_json::Value> = agents
            .iter()
            .map(|a| serde_json::json!({ "name": a.name, "id": a.id }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if agents.is_empty() {
        println!("(no agents on this machine yet, `sc agent add <name>`)");
        return Ok(());
    }
    for a in &agents {
        let id = if a.id.is_empty() {
            "(unreadable)"
        } else {
            &a.id
        };
        println!("{:<28} {}", a.name, id);
    }
    Ok(())
}

fn rm(args: AgentRmArgs) -> Result<(), String> {
    let agents = local_agents_in(&agents_dir()?);
    let matches: Vec<&LocalAgent> = agents
        .iter()
        .filter(|a| a.name == args.name || (!a.id.is_empty() && a.id == args.name))
        .collect();
    let agent = match matches.as_slice() {
        [a] => *a,
        [] => {
            return Err(format!(
                "no agent named '{}' on this machine (see `sc agent ls`)",
                args.name
            ))
        }
        _ => {
            return Err(format!(
                "'{}' matches several agents; remove by `ag_` id (`sc agent ls`)",
                args.name
            ))
        }
    };
    validate_name(&agent.name)?;
    let dir = agents_dir()?.join(&agent.name);
    std::fs::remove_dir_all(&dir).map_err(|e| format!("remove {}: {}", dir.display(), e))?;
    eprintln!(
        "Deleted the agent '{}' ({}) from this machine. Remove its vault access in the \
         console (Agents).",
        agent.name,
        if agent.id.is_empty() { "?" } else { &agent.id }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_names_cannot_escape_the_agents_dir() {
        for ok in ["Claude Code", "deploy-bot", "cursor_1"] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", " ", ".", "..", "../x", "a/b", "a\\b", ".hidden", "a\0b"] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn local_agents_lists_identity_dirs_only() {
        let dir = tempfile::tempdir().unwrap();
        assert!(local_agents_in(&dir.path().join("missing")).is_empty());
        let (seed, id) = crate::identity_file::mint(IdKind::Agent);
        crate::identity_file::write(
            &dir.path().join("bot").join("identity"),
            IdKind::Agent,
            &seed,
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("empty")).unwrap();
        std::fs::create_dir_all(dir.path().join("junk")).unwrap();
        std::fs::write(dir.path().join("junk").join("identity"), b"not json").unwrap();
        let got = local_agents_in(dir.path());
        assert_eq!(
            got,
            vec![
                LocalAgent {
                    name: "bot".into(),
                    id
                },
                LocalAgent {
                    name: "junk".into(),
                    id: String::new()
                },
            ]
        );
    }
}
