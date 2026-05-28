//! `sc install [--agent <variant>]` — print the agent install prompt.
//!
//! Outputs a two-sentence prompt the user pastes into their agent. The agent
//! then self-fetches the skill file and sets the env vars autonomously.
//!
//! Prompt format (unified with SaaS "Install on agent" modal):
//!
//!   Install the SafeClaw skill from <skill_url>. Set these env vars:
//!   SAFECLAW_VAULT_URL=<vault_url> [and SAFECLAW_API_KEY=<key>].
//!
//! `--agent` only affects the `?agent=` query param on the skill URL (which
//! controls the frontmatter in the file the agent receives). The two-sentence
//! prompt body is identical for all agents — every agent needs the same env
//! vars.

use crate::cli::active::load as load_config;
use crate::config::InstallArgs;

pub fn run(args: InstallArgs) -> Result<(), String> {
    let cfg = load_config()?;
    let custodian = cfg.custodian
        .ok_or("no active config — run `safeclaw vault use` or `safeclaw vault create` first")?;
    let vault = cfg.vault
        .ok_or("no active vault — run `safeclaw vault use` or `safeclaw vault create` first")?;

    let custodian = custodian.trim_end_matches('/');
    let vault_url = format!("{}/v/{}", custodian, vault);

    // Build skill URL — include ?agent= only when explicitly set (default
    // is empty, which daemon maps to the no-frontmatter "other" variant).
    let skill_url = match args.agent.as_deref() {
        Some(agent) if !agent.is_empty() => {
            format!("{}/skill.md?agent={}", custodian, urlencoding::encode(agent))
        }
        _ => format!("{}/skill.md", custodian),
    };

    // API key: read from caller's env (SaaS users set this; OSS leave empty).
    let api_key = std::env::var("SAFECLAW_API_KEY").unwrap_or_default();

    // Two-sentence prompt. Omit SAFECLAW_API_KEY when empty (OSS users don't
    // need it — daemon ignores the Authorization header).
    if api_key.is_empty() {
        println!(
            "Install the SafeClaw skill from {}. Set these env vars: SAFECLAW_VAULT_URL={}. Persist the install so future sessions load it automatically.",
            skill_url, vault_url
        );
    } else {
        println!(
            "Install the SafeClaw skill from {}. Set these env vars: SAFECLAW_VAULT_URL={} and SAFECLAW_API_KEY={}. Persist the install so future sessions load it automatically.",
            skill_url, vault_url, api_key
        );
    }

    Ok(())
}
