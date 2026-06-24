//! `sc install [--agent <variant>] [--first-time]` — "wire up an agent on an
//! already-paired host". Prints a paste-prompt that points the agent at this
//! host's local daemon vault URL + broker bearer.
//!
//! Two-step model (matches the safeclaw.pro Connect-a-new-agent modal):
//!
//!   1. `sc login --pair-token <SPT>` once per host. Exchanges the one-shot
//!      pair-token minted at safeclaw.pro/dashboard for this host's persistent
//!      daemon credential and active vault (writes
//!      `~/.safeclaw/device-key` + the active CLI config).
//!   2. `sc install` to wire up an agent (Claude / Cursor / Codex / …) on that
//!      paired host. Emits the agent install prompt with the env vars to set.
//!      Run again per additional agent on the same host.
//!
//! New-device users with no `~/.safeclaw/device-key` go through the
//! safeclaw.pro Connect-a-new-agent modal FIRST — that modal emits a combined
//! `sc login --pair-token <X> && sc install` prompt. `sc install --first-time`
//! is the just-pointer-to-that-flow variant for users who land here directly.
//!
//! Prompt format (unified with SaaS "Install on agent" modal):
//!
//!   Install the SafeClaw skill from <skill_url> on this agent, and set these
//!   env vars in the agent environment: SAFECLAW_VAULT_URL=<vault_url>
//!   [and SAFECLAW_API_KEY=<key>]. Persist the install so future sessions
//!   load it automatically.
//!
//! `--agent` only affects the `?agent=` query param on the skill URL (which
//! controls the frontmatter in the file the agent receives). The prompt body
//! is identical across agents — every agent needs the same env vars.

use crate::cli::active::load as load_config;
use crate::config::InstallArgs;

/// Public SaaS host shown to first-time users in the redirect hint when no
/// active custodian is configured yet (i.e. before `sc login` ever ran).
const DEFAULT_SAAS_HOST: &str = "https://safeclaw.pro";

pub fn run(args: InstallArgs) -> Result<(), String> {
    let cfg = load_config()?;

    // First-time redirect: print a pointer to the Connect-a-new-agent modal
    // and exit. Doesn't require an active config — that's exactly the state
    // a brand-new user is in.
    if args.first_time {
        let host = cfg
            .custodian
            .as_deref()
            .map(|c| c.trim_end_matches('/').to_string())
            .unwrap_or_else(|| DEFAULT_SAAS_HOST.to_string());
        println!(
            "First-time install? Go to {}/dashboard and click \"Connect a new agent\" \
             to get a one-shot pair-token + install prompt. \
             `sc install` (without --first-time) is for adding another agent on a host \
             that's already paired via `sc login --pair-token <TOKEN>`.",
            host
        );
        return Ok(());
    }

    let custodian = cfg.custodian
        .ok_or("no active config — pair this host first: `sc login --pair-token <TOKEN>` \
                (get a token from safeclaw.pro → Connect a new agent), or run \
                `sc install --first-time` for instructions")?;
    let vault = cfg.vault
        .ok_or("no active vault — pair this host first: `sc login --pair-token <TOKEN>` \
                (get a token from safeclaw.pro → Connect a new agent)")?;

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

    // API key: SaaS users set $SAFECLAW_API_KEY; a self-hosted localhost
    // daemon uses the provisioned api-key (~/.safeclaw/api-key) so the agent
    // satisfies the broker gate. Empty when neither applies.
    let api_key = crate::cli::active::resolve_api_key(custodian);

    let prompt = if api_key.is_empty() {
        format!(
            "Install the SafeClaw skill from {} on this agent, and set this env var in the agent environment: SAFECLAW_VAULT_URL={}. Persist the install so future sessions load it automatically.",
            skill_url, vault_url
        )
    } else {
        format!(
            "Install the SafeClaw skill from {} on this agent, and set these env vars in the agent environment: SAFECLAW_VAULT_URL={} and SAFECLAW_API_KEY={}. Persist the install so future sessions load it automatically.",
            skill_url, vault_url, api_key
        )
    };

    println!("Copy and send to your agent:\n");
    println!("```");
    println!("{}", prompt);
    println!("```");

    Ok(())
}
