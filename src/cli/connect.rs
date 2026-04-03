/// NL-Cooker: `safeclaw connect <service>` — prints human-readable setup instructions.
///
/// Reads recipe.toml for the specified service and renders step-by-step
/// instructions for manual installation. This is the open-source alternative
/// to the pro provisioner's automatic setup.

use std::path::Path;

#[derive(serde::Deserialize)]
struct Recipe {
    recipe: Option<RecipeMeta>,
    openclaw: Option<OpenClawDef>,
    passkey_sharing: Option<PasskeySharingDef>,
    #[serde(default)]
    steps: Vec<Step>,
}

#[derive(serde::Deserialize)]
struct RecipeMeta {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    requires_credential: Option<bool>,
}

#[derive(serde::Deserialize)]
struct OpenClawDef {
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    api: Option<String>,
    #[serde(default)]
    env_key: Option<String>,
    #[serde(default)]
    env_base_url: Option<String>,
    #[serde(default)]
    proxy_path: Option<String>,
    #[serde(default)]
    models: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct PasskeySharingDef {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    origins: Vec<String>,
}

#[derive(serde::Deserialize)]
struct Step {
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    run: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    config_patches: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    files: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    restart: Option<bool>,
}

/// Load a recipe.toml for a service, checking multiple paths.
/// Supports both flat (services/{id}/) and nested (services/{category}/{id}/) layouts.
fn load_recipe(service_id: &str) -> Option<(Recipe, String)> {
    let categories = ["llm", "channel", "integration"];
    let candidates: Vec<std::path::PathBuf> = {
        let mut v = Vec::new();
        let base_dirs: Vec<std::path::PathBuf> = {
            let mut dirs = Vec::new();
            if let Ok(data) = std::env::var("SAFECLAW_DATA") {
                dirs.push(Path::new(&data).join("services"));
            }
            if let Ok(exe) = std::env::current_exe() {
                if let Some(parent) = exe.parent() {
                    dirs.push(parent.join("services"));
                }
            }
            dirs
        };
        for base in &base_dirs {
            // Nested: services/{category}/{id}/recipe.toml
            for cat in &categories {
                v.push(base.join(cat).join(service_id).join("recipe.toml"));
            }
            // Flat: services/{id}/recipe.toml
            v.push(base.join(service_id).join("recipe.toml"));
        }
        v
    };

    for path in &candidates {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(recipe) = toml::from_str::<Recipe>(&content) {
                    return Some((recipe, content));
                }
            }
        }
    }

    // Compiled-in fallback
    let toml_str = match service_id {
        // llm
        "anthropic" => include_str!("../../services/llm/anthropic/recipe.toml"),
        "claude-code" => include_str!("../../services/llm/claude-code/recipe.toml"),
        "openai" => include_str!("../../services/llm/openai/recipe.toml"),
        "openai-codex" => include_str!("../../services/llm/openai-codex/recipe.toml"),
        "google" => include_str!("../../services/llm/google/recipe.toml"),
        "deepseek" => include_str!("../../services/llm/deepseek/recipe.toml"),
        "groq" => include_str!("../../services/llm/groq/recipe.toml"),
        // channel
        "telegram" => include_str!("../../services/channel/telegram/recipe.toml"),
        "weixin" => include_str!("../../services/channel/weixin/recipe.toml"),
        // integration
        "nodpay" => include_str!("../../services/integration/nodpay/recipe.toml"),
        "openclaw-dashboard" => include_str!("../../services/integration/openclaw-dashboard/recipe.toml"),
        _ => return None,
    };

    toml::from_str::<Recipe>(toml_str).ok().map(|r| (r, toml_str.to_string()))
}

/// List all available services with recipes.
fn list_services() {
    eprintln!("Available services:\n");

    eprintln!("  LLM Providers:");
    for (id, name) in [
        ("anthropic", "Anthropic (API key)"),
        ("claude-code", "Claude Code (OAuth)"),
        ("openai", "OpenAI (API key)"),
        ("openai-codex", "OpenAI Codex (OAuth)"),
        ("google", "Google AI (API key)"),
        ("deepseek", "DeepSeek"),
        ("groq", "Groq"),
    ] {
        eprintln!("    safeclaw connect {:<16} {}", id, name);
    }

    eprintln!("\n  Channels:");
    for (id, name) in [
        ("telegram", "Telegram"),
        ("weixin", "WeChat iLink"),
    ] {
        eprintln!("    safeclaw connect {:<16} {}", id, name);
    }

    eprintln!("\n  Integrations:");
    for (id, name) in [
        ("nodpay", "NodPay"),
        ("openclaw-dashboard", "OpenClaw Dashboard"),
    ] {
        eprintln!("    safeclaw connect {:<16} {}", id, name);
    }

    eprintln!();
}

pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        list_services();
        return Ok(());
    }

    let service_id = &args[0];

    let (recipe, _) = load_recipe(service_id)
        .ok_or_else(|| format!("No recipe found for service '{}'. Run 'safeclaw connect' to see available services.", service_id))?;

    let display_name = recipe.recipe
        .as_ref()
        .and_then(|r| r.display_name.as_deref())
        .unwrap_or(service_id);

    let requires_cred = recipe.recipe
        .as_ref()
        .and_then(|r| r.requires_credential)
        .unwrap_or(true);

    // Render instructions
    eprintln!("Connect: {}\n", display_name);
    eprintln!("{}", "=".repeat(40));

    let mut step_num = 0;

    // Credential step
    if requires_cred {
        step_num += 1;
        eprintln!("\nStep {}: Add credentials to SafeClaw vault", step_num);
        eprintln!("  Open the SafeClaw console and add service '{}'", service_id);
        eprintln!("  with your API key or OAuth tokens.");
    }

    // OpenClaw registration
    if let Some(oc) = &recipe.openclaw {
        if let (Some(env_key), Some(env_base_url), Some(proxy_path)) =
            (&oc.env_key, &oc.env_base_url, &oc.proxy_path) {
            step_num += 1;
            eprintln!("\nStep {}: Set environment variables", step_num);
            eprintln!("  Add to your OpenClaw environment:");
            eprintln!("    {}=sk-safeclaw-proxy", env_key);
            eprintln!("    {}=http://localhost:23295{}", env_base_url, proxy_path);
        }

        if let Some(plugin) = &oc.plugin {
            if oc.api.is_some() {
                step_num += 1;
                eprintln!("\nStep {}: Enable OpenClaw plugin '{}'", step_num, plugin);
                eprintln!("  Ensure '{}' is in your plugins.allow list.", plugin);
            }
        }

        if let Some(models) = &oc.models {
            if !models.is_empty() {
                step_num += 1;
                eprintln!("\nStep {}: Available models", step_num);
                for m in models {
                    eprintln!("    {}/{}", service_id, m);
                }
            }
        }
    }

    // Passkey sharing
    if let Some(ps) = &recipe.passkey_sharing {
        if ps.enabled {
            step_num += 1;
            eprintln!("\nStep {}: Enable passkey sharing", step_num);
            eprintln!("  SafeClaw will expose your passkey public coordinates to:");
            for origin in &ps.origins {
                eprintln!("    {}", origin);
            }
        }
    }

    // Recipe steps
    for step in &recipe.steps {
        step_num += 1;
        eprintln!("\nStep {}: {}", step_num, step.title);

        if let Some(desc) = &step.description {
            eprintln!("  {}", desc);
        }

        if let Some(run) = &step.run {
            let cwd_note = step.cwd.as_deref().map(|d| format!(" (in {} directory)", d)).unwrap_or_default();
            eprintln!("  Run{}:", cwd_note);
            eprintln!("    {}", run);
        }

        if let Some(files) = &step.files {
            for f in files {
                if let Some(path) = f.get("path").and_then(|v| v.as_str()) {
                    eprintln!("  Create file: {}", path);
                    if let Some(content) = f.get("content").and_then(|v| v.as_str()) {
                        eprintln!("    Content: {}", content);
                    }
                    if let Some(tmpl) = f.get("template").and_then(|v| v.as_str()) {
                        eprintln!("    (use template: {})", tmpl);
                    }
                }
            }
        }

        if let Some(patches) = &step.config_patches {
            eprintln!("  Set in OpenClaw config:");
            for p in patches {
                if let (Some(path), Some(value)) = (
                    p.get("path").and_then(|v| v.as_str()),
                    p.get("value"),
                ) {
                    eprintln!("    {} = {}", path, value);
                }
            }
        }

        if let Some(note) = &step.note {
            eprintln!("  Note: {}", note);
        }

        if step.restart.unwrap_or(false) {
            eprintln!("  -> Restart OpenClaw after this step");
        }
    }

    eprintln!("\n{}", "=".repeat(40));
    eprintln!("Done! Your service '{}' is ready to use.", service_id);

    Ok(())
}
