/// NL-Cooker: render a recipe as human-readable setup instructions (v2).

use super::Recipe;
use crate::service::ServiceRegistry;

/// Render a recipe into step-by-step instructions (printed to stderr).
pub fn render(service_id: &str, recipe: &Recipe) {
    let display_name = recipe.recipe
        .as_ref()
        .and_then(|r| r.display_name.as_deref())
        .unwrap_or(service_id);

    // Derive credential requirement from service.toml [[upstream]].auth
    let registry = ServiceRegistry::load();
    let requires_cred = registry.get(service_id)
        .map(|d| d.upstream_auth().is_some())
        .unwrap_or(false);

    eprintln!("Connect: {}\n", display_name);
    eprintln!("{}", "=".repeat(40));

    let mut step_num = 0;

    // Credential step (auto-derived from service.toml having [upstream.auth])
    if requires_cred {
        step_num += 1;
        eprintln!("\nStep {}: Add credentials to SafeClaw vault", step_num);
        eprintln!("  Open the SafeClaw console and add service '{}'", service_id);
        eprintln!("  with your API key or OAuth tokens.");
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
        let target_label = match step.target.as_str() {
            "safeclaw" => " [SafeClaw]",
            "safeclaw.vault" => " [SafeClaw Vault]",
            "openclaw" => " [OpenClaw]",
            _ => "",
        };
        eprintln!("\nStep {}:{} {}", step_num, target_label, step.title);

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
            eprintln!("  Set in config:");
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
            eprintln!("  -> Restart after this step");
        }
    }

    eprintln!("\n{}", "=".repeat(40));
    eprintln!("Done! Your service '{}' is ready to use.", service_id);
}
