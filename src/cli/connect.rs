/// CLI: `safeclaw connect [service]` — list services or print setup instructions.

use crate::cooker;

pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        list_services();
        return Ok(());
    }

    let service_id = &args[0];
    let recipe = cooker::load_recipe(service_id)
        .ok_or_else(|| format!(
            "No recipe found for '{}'. Run 'safeclaw connect' to see available services.",
            service_id
        ))?;

    cooker::nl::render(service_id, &recipe);
    Ok(())
}

fn list_services() {
    // Group recipes by category using the compiled-in service definitions
    let all_services = crate::generated_services::compiled_service_tomls();
    let all_recipes = crate::generated_services::compiled_recipe_tomls();
    let recipe_ids: Vec<&str> = all_recipes.iter().map(|(id, _)| *id).collect();

    // Build (id, name, category) tuples from service.toml definitions
    let mut llm = Vec::new();
    let mut channel = Vec::new();
    let mut integration = Vec::new();

    for (id, toml_str) in all_services {
        if !recipe_ids.contains(id) { continue; } // only show services with recipes
        let name = extract_field(toml_str, "name").unwrap_or_else(|| id.to_string());
        let cat = extract_field(toml_str, "category").unwrap_or_else(|| "integration".to_string());
        match cat.as_str() {
            "llm" => llm.push((*id, name)),
            "channel" => channel.push((*id, name)),
            _ => integration.push((*id, name)),
        }
    }

    // Also add recipe-only entries (no service.toml, like nodpay)
    let service_ids: Vec<&str> = all_services.iter().map(|(id, _)| *id).collect();
    for (id, toml_str) in all_recipes {
        if service_ids.contains(id) { continue; }
        let name = extract_recipe_name(toml_str).unwrap_or_else(|| id.to_string());
        integration.push((*id, name));
    }

    eprintln!("Available services:\n");

    if !llm.is_empty() {
        eprintln!("  LLM Providers:");
        for (id, name) in &llm {
            eprintln!("    safeclaw connect {:<20} {}", id, name);
        }
    }
    if !channel.is_empty() {
        eprintln!("\n  Channels:");
        for (id, name) in &channel {
            eprintln!("    safeclaw connect {:<20} {}", id, name);
        }
    }
    if !integration.is_empty() {
        eprintln!("\n  Integrations:");
        for (id, name) in &integration {
            eprintln!("    safeclaw connect {:<20} {}", id, name);
        }
    }

    eprintln!();
}

/// Quick field extraction from TOML without full parse.
fn extract_field(toml_str: &str, field: &str) -> Option<String> {
    let prefix = format!("{} = \"", field);
    toml_str.lines()
        .find(|l| l.trim().starts_with(&prefix))
        .and_then(|l| {
            let start = l.find(&prefix)? + prefix.len();
            let end = l[start..].find('"')? + start;
            Some(l[start..end].to_string())
        })
}

fn extract_recipe_name(toml_str: &str) -> Option<String> {
    extract_field(toml_str, "display_name")
}
