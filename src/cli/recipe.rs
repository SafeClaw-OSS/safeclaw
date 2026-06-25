//! `sc recipe validate <path>` — run the static recipe safety validator
//! offline (no daemon). Mirrors exactly what the console's custom-TOML upload
//! editor will enforce, so authors can check a recipe before submitting it.

use crate::config::RecipeValidateArgs;
use crate::service::validate::validate_recipe;

pub async fn run_validate(args: RecipeValidateArgs) -> Result<(), String> {
    let path = &args.path;
    let toml_str = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;

    match validate_recipe(&toml_str, args.first_party) {
        Ok(()) => {
            let mode = if args.first_party {
                " (first-party: exec allowed)"
            } else {
                ""
            };
            println!("✓ {} — valid{}", path.display(), mode);
            Ok(())
        }
        Err(problems) => {
            eprintln!(
                "✗ {} — {} problem{}:",
                path.display(),
                problems.len(),
                if problems.len() == 1 { "" } else { "s" }
            );
            for p in &problems {
                eprintln!("  • {}", p);
            }
            // Non-zero exit via the Err path (main prints + boxes it).
            Err(format!("{}: recipe validation failed", path.display()))
        }
    }
}
