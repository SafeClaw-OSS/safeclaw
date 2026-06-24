//! Human-readable rendering of an `Operation` for the approve UI.

use super::operation::{as_enroll_credential, ActType, Operation};

/// Returns a short string describing what the operation will do.
/// Frontend can show this to the user before they confirm.
pub fn render_operation(op: &Operation) -> String {
    match &op.act.kind {
        ActType::Enroll if op.act.target == "passkeys" => {
            // Add-passkey to an already-set-up vault. New credential
            // material lives under scope.new (not the top-level fields
            // first-time Enroll uses), so don't route through
            // as_enroll_credential here.
            let device = op
                .act
                .scope
                .get("new")
                .and_then(|n| n.get("device_name"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("(new device)");
            format!("Add passkey \"{}\" to this vault.", device)
        }
        ActType::Enroll => {
            match as_enroll_credential(op) {
                Ok(cred) => format!(
                    "Set up vault with passkey \"{}\".",
                    if cred.device_name.is_empty() {
                        "(new device)"
                    } else {
                        cred.device_name.as_str()
                    }
                ),
                Err(_) => "Set up vault.".to_string(),
            }
        }
        ActType::Write => "Update vault contents.".to_string(),
        ActType::Export => {
            format!(
                "Reveal the value at \"{}\" to the requesting agent.",
                op.act.target
            )
        }
        ActType::Use => format!(
            "Use the secret at \"{}\" for a brokered call (target details in scope).",
            op.act.target
        ),
        other => format!("Operation: {:?}", other),
    }
}
