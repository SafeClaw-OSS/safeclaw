//! Human-readable rendering of an `Operation` for the approve UI.

use super::operation::{Act, Operation};

/// Returns a short string describing what the operation will do.
/// Frontend can show this to the user before they confirm.
pub fn render_operation(op: &Operation) -> String {
    match &op.act {
        Act::Setup { credential } => {
            format!(
                "Set up vault with passkey \"{}\".",
                if credential.device_name.is_empty() {
                    "(new device)"
                } else {
                    credential.device_name.as_str()
                }
            )
        }
        Act::Write { .. } => "Update vault contents.".to_string(),
        Act::Reveal { path } => {
            format!("Reveal the value at \"{}\" to the requesting agent.", path)
        }
    }
}
