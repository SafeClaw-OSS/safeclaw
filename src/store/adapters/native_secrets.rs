//! `native-secrets` adapter — reads from sudp's `ProtectedState.targets`
//! via the [`VaultPlaintextView::native_secrets`] materialisation.

use std::collections::BTreeMap;

use crate::storage::plaintext::VaultPlaintextView;

/// Owns a snapshot of native-secrets items. The snapshot is taken at
/// adapter construction time — adapters are short-lived per-request, so
/// the cloning cost is bounded and avoids lifetime ties to the view.
pub struct NativeSecretsAdapter {
    items: BTreeMap<String, Vec<u8>>,
}

impl NativeSecretsAdapter {
    pub fn from_view(view: &VaultPlaintextView) -> Self {
        Self {
            items: view.native_secrets.clone(),
        }
    }

    /// Sync — no I/O, just a map lookup.
    pub fn resolve(&self, name: &str) -> Option<Vec<u8>> {
        self.items.get(name).cloned()
    }

    pub fn list(&self) -> Vec<String> {
        self.items.keys().cloned().collect()
    }
}
