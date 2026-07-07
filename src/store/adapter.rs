//! Enum-dispatched `Adapter`. New kinds = new variant + match arms.

use crate::storage::plaintext::{Category, Store, VaultPlaintextView};

use super::adapters::{
    gcp::GcpSecretManagerAdapter, native_secrets::NativeSecretsAdapter,
};

/// Errors raised by adapter operations. Resolution-path code treats
/// `NotFound` as "skip to next store" but `Backend` as fatal (abort the
/// resolution and surface upstream).
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("adapter config invalid: {0}")]
    Config(String),
    #[error("backend call failed: {0}")]
    Backend(String),
}

impl From<AdapterError> for crate::error::AppError {
    fn from(e: AdapterError) -> Self {
        crate::error::AppError::Internal(format!("adapter: {}", e))
    }
}

pub type AdapterResult<T> = std::result::Result<T, AdapterError>;

/// Runtime-dispatched adapter. One variant per supported store kind.
pub enum Adapter {
    NativeSecrets(NativeSecretsAdapter),
    Gcp(GcpSecretManagerAdapter),
}

impl Adapter {
    pub fn kind(&self) -> &'static str {
        match self {
            Adapter::NativeSecrets(_) => "native-secrets",
            Adapter::Gcp(_) => "gcp-secret-manager",
        }
    }

    pub fn category(&self) -> Category {
        match self {
            Adapter::NativeSecrets(_) | Adapter::Gcp(_) => Category::Value,
        }
    }

    /// Resolve an item by name. `Ok(None)` = not in this store (caller
    /// continues store_order). `Err` = configured store failed (caller
    /// aborts and propagates).
    pub async fn resolve(&self, name: &str) -> AdapterResult<Option<Vec<u8>>> {
        match self {
            Adapter::NativeSecrets(a) => Ok(a.resolve(name)),
            Adapter::Gcp(a) => a.resolve(name).await,
        }
    }

    /// List item names this store currently exposes. UI uses this for
    /// per-store browsers.
    pub async fn list(&self) -> AdapterResult<Vec<String>> {
        match self {
            Adapter::NativeSecrets(a) => Ok(a.list()),
            Adapter::Gcp(a) => a.list().await,
        }
    }

    /// Verify the adapter can reach its backend with current credentials.
    pub async fn health(&self) -> AdapterResult<()> {
        match self {
            Adapter::NativeSecrets(_) => Ok(()),
            Adapter::Gcp(a) => a.health().await,
        }
    }
}

/// Build an `Adapter` from a configured `Store` + the current vault view.
///
/// For stores that depend on a credential held in `native-secrets`
/// (e.g. GCP's SA JSON via `credentials_item`), this is where the bytes
/// get pulled out — so the adapter owns its credentials and the rest of
/// the system doesn't need to thread the view further.
pub fn build_adapter(
    store_id: &str,
    store: &Store,
    view: &VaultPlaintextView,
) -> AdapterResult<Adapter> {
    match store.kind.as_str() {
        "native-secrets" => Ok(Adapter::NativeSecrets(
            NativeSecretsAdapter::from_view(view),
        )),
        "gcp-secret-manager" => {
            let project_id = store
                .extra
                .get("project_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AdapterError::Config(format!(
                        "store '{}': gcp-secret-manager requires `project_id` (string)",
                        store_id
                    ))
                })?
                .to_string();
            let creds_item = store
                .extra
                .get("credentials_item")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AdapterError::Config(format!(
                        "store '{}': gcp-secret-manager requires `credentials_item` (string — name of the SA JSON in native-secrets)",
                        store_id
                    ))
                })?;
            let sa_json = view
                .native_secrets
                .get(creds_item)
                .ok_or_else(|| {
                    AdapterError::Config(format!(
                        "store '{}': credentials_item '{}' not found in native-secrets",
                        store_id, creds_item
                    ))
                })?
                .clone();
            Ok(Adapter::Gcp(GcpSecretManagerAdapter::new(project_id, sa_json)?))
        }
        // Future kinds (1password-sa, aws-secrets-manager) aren't wired through
        // this dispatcher yet — they live in store_order but are skipped during
        // value resolution.
        other => Err(AdapterError::Config(format!(
            "unsupported store kind '{}' (have: native-secrets, gcp-secret-manager)",
            other
        ))),
    }
}
