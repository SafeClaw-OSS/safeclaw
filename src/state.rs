//! Top-level application state.

use std::sync::Mutex;

use crate::approval::ApprovalStore;
use crate::config::Config;
use crate::passkey::challenge::ChallengeStore;
use crate::service::ServiceRegistry;
use crate::storage::TenantDir;

pub struct AppState {
    pub config: Config,
    pub tenants: TenantDir,
    pub challenges: Mutex<ChallengeStore>,
    pub approvals: Mutex<ApprovalStore>,
    pub services: ServiceRegistry,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let tenants = TenantDir::new(&config.state_dir);
        Self {
            config,
            tenants,
            challenges: Mutex::new(ChallengeStore::new()),
            approvals: Mutex::new(ApprovalStore::new()),
            services: ServiceRegistry::load(),
        }
    }
}
