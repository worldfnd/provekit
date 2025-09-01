//! Application state management
//!
//! Contains the application state that is shared across all request handlers,
//! including configured services and other shared resources.

use {
    crate::{
        config::Config,
        services::{ArtifactService, VerificationService},
    },
    std::sync::Arc,
};

/// Shared application state
#[derive(Debug, Clone)]
pub struct AppState {
    /// Configuration
    pub config:               Config,
    /// Artifact management service
    pub artifact_service:     Arc<ArtifactService>,
    /// Verification service
    pub verification_service: Arc<VerificationService>,
}

impl AppState {
    /// Create new application state from configuration
    pub fn new(config: Config) -> Self {
        let artifact_service = Arc::new(ArtifactService::new(&config.artifacts.artifacts_dir));
        let verification_service = Arc::new(VerificationService::new(
            &config.verification.verifier_binary_path,
        ));

        Self {
            config,
            artifact_service,
            verification_service,
        }
    }
}
