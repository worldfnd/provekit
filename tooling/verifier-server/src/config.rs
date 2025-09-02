//! Configuration management for the verifier server
//!
//! Handles loading configuration from environment variables and
//! providing sensible defaults for all server settings.

use std::{env, path::PathBuf, time::Duration};

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Server configuration
    pub server:       ServerConfig,
    /// Verification configuration
    pub verification: VerificationConfig,
    /// Artifact management configuration
    pub artifacts:    ArtifactConfig,
}

/// HTTP server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host to bind to
    pub host:             String,
    /// Port to bind to
    pub port:             u16,
    /// Maximum request body size in bytes
    pub max_request_size: usize,
    /// Request timeout duration
    pub request_timeout:  Duration,
}

/// Verification-specific configuration
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Path to the external verifier binary
    pub verifier_binary_path:          String,
    /// Default maximum verification time in seconds
    pub default_max_verification_time: u64,
    /// Timeout for external verifier binary execution in seconds
    pub verifier_timeout_seconds:      u64,
}

/// Artifact management configuration
#[derive(Debug, Clone)]
pub struct ArtifactConfig {
    /// Base directory for storing artifacts
    pub artifacts_dir: PathBuf,
}

impl Config {
    /// Load configuration from environment variables with fallbacks to defaults
    pub fn from_env() -> Self {
        Self {
            server:       ServerConfig::from_env(),
            verification: VerificationConfig::from_env(),
            artifacts:    ArtifactConfig::from_env(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server:       ServerConfig::default(),
            verification: VerificationConfig::default(),
            artifacts:    ArtifactConfig::default(),
        }
    }
}

impl ServerConfig {
    fn from_env() -> Self {
        Self {
            host:             env::var("VERIFIER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port:             env::var("VERIFIER_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            max_request_size: env::var("VERIFIER_MAX_REQUEST_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10 * 1024 * 1024), // 10MB
            request_timeout:  Duration::from_secs(
                env::var("VERIFIER_REQUEST_TIMEOUT")
                    .ok()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(600), // 10 minutes
            ),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host:             "0.0.0.0".to_string(),
            port:             3000,
            max_request_size: 10 * 1024 * 1024,         // 10MB
            request_timeout:  Duration::from_secs(600), // 10 minutes
        }
    }
}

impl VerificationConfig {
    fn from_env() -> Self {
        Self {
            verifier_binary_path:          env::var("VERIFIER_BINARY_PATH")
                .unwrap_or_else(|_| "./verifier".to_string()),
            default_max_verification_time: env::var("VERIFIER_DEFAULT_MAX_TIME")
                .ok()
                .and_then(|t| t.parse().ok())
                .unwrap_or(300), // 5 minutes
            verifier_timeout_seconds:      env::var("VERIFIER_TIMEOUT_SECONDS")
                .ok()
                .and_then(|t| t.parse().ok())
                .unwrap_or(600), // 10 minutes
        }
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            verifier_binary_path:          "./verifier".to_string(),
            default_max_verification_time: 300, // 5 minutes
            verifier_timeout_seconds:      600, // 10 minutes
        }
    }
}

impl ArtifactConfig {
    fn from_env() -> Self {
        Self {
            artifacts_dir: env::var("VERIFIER_ARTIFACTS_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./artifacts")),
        }
    }
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            artifacts_dir: PathBuf::from("./artifacts"),
        }
    }
}
