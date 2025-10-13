//! Artifact management service
//!
//! Handles downloading and caching of verification artifacts including
//! PKV files, R1CS files, proving keys, and verification keys.

use {
    crate::error::{AppError, AppResult},
    provekit_common::Verifier,
    sha2::{Digest, Sha256},
    std::path::{Path, PathBuf},
    tracing::{info, instrument},
};

/// Service for managing verification artifacts
#[derive(Debug, Clone)]
pub struct ArtifactService {
    /// Base directory for storing artifacts
    artifacts_dir: PathBuf,
}

impl ArtifactService {
    /// Create a new artifact service
    pub fn new(artifacts_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifacts_dir: artifacts_dir.into(),
        }
    }

    /// Download and cache all required artifacts for verification
    #[instrument(skip(self))]
    pub async fn prepare_artifacts(
        &self,
        pkv_url: &str,
        r1cs_url: &str,
        pk_url: Option<&str>,
        vk_url: Option<&str>,
    ) -> AppResult<(Verifier, ArtifactPaths)> {
        let cache_dir = self.create_cache_directory(pkv_url).await?;
        let paths = ArtifactPaths::new(&cache_dir);

        info!(
            cache_dir = %cache_dir.display(),
            "Preparing artifacts in cache directory"
        );

        // Download all required artifacts
        self.download_artifacts_if_missing(&paths, pkv_url, r1cs_url, pk_url, vk_url)
            .await?;

        // Load and return the Verifier
        let verifier = self.load_verifier(&paths.pkv_file).await?;

        Ok((verifier, paths))
    }

    /// Create a cache directory based on the PKV URL hash
    async fn create_cache_directory(&self, pkv_url: &str) -> AppResult<PathBuf> {
        let mut hasher = Sha256::new();
        hasher.update(pkv_url.as_bytes());
        let url_hash = format!("{:x}", hasher.finalize());

        let cache_dir = self.artifacts_dir.join(&url_hash);

        tokio::fs::create_dir_all(&cache_dir)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create cache directory: {}", e)))?;

        info!(
            url_hash = %url_hash,
            cache_dir = %cache_dir.display(),
            "Created cache directory"
        );

        Ok(cache_dir)
    }

    /// Download artifacts that don't exist in the cache
    async fn download_artifacts_if_missing(
        &self,
        paths: &ArtifactPaths,
        pkv_url: &str,
        r1cs_url: &str,
        pk_url: Option<&str>,
        vk_url: Option<&str>,
    ) -> AppResult<()> {
        // Download required artifacts if not present
        let required_downloads = [
            (pkv_url, &paths.pkv_file, "ProveKit Verifier"),
            (r1cs_url, &paths.r1cs_file, "R1CS"),
        ];

        for (url, file_path, description) in required_downloads {
            if !file_path.exists() {
                info!(
                    url = %url,
                    file_path = %file_path.display(),
                    "Downloading {}", description
                );

                self.download_file(url, file_path).await.map_err(|e| {
                    AppError::DownloadFailed(format!("Failed to download {}: {}", description, e))
                })?;

                info!(
                    file_path = %file_path.display(),
                    "Successfully downloaded {}", description
                );
            } else {
                info!(
                    file_path = %file_path.display(),
                    "{} already exists in cache", description
                );
            }
        }

        // Download optional artifacts if URLs are provided
        let optional_downloads = [
            (pk_url, &paths.pk_file, "Proving Key"),
            (vk_url, &paths.vk_file, "Verification Key"),
        ];

        for (url_opt, file_path, description) in optional_downloads {
            if let Some(url) = url_opt {
                if !file_path.exists() {
                    info!(
                        url = %url,
                        file_path = %file_path.display(),
                        "Downloading {}", description
                    );

                    self.download_file(url, file_path).await.map_err(|e| {
                        AppError::DownloadFailed(format!(
                            "Failed to download {}: {}",
                            description, e
                        ))
                    })?;

                    info!(
                        file_path = %file_path.display(),
                        "Successfully downloaded {}", description
                    );
                } else {
                    info!(
                        file_path = %file_path.display(),
                        "{} already exists in cache", description
                    );
                }
            } else {
                info!(
                    file_path = %file_path.display(),
                    "Skipping {} download - URL not provided", description
                );
            }
        }

        Ok(())
    }

    /// Download a single file from URL to local path
    async fn download_file(
        &self,
        url: &str,
        file_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = reqwest::get(url).await?;

        if !response.status().is_success() {
            return Err(format!(
                "HTTP error {}: {}",
                response.status(),
                response.status().canonical_reason().unwrap_or("Unknown")
            )
            .into());
        }

        let bytes = response.bytes().await?;
        tokio::fs::write(file_path, bytes).await?;

        Ok(())
    }

    /// Load a Verifier from the PKV file
    async fn load_verifier(&self, pkv_file: &Path) -> AppResult<Verifier> {
        info!(
            pkv_file = %pkv_file.display(),
            "Loading Verifier"
        );

        let verifier = provekit_common::file::read(pkv_file)
            .map_err(|e| AppError::Internal(format!("Failed to load Verifier: {}", e)))?;

        info!("Successfully loaded Verifier");
        Ok(verifier)
    }
}

impl Default for ArtifactService {
    fn default() -> Self {
        Self::new("./artifacts")
    }
}

/// Paths to all required artifact files
#[derive(Debug, Clone)]
pub struct ArtifactPaths {
    pub pkv_file:          PathBuf,
    pub r1cs_file:         PathBuf,
    pub pk_file:           PathBuf,
    pub vk_file:           PathBuf,
    pub gnark_params_file: PathBuf,
}

impl ArtifactPaths {
    /// Create artifact paths for a given cache directory
    pub fn new(cache_dir: &Path) -> Self {
        Self {
            pkv_file:          cache_dir.join("verifier.pkv"),
            r1cs_file:         cache_dir.join("r1cs.json"),
            pk_file:           cache_dir.join("proving_key.bin"),
            vk_file:           cache_dir.join("verification_key.bin"),
            gnark_params_file: cache_dir.join("gnark_params"),
        }
    }
}
