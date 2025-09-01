//! Artifact management service
//!
//! Handles downloading and caching of verification artifacts including
//! NPS files, R1CS files, proving keys, and verification keys.

use {
    crate::error::{AppError, AppResult},
    provekit_common::NoirProofScheme,
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
        nps_url: &str,
        r1cs_url: &str,
        pk_url: &str,
        vk_url: &str,
    ) -> AppResult<(NoirProofScheme, ArtifactPaths)> {
        let cache_dir = self.create_cache_directory(nps_url).await?;
        let paths = ArtifactPaths::new(&cache_dir);

        info!(
            cache_dir = %cache_dir.display(),
            "Preparing artifacts in cache directory"
        );

        // Download all required artifacts
        self.download_artifacts_if_missing(&paths, nps_url, r1cs_url, pk_url, vk_url)
            .await?;

        // Load and return the NoirProofScheme
        let scheme = self.load_noir_proof_scheme(&paths.nps_file).await?;

        Ok((scheme, paths))
    }

    /// Create a cache directory based on the NPS URL hash
    async fn create_cache_directory(&self, nps_url: &str) -> AppResult<PathBuf> {
        let mut hasher = Sha256::new();
        hasher.update(nps_url.as_bytes());
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
        nps_url: &str,
        r1cs_url: &str,
        pk_url: &str,
        vk_url: &str,
    ) -> AppResult<()> {
        let downloads = [
            (nps_url, &paths.nps_file, "Noir Proof Scheme"),
            (r1cs_url, &paths.r1cs_file, "R1CS"),
            (pk_url, &paths.pk_file, "Proving Key"),
            (vk_url, &paths.vk_file, "Verification Key"),
        ];

        for (url, file_path, description) in downloads {
            if !file_path.exists() {
                info!(
                    url = %url,
                    file_path = %file_path.display(),
                    "Downloading {}", description
                );

                self.download_file(url, file_path).await.map_err(|e| {
                    AppError::Internal(format!("Failed to download {}: {}", description, e))
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

    /// Load a NoirProofScheme from the NPS file
    async fn load_noir_proof_scheme(&self, nps_file: &Path) -> AppResult<NoirProofScheme> {
        info!(
            nps_file = %nps_file.display(),
            "Loading NoirProofScheme"
        );

        let scheme = provekit_common::file::read(nps_file)
            .map_err(|e| AppError::Internal(format!("Failed to load NoirProofScheme: {}", e)))?;

        info!("Successfully loaded NoirProofScheme");
        Ok(scheme)
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
    pub nps_file:          PathBuf,
    pub r1cs_file:         PathBuf,
    pub pk_file:           PathBuf,
    pub vk_file:           PathBuf,
    pub gnark_params_file: PathBuf,
}

impl ArtifactPaths {
    /// Create artifact paths for a given cache directory
    pub fn new(cache_dir: &Path) -> Self {
        Self {
            nps_file:          cache_dir.join("scheme.nps"),
            r1cs_file:         cache_dir.join("r1cs.json"),
            pk_file:           cache_dir.join("proving_key.bin"),
            vk_file:           cache_dir.join("verification_key.bin"),
            gnark_params_file: cache_dir.join("gnark_params"),
        }
    }
}
