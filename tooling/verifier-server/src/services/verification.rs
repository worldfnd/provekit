//! Verification service
//!
//! Handles the core proof verification logic including preparation of
//! gnark parameters and execution of the external verifier binary.

use {
    crate::{
        error::{AppError, AppResult},
        models::VerifyRequest,
        services::artifact::ArtifactPaths,
    },
    provekit_common::{NoirProof, NoirProofScheme},
    provekit_gnark::write_gnark_parameters_to_file,
    std::time::Instant,
    tracing::{info, warn},
};

/// Service for performing proof verification
#[derive(Debug, Clone)]
pub struct VerificationService {
    /// Path to the external verifier binary
    verifier_binary_path: String,
    /// Timeout for verifier binary execution in seconds
    verifier_timeout_seconds: u64,
}

impl VerificationService {
    /// Create a new verification service
    pub fn new(verifier_binary_path: impl Into<String>, verifier_timeout_seconds: u64) -> Self {
        Self {
            verifier_binary_path: verifier_binary_path.into(),
            verifier_timeout_seconds,
        }
    }

    /// Perform complete proof verification
    pub async fn verify_proof(
        &self,
        request: &VerifyRequest,
        proof: &NoirProof,
        scheme: &NoirProofScheme,
        paths: &ArtifactPaths,
    ) -> AppResult<u64> {
        let verification_start = Instant::now();

        // Prepare gnark parameters
        self.prepare_gnark_parameters(proof, scheme, paths)?;

        // Execute external verifier
        self.execute_verifier(paths, request).await?;

        let verification_time = verification_start.elapsed().as_millis() as u64;

        // Check timeout if specified
        self.check_timeout(request, verification_time)?;

        info!(
            verification_time_ms = verification_time,
            "Proof verification completed successfully"
        );

        Ok(verification_time)
    }

    /// Prepare gnark parameters file for verification
    fn prepare_gnark_parameters(
        &self,
        proof: &NoirProof,
        scheme: &NoirProofScheme,
        paths: &ArtifactPaths,
    ) -> AppResult<()> {
        info!(
            gnark_params_file = %paths.gnark_params_file.display(),
            "Preparing gnark parameters"
        );

        let gnark_params_path = paths
            .gnark_params_file
            .to_str()
            .ok_or_else(|| AppError::Internal("Invalid gnark params path".to_string()))?;

        write_gnark_parameters_to_file(
            &scheme.whir_for_witness.whir_witness,
            &scheme.whir_for_witness.whir_for_hiding_spartan,
            &proof.whir_r1cs_proof.transcript,
            &scheme.whir_for_witness.create_io_pattern(),
            scheme.whir_for_witness.m_0,
            scheme.whir_for_witness.m,
            scheme.whir_for_witness.a_num_terms,
            gnark_params_path,
        );

        info!("Gnark parameters prepared successfully");
        Ok(())
    }

    /// Execute the external verifier binary
    async fn execute_verifier(
        &self,
        paths: &ArtifactPaths,
        request: &VerifyRequest,
    ) -> AppResult<()> {
        info!(
            verifier_binary = %self.verifier_binary_path,
            config_path = %paths.gnark_params_file.display(),
            r1cs_path = %paths.r1cs_file.display(),
            "Executing external verifier binary"
        );
        if paths.pk_file.exists() && request.pk_url.is_some() {
            info!(
                pk_path = %paths.pk_file.display(),
                vk_path = %paths.vk_file.display(),
            );
        }

        let mut command = tokio::process::Command::new(&self.verifier_binary_path);
        command
            .arg("--config")
            .arg(&paths.gnark_params_file)
            .arg("--r1cs")
            .arg(&paths.r1cs_file);

        // Only add pk/vk arguments if the URLs were provided in the request
        if request.pk_url.is_some() {
            command.arg("--pk").arg(&paths.pk_file);
        }
        if request.vk_url.is_some() {
            command.arg("--vk").arg(&paths.vk_file);
        }

        // Add timeout to prevent hanging
        let timeout_duration = std::time::Duration::from_secs(self.verifier_timeout_seconds);
        info!(
            timeout_seconds = timeout_duration.as_secs(),
            "Starting verifier binary with timeout"
        );
        
        // Spawn the process so we can kill it on timeout
        let mut child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                warn!(
                    error = %e,
                    "Failed to spawn verifier binary"
                );
                AppError::Internal(format!(
                    "Failed to spawn verifier binary '{}': {}",
                    self.verifier_binary_path, e
                ))
            })?;
        
        // Get stdout and stderr handles for real-time logging
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        
        // Spawn tasks to stream output in real-time
        let stdout_handle = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() {
                    info!("[VERIFIER STDOUT] {}", line);
                }
            }
        });
        
        let stderr_handle = tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() {
                    warn!("[VERIFIER STDERR] {}", line);
                }
            }
        });
        
        // Wait for completion with timeout
        let output = match tokio::time::timeout(timeout_duration, child.wait_with_output()).await {
            Ok(result) => result.map_err(|e| {
                warn!(
                    error = %e,
                    "Failed to execute verifier binary"
                );
                AppError::Internal(format!(
                    "Failed to execute verifier binary '{}': {}",
                    self.verifier_binary_path, e
                ))
            })?,
            Err(_) => {
                warn!("Verifier binary timed out after {} seconds, killing process", timeout_duration.as_secs());
                
                // Cancel the logging tasks gracefully
                stdout_handle.abort();
                stderr_handle.abort();
                
                return Err(AppError::Timeout);
            }
        };
        
        // Wait for logging tasks to complete (with timeout to prevent hanging)
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async { 
                let (stdout_result, stderr_result) = tokio::join!(stdout_handle, stderr_handle);
                if let Err(e) = stdout_result {
                    warn!("Stdout logging task failed: {}", e);
                }
                if let Err(e) = stderr_result {
                    warn!("Stderr logging task failed: {}", e);
                }
            }
        ).await;

        self.process_verifier_output(output)
    }

    /// Process the output from the verifier binary
    fn process_verifier_output(&self, output: std::process::Output) -> AppResult<()> {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            info!(
                exit_code = %output.status,
                stdout = %stdout,
                "Verifier binary completed successfully"
            );
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            warn!(
                exit_code = %output.status,
                stderr = %stderr,
                stdout = %stdout,
                "Verifier binary failed"
            );

            Err(AppError::VerificationFailed(format!(
                "Verification failed: {}",
                if !stderr.is_empty() {
                    stderr.as_ref()
                } else {
                    "Unknown error"
                }
            )))
        }
    }

    /// Check if verification exceeded the timeout limit
    fn check_timeout(&self, request: &VerifyRequest, verification_time_ms: u64) -> AppResult<()> {
        if let Some(ref params) = request.verification_params {
            let timeout_ms = params.max_verification_time * 1000;
            if verification_time_ms > timeout_ms {
                return Err(AppError::Timeout);
            }
        }
        Ok(())
    }
}

impl Default for VerificationService {
    fn default() -> Self {
        Self::new("./verifier", 600) // 10 minutes default timeout
    }
}
