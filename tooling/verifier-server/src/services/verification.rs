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
    provekit_common::{NoirProof, Verifier},
    provekit_gnark::write_gnark_parameters_to_file,
    std::time::Instant,
    tokio_util::sync::CancellationToken,
    tracing::{info, warn},
};

/// Service for performing proof verification
#[derive(Debug, Clone)]
pub struct VerificationService {
    /// Path to the external verifier binary
    verifier_binary_path:     String,
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
        verifier: &Verifier,
        paths: &ArtifactPaths,
        cancellation_token: CancellationToken,
    ) -> AppResult<u64> {
        let verification_start = Instant::now();

        // Prepare gnark parameters
        self.prepare_gnark_parameters(proof, verifier, paths)?;

        // Execute external verifier
        self.execute_verifier(paths, request, cancellation_token)
            .await?;

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
        verifier: &Verifier,
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

        let whir_scheme = verifier
            .whir_for_witness
            .as_ref()
            .ok_or_else(|| AppError::Internal("WHIR scheme not found in verifier".to_string()))?;

        write_gnark_parameters_to_file(
            &whir_scheme.whir_witness,
            &whir_scheme.whir_for_hiding_spartan,
            &proof.whir_r1cs_proof.transcript,
            &whir_scheme.create_io_pattern(),
            whir_scheme.m_0,
            whir_scheme.m,
            whir_scheme.a_num_terms,
            whir_scheme.num_challenges,
            gnark_params_path,
        );

        info!("Gnark parameters prepared successfully");
        Ok(())
    }

    /// Execute the external verifier binary
    async fn execute_verifier(
        &self,
        paths: &ArtifactPaths,
        _request: &VerifyRequest,
        cancellation_token: CancellationToken,
    ) -> AppResult<()> {
        info!(
            verifier_binary = %self.verifier_binary_path,
            config_path = %paths.gnark_params_file.display(),
            r1cs_path = %paths.r1cs_file.display(),
            "Executing external verifier binary"
        );

        let mut command = tokio::process::Command::new(&self.verifier_binary_path);
        command
            .arg("--config")
            .arg(&paths.gnark_params_file)
            .arg("--r1cs")
            .arg(&paths.r1cs_file);

        // Only add --pk/--vk args if the files exist
        if paths.pk_file.exists() {
            command.arg("--pk").arg(&paths.pk_file);
            info!(
                pk_path = %paths.pk_file.display(),
            );
        }

        if paths.vk_file.exists() {
            command.arg("--vk").arg(&paths.vk_file);
            info!(
                vk_path = %paths.vk_file.display(),
            );
        }

        // Add timeout to prevent hanging
        let timeout_duration = std::time::Duration::from_secs(self.verifier_timeout_seconds);
        info!(
            timeout_seconds = timeout_duration.as_secs(),
            "Starting verifier binary with cancellation support"
        );

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

        let child_id = child.id().unwrap_or(0);
        info!(pid = child_id, "Spawned verifier process with PID");

        // Get stdout and stderr handles for real-time logging
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Spawn cancellation-aware logging tasks
        let stdout_handle = tokio::spawn({
            let token = cancellation_token.clone();
            async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();

                tokio::select! {
                    _ = token.cancelled() => {
                        info!("Stdout logging task cancelled");
                        return;
                    }
                    _ = async {
                        while let Ok(Some(line)) = lines.next_line().await {
                            if !line.trim().is_empty() {
                                info!("{}", line);
                            }
                        }
                    } => {
                        info!("Stdout logging task completed");
                    }
                }
            }
        });

        let stderr_handle = tokio::spawn({
            let token = cancellation_token.clone();
            async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();

                tokio::select! {
                    _ = token.cancelled() => {
                        warn!("Stderr logging task cancelled");
                        return;
                    }
                    _ = async {
                        while let Ok(Some(line)) = lines.next_line().await {
                            if !line.trim().is_empty() {
                                warn!("{}", line);
                            }
                        }
                    } => {
                        info!("Stderr logging task completed");
                    }
                }
            }
        });

        // Wait for completion with cancellation and timeout support
        let status = tokio::select! {
            result = child.wait() => {
                info!(
                    pid = child_id,
                    "Verifier process completed normally"
                );
                result.map_err(|e| {
                    warn!(
                        error = %e,
                        pid = child_id,
                        "Failed to execute verifier binary"
                    );
                    AppError::Internal(format!(
                        "Failed to execute verifier binary '{}': {}",
                        self.verifier_binary_path, e
                    ))
                })?
            }
            _ = cancellation_token.cancelled() => {
                warn!(
                    pid = child_id,
                    "Verification cancelled, killing process"
                );

                // Kill the process directly
                if let Err(e) = child.kill().await {
                    warn!(
                        error = %e,
                        pid = child_id,
                        "Failed to kill verifier process"
                    );
                } else {
                    info!(
                        pid = child_id,
                        "Successfully killed verifier process"
                    );
                }

                return Err(AppError::Cancelled);
            }
            _ = tokio::time::sleep(timeout_duration) => {
                warn!(
                    pid = child_id,
                    timeout_seconds = timeout_duration.as_secs(),
                    "Verifier binary timed out, killing process"
                );

                // Kill the process directly
                if let Err(e) = child.kill().await {
                    warn!(
                        error = %e,
                        pid = child_id,
                        "Failed to kill verifier process"
                    );
                } else {
                    info!(
                        pid = child_id,
                        "Successfully killed verifier process"
                    );
                }

                return Err(AppError::Timeout);
            }
        };

        // Create a mock output for processing
        let output = std::process::Output {
            status,
            stdout: Vec::new(), // We already captured stdout via logging
            stderr: Vec::new(), // We already captured stderr via logging
        };

        // Wait for logging tasks to complete gracefully
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (stdout_result, stderr_result) = tokio::join!(stdout_handle, stderr_handle);
            if let Err(e) = stdout_result {
                warn!("Stdout logging task failed: {}", e);
            }
            if let Err(e) = stderr_result {
                warn!("Stderr logging task failed: {}", e);
            }
        })
        .await;

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
        Self::new("./verifier", 1200) // 20 minutes default timeout
    }
}
