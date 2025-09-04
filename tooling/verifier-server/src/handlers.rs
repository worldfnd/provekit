use {
    crate::{
        error::{AppError, AppResult},
        models::{VerificationStatus, VerifyRequest, VerifyResponse},
        state::AppState,
    },
    axum::{
        extract::{Json, State},
        response::Json as ResponseJson,
    },
    std::time::Instant,
    tokio::sync::OwnedSemaphorePermit,
    tracing::{info, warn},
};

/// Handle proof verification requests
pub async fn verify_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> AppResult<ResponseJson<VerifyResponse>> {
    let start_time = Instant::now();
    let request_id = payload.metadata.as_ref().and_then(|m| m.request_id.clone());

    info!(
        request_id = %request_id.as_deref().unwrap_or("unknown"),
        nps_url = %payload.nps_url,
        r1cs_url = %payload.r1cs_url,
        pk_url = %payload.pk_url.as_deref().unwrap_or("not provided"),
        vk_url = %payload.vk_url.as_deref().unwrap_or("not provided"),
        "Received verification request"
    );

    // Acquire the semaphore permit (waits until available).
    // Using acquire_owned ensures the permit is released when dropped even if the
    // handler is cancelled.
    let permit: OwnedSemaphorePermit = state
        .verification_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| {
        // semaphore closed/unusable (very unlikely), map to internal error
        AppError::Internal("verification semaphore closed".into())
    })?;

    // From here on we hold the permit until we intentionally drop it (or handler is
    // dropped). If the client disconnects and the handler is cancelled, the
    // permit will be dropped automatically, allowing the next queued request to
    // proceed.

    // Validate the request
    if let Err(validation_error) = payload.validate() {
        warn!("Request validation failed: {}", validation_error);
        let response = VerifyResponse::failure(
            VerificationStatus::Error,
            Some(validation_error),
            start_time.elapsed().as_millis() as u64,
            request_id,
        );
        drop(permit);
        return Ok(ResponseJson(response));
    }

    // Perform the actual verification
    match verification(&state, &payload).await {
        Ok(verification_time_ms) => {
            let total_time = start_time.elapsed().as_millis() as u64;
            info!(
                verification_time_ms = verification_time_ms,
                total_time_ms = total_time,
                "Verification completed successfully"
            );

            // mark done; permit will be released when dropped at end of scope
            drop(permit);

            let response = VerifyResponse::success(verification_time_ms, request_id);
            Ok(ResponseJson(response))
        }
        Err(error) => {
            let total_time = start_time.elapsed().as_millis() as u64;
            warn!(
                error = %error,
                total_time_ms = total_time,
                "Verification failed"
            );

            // release permit before returning
            drop(permit);

            // For verification failures (proof is invalid), return HTTP 200 with failure
            // status For actual errors (404s, network failures, etc.),
            // propagate the error to return proper HTTP status codes
            match error {
                AppError::VerificationFailed(msg) => {
                    let response = VerifyResponse::failure(
                        VerificationStatus::Invalid,
                        Some(msg),
                        total_time,
                        request_id,
                    );
                    Ok(ResponseJson(response))
                }
                AppError::Timeout => {
                    let response = VerifyResponse::failure(
                        VerificationStatus::Timeout,
                        Some("Verification timeout".to_string()),
                        total_time,
                        request_id,
                    );
                    Ok(ResponseJson(response))
                }
                // For all other errors (InvalidInput, Internal, etc.), propagate them
                // This will cause Axum to use the IntoResponse implementation and return proper
                // HTTP status codes
                _ => Err(error),
            }
        }
    }
}

/// Perform the proof verification using services
async fn verification(state: &AppState, request: &VerifyRequest) -> AppResult<u64> {
    // Decode and validate the NoirProof
    let proof = request
        .decode_noir_proof()
        .map_err(|e| AppError::InvalidInput(e.to_string()))?;

    info!("Successfully decoded NoirProof from request");

    // Download and prepare artifacts
    let (scheme, paths) = state
        .artifact_service
        .prepare_artifacts(
            &request.nps_url,
            &request.r1cs_url,
            request.pk_url.as_deref(),
            request.vk_url.as_deref(),
        )
        .await?;

    // Perform verification
    state
        .verification_service
        .verify_proof(request, &proof, &scheme, &paths)
        .await
}
