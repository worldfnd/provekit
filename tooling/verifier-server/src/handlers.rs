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
    tracing::{info, instrument, warn},
};

/// Handle proof verification requests
#[instrument(
    skip(payload),
    fields(
        request_id = %payload.metadata.as_ref().and_then(|m| m.request_id.as_deref()).unwrap_or("unknown"),
        nps_url = %payload.nps_url,
        r1cs_url = %payload.r1cs_url,
        pk_url = %payload.pk_url,
        vk_url = %payload.vk_url
    )
)]
pub async fn verify_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> AppResult<ResponseJson<VerifyResponse>> {
    let start_time = Instant::now();
    let request_id = payload.metadata.as_ref().and_then(|m| m.request_id.clone());

    info!("Received verification request");

    // Validate the request
    if let Err(validation_error) = payload.validate() {
        warn!("Request validation failed: {}", validation_error);
        return Err(AppError::InvalidInput(validation_error));
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

            Ok(ResponseJson(VerifyResponse::success(
                verification_time_ms,
                request_id,
            )))
        }
        Err(error) => {
            let total_time = start_time.elapsed().as_millis() as u64;
            warn!(
                error = %error,
                total_time_ms = total_time,
                "Verification failed"
            );

            let (status, error_message) = match error {
                AppError::VerificationFailed(msg) => (VerificationStatus::Invalid, Some(msg)),
                AppError::Timeout => (
                    VerificationStatus::Timeout,
                    Some("Verification timeout".to_string()),
                ),
                _ => (VerificationStatus::Error, Some(error.to_string())),
            };

            Ok(ResponseJson(VerifyResponse::failure(
                status,
                error_message,
                total_time,
                request_id,
            )))
        }
    }
}

/// Perform the proof verification using services
#[instrument(skip(state, request))]
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
            &request.pk_url,
            &request.vk_url,
        )
        .await?;

    // Perform verification
    state
        .verification_service
        .verify_proof(request, &proof, &scheme, &paths)
        .await
}
