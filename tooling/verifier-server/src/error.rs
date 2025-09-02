use {
    axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
        Json,
    },
    serde_json::json,
    std::fmt,
    tracing::error,
};

/// Application-specific error types
#[derive(Debug)]
pub enum AppError {
    /// Invalid input data
    InvalidInput(String),
    /// Verification failed
    VerificationFailed(String),
    /// Download failed (404, network issues, etc.)
    DownloadFailed(String),
    /// Internal server error
    Internal(String),
    /// Timeout occurred
    Timeout,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            AppError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            AppError::DownloadFailed(msg) => write!(f, "Download failed: {}", msg),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
            AppError::Timeout => write!(f, "Request timeout"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code) = match &self {
            AppError::InvalidInput(_) => {
                (StatusCode::BAD_REQUEST, self.to_string(), "INVALID_INPUT")
            }
            AppError::VerificationFailed(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                self.to_string(),
                "VERIFICATION_FAILED",
            ),
            AppError::DownloadFailed(_) => {
                (StatusCode::BAD_GATEWAY, self.to_string(), "DOWNLOAD_FAILED")
            }
            AppError::Internal(_) => {
                error!("Internal server error: {}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "INTERNAL_ERROR",
                )
            }
            AppError::Timeout => (StatusCode::REQUEST_TIMEOUT, self.to_string(), "TIMEOUT"),
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": error_message,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }
        }));

        (status, body).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::InvalidInput(format!("JSON parsing error: {}", err))
    }
}

/// Result type alias for application operations
pub type AppResult<T> = Result<T, AppError>;
