use {
    provekit_common::NoirProof,
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
    tracing::info,
};

/// Request payload for proof verification
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyRequest {
    /// URL to the Noir Proof Scheme file (.nps)
    #[serde(rename = "npsUrl")]
    pub nps_url:             String,
    /// JSON encoded NoirProof (.np file content)
    pub np:                  serde_json::Value,
    /// URL to the R1CS file
    #[serde(rename = "r1csUrl")]
    pub r1cs_url:            String,
    /// URL to the proving key file
    #[serde(rename = "pkUrl")]
    pub pk_url:              Option<String>,
    /// URL to the verification key file
    #[serde(rename = "vkUrl")]
    pub vk_url:              Option<String>,
    /// Optional verification parameters
    #[serde(rename = "verificationParams")]
    pub verification_params: Option<VerificationParams>,
    /// Request metadata
    #[serde(default)]
    pub metadata:            Option<RequestMetadata>,
}

/// Verification parameters
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct VerificationParams {
    /// Maximum verification time in seconds
    #[serde(rename = "maxVerificationTime")]
    pub max_verification_time: u64,
    /// Additional verification options
    #[serde(default)]
    pub options:               HashMap<String, serde_json::Value>,
}

/// Request metadata
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RequestMetadata {
    /// Client identifier
    #[serde(rename = "clientId")]
    pub client_id:     Option<String>,
    /// Request timestamp (ISO 8601)
    pub timestamp:     Option<String>,
    /// Request ID for tracking
    #[serde(rename = "requestId")]
    pub request_id:    Option<String>,
    /// Additional custom fields
    #[serde(default)]
    #[serde(rename = "customFields")]
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Response payload for proof verification
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyResponse {
    /// Whether the proof is valid
    #[serde(rename = "isValid")]
    pub is_valid: bool,
    /// Verification result details
    pub result:   VerificationResult,
    /// Response metadata
    pub metadata: ResponseMetadata,
}

/// Detailed verification result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationResult {
    /// Verification status
    pub status:               VerificationStatus,
    /// Error message if verification failed
    #[serde(rename = "errorMessage")]
    pub error_message:        Option<String>,
    /// Verification time in milliseconds
    #[serde(rename = "verificationTimeMs")]
    pub verification_time_ms: u64,
    /// Additional result data
    #[serde(default)]
    pub details:              HashMap<String, serde_json::Value>,
}

/// Verification status enum
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Proof is valid
    Valid,
    /// Proof is invalid
    Invalid,
    /// Verification failed due to error
    Error,
    /// Verification timed out
    Timeout,
}

/// Response metadata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseMetadata {
    /// Server version
    #[serde(rename = "serverVersion")]
    pub server_version:     String,
    /// Response timestamp (ISO 8601)
    pub timestamp:          String,
    /// Request ID (if provided)
    #[serde(rename = "requestId")]
    pub request_id:         Option<String>,
    /// Processing time in milliseconds
    #[serde(rename = "processingTimeMs")]
    pub processing_time_ms: u64,
}

impl VerifyRequest {
    /// Validate the request data
    pub fn validate(&self) -> Result<(), String> {
        info!("Validating request");

        // Validate URLs
        if self.nps_url.is_empty() {
            return Err("nps_url cannot be empty".to_string());
        }

        if self.r1cs_url.is_empty() {
            return Err("r1cs_url cannot be empty".to_string());
        }

        // pk_url and vk_url are optional - if not provided, gnark-verifier will generate them

        // Validate URLs are properly formatted
        self.validate_url("nps_url", &self.nps_url)?;
        self.validate_url("r1cs_url", &self.r1cs_url)?;
        
        if let Some(ref pk_url) = self.pk_url {
            self.validate_url("pk_url", pk_url)?;
        }
        if let Some(ref vk_url) = self.vk_url {
            self.validate_url("vk_url", vk_url)?;
        }

        // Validate np (JSON NoirProof) - basic check for null
        if self.np.is_null() {
            return Err("np (NoirProof) cannot be null".to_string());
        }

        // Validate verification params if present
        if let Some(ref params) = self.verification_params {
            if params.max_verification_time == 0 {
                return Err("Max verification time must be greater than 0".to_string());
            }

            if params.max_verification_time > 300 {
                return Err("Max verification time cannot exceed 300 seconds".to_string());
            }
        }

        Ok(())
    }

    /// Decode the NoirProof from the JSON np field
    pub fn decode_noir_proof(&self) -> anyhow::Result<NoirProof> {
        serde_json::from_value(self.np.clone()).map_err(Into::into)
    }

    /// Validate that a URL is properly formatted
    fn validate_url(&self, field_name: &str, url: &str) -> Result<(), String> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!("{} must be a valid HTTP/HTTPS URL", field_name));
        }
        Ok(())
    }
}

impl VerifyResponse {
    /// Create a successful verification response
    pub fn success(verification_time_ms: u64, request_id: Option<String>) -> Self {
        Self {
            is_valid: true,
            result:   VerificationResult {
                status: VerificationStatus::Valid,
                error_message: None,
                verification_time_ms,
                details: HashMap::new(),
            },
            metadata: ResponseMetadata {
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id,
                processing_time_ms: verification_time_ms,
            },
        }
    }

    /// Create a failed verification response
    pub fn failure(
        status: VerificationStatus,
        error_message: Option<String>,
        verification_time_ms: u64,
        request_id: Option<String>,
    ) -> Self {
        Self {
            is_valid: false,
            result:   VerificationResult {
                status,
                error_message,
                verification_time_ms,
                details: HashMap::new(),
            },
            metadata: ResponseMetadata {
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id,
                processing_time_ms: verification_time_ms,
            },
        }
    }
}
