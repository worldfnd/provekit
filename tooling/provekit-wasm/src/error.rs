use wasm_bindgen::JsValue;

/// Stable machine-readable error codes exposed on JavaScript exceptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ErrorCode {
    ArtifactTooLarge,
    ArtifactTooShort,
    ArtifactInvalidMagic,
    ArtifactInvalidFormat,
    ArtifactIncompatibleVersion,
    ArtifactUnknownCompression,
    ArtifactDecompressionFailed,
    ArtifactDecompressedTooLarge,
    ArtifactDeserializationFailed,
    ArtifactJsonInvalid,
    WitnessInvalid,
    ProverConsumed,
    ProvingFailed,
    ProofSerializationFailed,
    ProofMalformed,
    UnsupportedProver,
}

impl ErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactTooLarge => "ARTIFACT_TOO_LARGE",
            Self::ArtifactTooShort => "ARTIFACT_TOO_SHORT",
            Self::ArtifactInvalidMagic => "ARTIFACT_INVALID_MAGIC",
            Self::ArtifactInvalidFormat => "ARTIFACT_INVALID_FORMAT",
            Self::ArtifactIncompatibleVersion => "ARTIFACT_INCOMPATIBLE_VERSION",
            Self::ArtifactUnknownCompression => "ARTIFACT_UNKNOWN_COMPRESSION",
            Self::ArtifactDecompressionFailed => "ARTIFACT_DECOMPRESSION_FAILED",
            Self::ArtifactDecompressedTooLarge => "ARTIFACT_DECOMPRESSED_TOO_LARGE",
            Self::ArtifactDeserializationFailed => "ARTIFACT_DESERIALIZATION_FAILED",
            Self::ArtifactJsonInvalid => "ARTIFACT_JSON_INVALID",
            Self::WitnessInvalid => "WITNESS_INVALID",
            Self::ProverConsumed => "PROVER_CONSUMED",
            Self::ProvingFailed => "PROVING_FAILED",
            Self::ProofSerializationFailed => "PROOF_SERIALIZATION_FAILED",
            Self::ProofMalformed => "PROOF_MALFORMED",
            Self::UnsupportedProver => "UNSUPPORTED_PROVER",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct WasmError {
    code:    ErrorCode,
    message: String,
}

impl WasmError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn code(&self) -> ErrorCode {
        self.code
    }

    #[cfg(test)]
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn into_js_value(self) -> JsValue {
        let error = js_sys::Error::new(&self.message);
        error.set_name("ProveKitError");
        let _ = js_sys::Reflect::set(
            error.as_ref(),
            &JsValue::from_str("code"),
            &JsValue::from_str(self.code.as_str()),
        );
        error.into()
    }
}

impl From<WasmError> for JsValue {
    fn from(error: WasmError) -> Self {
        error.into_js_value()
    }
}

pub(crate) type WasmResult<T> = Result<T, WasmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable_strings() {
        assert_eq!(
            ErrorCode::ArtifactInvalidMagic.as_str(),
            "ARTIFACT_INVALID_MAGIC"
        );
        assert_eq!(ErrorCode::ProofMalformed.as_str(), "PROOF_MALFORMED");
        assert_eq!(ErrorCode::WitnessInvalid.as_str(), "WITNESS_INVALID");
    }
}
