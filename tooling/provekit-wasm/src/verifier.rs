use {
    crate::{
        error::{ErrorCode, WasmError},
        format::{ensure_json_artifact_size, looks_like_json, parse_binary_verifier},
    },
    provekit_backend_bn254::{Bn254Field, ProvekitProof, Verifier as VerifierCore, Verify},
    wasm_bindgen::prelude::*,
};

/// WASM bindings for proof verification. Reusable across multiple proofs.
///
/// JavaScript owners must call the generated `free()` method exactly once when
/// the handle is no longer needed.
#[wasm_bindgen]
pub struct Verifier {
    inner: VerifierCore,
}

#[wasm_bindgen]
impl Verifier {
    /// Creates a new verifier from a `.pkv` verifier artifact.
    #[wasm_bindgen(constructor)]
    pub fn new(verifier_data: &[u8]) -> Result<Verifier, JsValue> {
        let inner = if looks_like_json(verifier_data) {
            ensure_json_artifact_size(verifier_data, "verifier")
                .map_err(WasmError::into_js_value)?;
            serde_json::from_slice(verifier_data).map_err(|error| {
                WasmError::new(
                    ErrorCode::ArtifactJsonInvalid,
                    format!("Failed to parse verifier JSON: {error}"),
                )
                .into_js_value()
            })?
        } else {
            parse_binary_verifier(verifier_data).map_err(WasmError::into_js_value)?
        };
        Ok(Self { inner })
    }

    /// Verifies a proof provided as JSON bytes. The verifier is **not**
    /// consumed.
    #[wasm_bindgen(js_name = verifyBytes)]
    pub fn verify_bytes(&self, proof_json: &[u8]) -> Result<bool, JsValue> {
        let proof: ProvekitProof<Bn254Field> =
            serde_json::from_slice(proof_json).map_err(|error| {
                WasmError::new(
                    ErrorCode::ProofMalformed,
                    format!("Failed to parse proof JSON: {error}"),
                )
                .into_js_value()
            })?;
        Ok(self.verify_proof(&proof))
    }

    /// Verifies a proof provided as a JavaScript object. The verifier is
    /// **not** consumed.
    #[wasm_bindgen(js_name = verifyJs)]
    pub fn verify_js(&self, proof: JsValue) -> Result<bool, JsValue> {
        let proof: ProvekitProof<Bn254Field> =
            serde_wasm_bindgen::from_value(proof).map_err(|error| {
                WasmError::new(
                    ErrorCode::ProofMalformed,
                    format!("Failed to parse proof: {error}"),
                )
                .into_js_value()
            })?;
        Ok(self.verify_proof(&proof))
    }
}

impl Verifier {
    fn verify_proof(&self, proof: &ProvekitProof<Bn254Field>) -> bool {
        // Clone so the core verifier's .take() consumption doesn't prevent reuse.
        let mut verifier = self.inner.clone();
        verifier.verify(proof).is_ok()
    }
}
