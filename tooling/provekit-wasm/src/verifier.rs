use {
    crate::format::parse_binary_verifier,
    provekit_common::{
        binary_format::{HEADER_SIZE, MAGIC_BYTES},
        NoirProof, Verifier as VerifierCore,
    },
    provekit_verifier::Verify,
    wasm_bindgen::prelude::*,
};

/// A verifier instance for verifying zero-knowledge proofs in WebAssembly.
///
/// Wraps the same `Verifier` artifact used by the native CLI. Create an
/// instance by loading a `.pkv` file.
#[wasm_bindgen]
pub struct Verifier {
    inner: VerifierCore,
}

#[wasm_bindgen]
impl Verifier {
    /// Creates a new verifier from a `.pkv` verifier artifact.
    ///
    /// Generate `.pkv` artifacts using:
    /// ```sh
    /// provekit-cli prepare circuit.json --pkp prover.pkp --pkv verifier.pkv
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(verifier_data: &[u8]) -> Result<Verifier, JsError> {
        let is_binary = verifier_data.len() >= HEADER_SIZE && &verifier_data[..8] == MAGIC_BYTES;

        let inner = if is_binary {
            parse_binary_verifier(verifier_data)?
        } else {
            serde_json::from_slice(verifier_data)
                .map_err(|err| JsError::new(&format!("Failed to parse verifier JSON: {err}")))?
        };
        Ok(Self { inner })
    }

    /// Verifies a proof provided as JSON bytes.
    #[wasm_bindgen(js_name = verifyBytes)]
    pub fn verify_bytes(&mut self, proof_json: &[u8]) -> Result<(), JsError> {
        let proof: NoirProof = serde_json::from_slice(proof_json)
            .map_err(|err| JsError::new(&format!("Failed to parse proof JSON: {err}")))?;
        self.inner
            .verify(&proof)
            .map_err(|err| JsError::new(&format!("{err:#}")))
    }

    /// Verifies a proof provided as a JavaScript object.
    #[wasm_bindgen(js_name = verifyJs)]
    pub fn verify_js(&mut self, proof: JsValue) -> Result<(), JsError> {
        let proof: NoirProof = serde_wasm_bindgen::from_value(proof)
            .map_err(|err| JsError::new(&format!("Failed to parse proof: {err}")))?;
        self.inner
            .verify(&proof)
            .map_err(|err| JsError::new(&format!("{err:#}")))
    }
}
