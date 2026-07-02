mod whir_r1cs;

use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::Result,
    provekit_common::{NoirProof, Verifier},
    tracing::instrument,
};

pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

impl Verify for Verifier {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        provekit_common::register_ntt();

        match self.whir_for_witness.take() {
            Some(whir) => {
                whir.verify(&proof.whir_r1cs_proof, &proof.public_inputs, &self.r1cs)?;
                Ok(())
            }
            // `None` at rest marks a Zinc+ verifier (WHIR verifiers are
            // always serialized with `Some`; see `Verifier`'s docs). The
            // Zinc+ proof bytes ride in `narg_string`.
            #[cfg(not(target_arch = "wasm32"))]
            None => {
                anyhow::ensure!(
                    proof.whir_r1cs_proof.hints.is_empty(),
                    "Malformed Zinc+ proof: unexpected hints"
                );
                provekit_zinc_backend::zinc_verify(
                    &self.r1cs,
                    &proof.public_inputs.0,
                    &proof.whir_r1cs_proof.narg_string,
                )
            }
            #[cfg(target_arch = "wasm32")]
            None => anyhow::bail!("Zinc+ verification is not supported on WASM"),
        }
    }
}
