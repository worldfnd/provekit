mod whir_r1cs;

use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::{Context, Result},
    provekit_common::ensure_field_backend_registered,
    provekit_noir::{NoirProof, Verifier},
    tracing::instrument,
};

/// Verify a proof.
///
/// The caller must register a field backend (e.g.
/// `provekit_field_bn254::register()`) before calling this. Verification does
/// not register one itself, but checks up front and returns a clear error
/// rather than panicking in a field-native hash path if none is registered.
pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

impl Verify for Verifier {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        // Surface a missing field backend as a clean error, not a deep panic.
        ensure_field_backend_registered()
            .context("cannot verify without a registered field backend")?;
        self.whir_for_witness
            .take()
            .context("Verifier has already been consumed; cannot verify twice")?
            .verify(&proof.whir_r1cs_proof, &proof.public_inputs, &self.r1cs)?;

        Ok(())
    }
}
