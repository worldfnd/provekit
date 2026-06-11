pub mod whir_r1cs;

// Guard against Cargo feature unification building this verifier over the wrong
// `provekit_common::FieldElement` (a sibling forcing `provekit-common/bn254`
// while this verifier is built for goldilocks).
provekit_common::assert_field_matches_common!();

#[cfg(feature = "bn254")]
use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::{Context, Result},
    provekit_common::{NoirProof, Verifier},
    tracing::instrument,
};

/// Verify a [`NoirProof`] against a Noir proof scheme's [`Verifier`].
#[cfg(feature = "bn254")]
pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

#[cfg(feature = "bn254")]
impl Verify for Verifier {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        provekit_common::register_ntt();

        self.whir_for_witness
            .take()
            .context("Verifier has already been consumed; cannot verify twice")?
            .verify(&proof.whir_r1cs_proof, &proof.public_inputs, &self.r1cs)?;

        Ok(())
    }
}
