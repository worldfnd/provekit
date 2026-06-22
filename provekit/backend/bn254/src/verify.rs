use {
    crate::{NoirProof, Verifier},
    anyhow::{Context, Result},
    provekit_verifier::WhirR1CSVerifier,
    tracing::instrument,
};

pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

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
