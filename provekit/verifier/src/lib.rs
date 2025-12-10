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
        self.whir_for_witness
            .take()
            .unwrap()
            .verify(&proof.whir_r1cs_proof, &proof.public_inputs)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
