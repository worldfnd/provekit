mod whir_r1cs;

use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::Result,
    provekit_common::{hash::HashScheme, NoirProof, Verifier},
    tracing::instrument,
};

pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

impl<H: HashScheme> Verify for Verifier<H> {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        self.whir_for_witness
            .take()
            .unwrap()
            .verify(&proof.whir_r1cs_proof)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
