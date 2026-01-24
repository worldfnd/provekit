mod whir_r1cs;

use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::Result,
    provekit_common::{NoirProof, Verifier, R1CS},
    tracing::instrument,
};

pub trait Verify {
    fn verify(&mut self, proof: &NoirProof, r1cs: &R1CS) -> Result<()>;
}

impl Verify for Verifier {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof, r1cs: &R1CS) -> Result<()> {
        self.whir_for_witness.take().unwrap().verify(
            &proof.whir_r1cs_proof,
            &proof.public_inputs,
            r1cs,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
