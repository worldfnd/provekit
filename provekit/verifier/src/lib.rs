mod whir_r1cs;

use {
    anyhow::Result,
    provekit_common::{hash::HashFunction, NoirProof, Verifier},
    tracing::instrument,
};

pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

impl Verify for Verifier {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        let scheme = self.whir_for_witness.take().unwrap();

        match scheme.hash_function {
            HashFunction::Skyscraper => {
                whir_r1cs::skyscraper_verifier::verify(&scheme, &proof.whir_r1cs_proof)
            }
            HashFunction::Sha2 => whir_r1cs::sha2_verifier::verify(&scheme, &proof.whir_r1cs_proof),
            HashFunction::Sha3 => whir_r1cs::sha3_verifier::verify(&scheme, &proof.whir_r1cs_proof),
            HashFunction::Blake3 => {
                whir_r1cs::blake3_verifier::verify(&scheme, &proof.whir_r1cs_proof)
            }
        }
    }
}

#[cfg(test)]
mod tests {}
