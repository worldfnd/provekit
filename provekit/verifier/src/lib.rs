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

// Implement Verify for each concrete type we support
impl Verify
    for Verifier<
        provekit_common::skyscraper::SkyscraperMerkleConfig,
        provekit_common::skyscraper::SkyscraperPoW,
    >
{
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        self.whir_for_witness
            .take()
            .unwrap()
            .verify(&proof.whir_r1cs_proof)?;
        Ok(())
    }
}

impl Verify
    for Verifier<provekit_common::sha256::Sha256MerkleConfig, provekit_common::sha256::Sha256PoW>
{
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        self.whir_for_witness
            .take()
            .unwrap()
            .verify(&proof.whir_r1cs_proof)?;
        Ok(())
    }
}

impl Verify
    for Verifier<provekit_common::keccak::KeccakMerkleConfig, provekit_common::keccak::KeccakPoW>
{
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        self.whir_for_witness
            .take()
            .unwrap()
            .verify(&proof.whir_r1cs_proof)?;
        Ok(())
    }
}

impl Verify
    for Verifier<provekit_common::blake3::Blake3MerkleConfig, provekit_common::blake3::Blake3PoW>
{
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
