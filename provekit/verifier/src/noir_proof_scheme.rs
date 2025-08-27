use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::Result,
    provekit_common::{NoirProof, NoirProofScheme},
    tracing::instrument,
};

pub trait NoirProofSchemeVerifier {
    fn verify(&self, proof: &NoirProof) -> Result<()>;
}

impl NoirProofSchemeVerifier for NoirProofScheme {
    #[instrument(skip_all)]
    fn verify(&self, proof: &NoirProof) -> Result<()> {
        self.whir_for_witness.verify(&proof.whir_r1cs_proof)?;
        Ok(())
    }
}
