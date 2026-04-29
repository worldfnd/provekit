mod whir_r1cs;

use {
    crate::whir_r1cs::WhirR1CSVerifier,
    anyhow::{Context, Result},
    provekit_common::{NoirProof, Verifier},
    tracing::instrument,
};

use ark_bn254;

pub trait Verify {
    fn verify(&mut self, proof: &NoirProof) -> Result<()>;
}

impl Verify for Verifier {
    #[instrument(skip_all)]
    fn verify(&mut self, proof: &NoirProof) -> Result<()> {
        match proof {
            NoirProof::Whir { public_inputs, whir_r1cs_proof } => {
                anyhow::ensure!(
                    self.whir_for_witness.is_some(),
                    "proof/verifier backend mismatch: proof is WHIR but verifier was prepared for Groth16"
                );

                provekit_common::register_ntt();

                self.whir_for_witness
                    .take()
                    .context("Verifier has already been consumed; cannot verify twice")?
                    .verify(
                        whir_r1cs_proof,
                        public_inputs,
                        &self.r1cs,
                        self.hash_config,
                    )?;

                Ok(())
            }
            NoirProof::Groth16 { public_inputs, groth16_proof } => {
                use ark_serialize::CanonicalDeserialize;

                let vk_bytes = self.groth16_vk.as_ref()
                    .context("proof/verifier backend mismatch: proof is Groth16 but verifier was prepared for WHIR")?;

                tracing::debug!(
                    vk_bytes_len = vk_bytes.len(),
                    "deserializing Groth16 VK"
                );

                let mut vk: provekit_groth16::VerifyingKey =
                    CanonicalDeserialize::deserialize_uncompressed(&vk_bytes[..])
                        .context("while deserializing Groth16 verifying key")?;
                vk.precompute()?;

                tracing::debug!(
                    g1_k_len = vk.g1_k.len(),
                    commitment_keys_len = vk.commitment_keys.len(),
                    public_and_commitment_committed_len = vk.public_and_commitment_committed.len(),
                    "deserialized Groth16 VK"
                );

                let proof: provekit_groth16::Proof =
                    CanonicalDeserialize::deserialize_compressed(&groth16_proof[..])
                        .context("while deserializing Groth16 proof")?;

                tracing::debug!(
                    commitments_len = proof.commitments.len(),
                    public_witness_len = public_inputs.0.len(),
                    "deserialized Groth16 proof"
                );

                let public_witness: Vec<ark_bn254::Fr> = public_inputs.0.clone();

                provekit_groth16::verifier::verify(&proof, &vk, &public_witness)
                    .context("Groth16 verification failed")?;

                Ok(())
            }
        }
    }
}
