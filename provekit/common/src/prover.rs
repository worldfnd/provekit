use {
    crate::{noir_proof_scheme::NoirProofScheme, whir_r1cs::WhirR1CSScheme, R1CS},
    serde::{Deserialize, Serialize},
    spartan_vm::CompiledArtifacts,
};

/// A prover for a Noir Proof Scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prover {
    pub whir_for_witness: WhirR1CSScheme,
    pub artifacts:        CompiledArtifacts,
    pub r1cs:             R1CS,
}

impl Prover {
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            whir_for_witness: noir_proof_scheme.whir_for_witness,
            artifacts:        noir_proof_scheme.artifacts,
            r1cs:             noir_proof_scheme.r1cs,
        }
    }

    pub const fn size(&self) -> (usize, usize) {
        (
            self.artifacts.r1cs.constraints.len(),
            self.artifacts.r1cs.witness_layout.algebraic_size,
        )
    }
}
