use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        R1CS,
    },
    serde::{Deserialize, Serialize},
    spartan_vm::compiled_artifacts::CompiledArtifacts,
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub whir_for_witness: WhirR1CSScheme,
    pub artifacts:        CompiledArtifacts,
    /// R1CS in the format expected by the recursive verifier (Go/gnark)
    pub r1cs:             R1CS,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.artifacts.r1cs.constraints.len(), self.artifacts.r1cs.witness_layout.algebraic_size)
    }
}
