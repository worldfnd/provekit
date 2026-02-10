use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        NoirElement, PublicInputs, R1CS,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

#[cfg(feature = "mavros_compiler")]
use mavros::compiled_artifacts::CompiledArtifacts;

/// A scheme for proving a Noir program.
#[cfg(not(feature = "mavros_compiler"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
}

#[cfg(feature = "mavros_compiler")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub whir_for_witness:       WhirR1CSScheme,
    pub artifacts:              CompiledArtifacts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub public_inputs:   PublicInputs,
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}
