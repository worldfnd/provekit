use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        NoirElement, R1CS,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

#[cfg(feature = "mavros_compiler")]
use mavros::compiled_artifacts::CompiledArtifacts;

/// A prover for a Noir Proof Scheme
#[cfg(not(feature = "mavros_compiler"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prover {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
}

#[cfg(feature = "mavros_compiler")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prover {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub whir_for_witness:       WhirR1CSScheme,
    pub artifacts:              CompiledArtifacts,
}

impl Prover {
    #[cfg(not(feature = "mavros_compiler"))]
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            program:                noir_proof_scheme.program,
            r1cs:                   noir_proof_scheme.r1cs,
            split_witness_builders: noir_proof_scheme.split_witness_builders,
            witness_generator:      noir_proof_scheme.witness_generator,
            whir_for_witness:       noir_proof_scheme.whir_for_witness,
        }
    }
    #[cfg(feature = "mavros_compiler")]
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            program:                noir_proof_scheme.program,
            r1cs:                   noir_proof_scheme.r1cs,
            whir_for_witness:       noir_proof_scheme.whir_for_witness,
            artifacts:              noir_proof_scheme.artifacts,
        }
    }

    #[cfg(not(feature = "mavros_compiler"))]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }

    #[cfg(feature = "mavros_compiler")]
    pub const fn size(&self) -> (usize, usize) {
        (self.artifacts.r1cs.constraints.len(), self.artifacts.r1cs.witness_layout.algebraic_size)
    }
}
