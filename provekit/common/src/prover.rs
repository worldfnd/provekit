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

/// A prover for a Noir Proof Scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prover {
    pub program:                  Program<NoirElement>,
    pub r1cs:                     R1CS,
    pub layered_witness_builders: LayeredWitnessBuilders,
    pub witness_generator:        NoirWitnessGenerator,
    pub whir_for_witness:         WhirR1CSScheme,
}

impl Prover {
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            program:                  noir_proof_scheme.program,
            r1cs:                     noir_proof_scheme.r1cs,
            layered_witness_builders: noir_proof_scheme.layered_witness_builders,
            witness_generator:        noir_proof_scheme.witness_generator,
            whir_for_witness:         noir_proof_scheme.whir_for_witness,
        }
    }

    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}
