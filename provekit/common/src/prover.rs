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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prover {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
}

impl Prover {
    #[must_use]
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        let NoirProofScheme {
            program,
            r1cs,
            split_witness_builders,
            witness_generator,
            whir_for_witness,
        } = scheme;

        Self {
            program,
            r1cs,
            split_witness_builders,
            witness_generator,
            whir_for_witness,
        }
    }

    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}
