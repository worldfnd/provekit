use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{LayeredWitnessBuilders, NoirWitnessGenerator},
        NoirElement, R1CS,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

/// A prover for a Noir Proof Scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prover {
    pub program:                  Option<Program<NoirElement>>,
    pub r1cs:                     Option<R1CS>,
    pub layered_witness_builders: Option<LayeredWitnessBuilders>,
    pub witness_generator:        Option<NoirWitnessGenerator>,
    pub whir_for_witness:         Option<WhirR1CSScheme>,
}

impl Prover {
    pub fn from_noir_proof_scheme(noir_proof_scheme: NoirProofScheme) -> Self {
        Self {
            program:                  Some(noir_proof_scheme.program),
            r1cs:                     Some(noir_proof_scheme.r1cs),
            layered_witness_builders: Some(noir_proof_scheme.layered_witness_builders),
            witness_generator:        Some(noir_proof_scheme.witness_generator),
            whir_for_witness:         Some(noir_proof_scheme.whir_for_witness),
        }
    }

    pub const fn size(&self) -> (usize, usize) {
        (
            self.r1cs.as_ref().unwrap().num_constraints(),
            self.r1cs.as_ref().unwrap().num_witnesses(),
        )
    }
}
