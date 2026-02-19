#[cfg(feature = "mavros_compiler")]
use {mavros_artifacts::{ConstraintsLayout, WitnessLayout}, noirc_abi::Abi};
use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        PublicInputs, R1CS,
    },
    serde::{Deserialize, Serialize},
};
#[cfg(not(feature = "mavros_compiler"))]
use {
    acir::circuit::Program,
    crate::{
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        NoirElement,
    },
};

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
    #[serde(with = "crate::utils::serde_jsonify")]
    pub abi:                Abi,
    pub num_public_inputs:  usize,
    pub r1cs:               R1CS,
    pub whir_for_witness:   WhirR1CSScheme,
    pub witgen_binary:      Vec<u64>,
    pub ad_binary:          Vec<u64>,
    pub constraints_layout:    ConstraintsLayout,
    pub witness_layout: WitnessLayout,
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
