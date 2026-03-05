use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, NoirElement, PublicInputs, R1CS,
    },
    acir::circuit::Program,
    mavros_vm::{ConstraintsLayout, WitnessLayout},
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirSchemeData {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
    pub hash_config:            HashConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavrosSchemeData {
    #[serde(with = "crate::utils::serde_jsonify")]
    pub abi:                Abi,
    pub num_public_inputs:  usize,
    pub r1cs:               R1CS,
    pub whir_for_witness:   WhirR1CSScheme,
    pub witgen_binary:      Vec<u64>,
    pub ad_binary:          Vec<u64>,
    pub constraints_layout: ConstraintsLayout,
    pub witness_layout:     WitnessLayout,
    pub hash_config:        HashConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoirProofScheme {
    Noir(NoirSchemeData),
    Mavros(MavrosSchemeData),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub public_inputs:   PublicInputs,
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[must_use]
    pub fn r1cs(&self) -> &R1CS {
        match self {
            NoirProofScheme::Noir(d) => &d.r1cs,
            NoirProofScheme::Mavros(d) => &d.r1cs,
        }
    }

    #[must_use]
    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            NoirProofScheme::Noir(d) => &d.whir_for_witness,
            NoirProofScheme::Mavros(d) => &d.whir_for_witness,
        }
    }

    #[must_use]
    pub fn size(&self) -> (usize, usize) {
        let r1cs = self.r1cs();
        (r1cs.num_constraints(), r1cs.num_witnesses())
    }
}
