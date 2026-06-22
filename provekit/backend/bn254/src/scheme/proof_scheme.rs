use {
    crate::{
        witness::SplitWitnessBuilders, Bn254Field, MavrosSchemeData, NoirElement,
        NoirWitnessGenerator,
    },
    acir::circuit::Program,
    provekit_common::{HashConfig, WhirR1CSScheme, R1CS},
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirSchemeData {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme<Bn254Field>,
    pub hash_config:            HashConfig,
}

// INVARIANT: Variant order is wire-format-critical (postcard uses positional
// discriminants). Do not reorder, cfg-gate, or insert variants without
// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoirProofScheme {
    Noir(NoirSchemeData),
    Mavros(MavrosSchemeData),
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
    pub fn whir_for_witness(&self) -> &WhirR1CSScheme<Bn254Field> {
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

    #[must_use]
    pub fn abi(&self) -> &noirc_abi::Abi {
        match self {
            NoirProofScheme::Noir(d) => d.witness_generator.abi(),
            NoirProofScheme::Mavros(d) => &d.abi,
        }
    }
}
