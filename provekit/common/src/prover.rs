#[cfg(feature = "mavros_compiler")]
use {mavros_artifacts::{ConstraintsLayout, WitnessLayout}, noirc_abi::Abi};
use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
    },
    serde::{Deserialize, Serialize},
};
#[cfg(not(feature = "mavros_compiler"))]
use {
    acir::circuit::Program,
    crate::{
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        NoirElement, R1CS,
    },
};

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
    #[serde(with = "crate::utils::serde_jsonify")]
    pub abi:                Abi,
    pub num_public_inputs:  usize,
    pub whir_for_witness:   WhirR1CSScheme,
    pub witgen_binary:      Vec<u64>,
    pub ad_binary:          Vec<u64>,
    pub constraints_layout:   ConstraintsLayout,
    pub witness_layout: WitnessLayout,
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
            abi:                noir_proof_scheme.abi,
            num_public_inputs:  noir_proof_scheme.num_public_inputs,
            whir_for_witness:   noir_proof_scheme.whir_for_witness,
            witgen_binary:      noir_proof_scheme.witgen_binary,
            ad_binary:          noir_proof_scheme.ad_binary,
            constraints_layout:    noir_proof_scheme.constraints_layout,
            witness_layout: noir_proof_scheme.witness_layout,
        }
    }

    #[cfg(not(feature = "mavros_compiler"))]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }

    #[cfg(feature = "mavros_compiler")]
    pub const fn size(&self) -> (usize, usize) {
        (
            self.constraints_layout.algebraic_size,
            self.witness_layout.algebraic_size,
        )
    }
}
