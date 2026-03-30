use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, MavrosProver, NoirElement, R1CS,
    },
    acir::circuit::Program,
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProver {
    pub hash_config:            HashConfig,
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
}

// INVARIANT: Variant order is wire-format-critical (postcard uses positional
// discriminants). Do not reorder, cfg-gate, or insert variants without
// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Prover {
    Noir(NoirProver),
    Mavros(MavrosProver),
}

impl Prover {
    /// Convert a compilation output into the on-disk prover format.
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        match scheme {
            NoirProofScheme::Noir(d) => Prover::Noir(NoirProver {
                hash_config:            d.hash_config,
                program:                d.program,
                r1cs:                   d.r1cs,
                split_witness_builders: d.split_witness_builders,
                witness_generator:      d.witness_generator,
                whir_for_witness:       d.whir_for_witness,
            }),
            NoirProofScheme::Mavros(d) => Prover::Mavros(MavrosProver {
                abi:                d.abi,
                num_public_inputs:  d.num_public_inputs,
                whir_for_witness:   d.whir_for_witness,
                witgen_binary:      d.witgen_binary,
                ad_binary:          d.ad_binary,
                constraints_layout: d.constraints_layout,
                witness_layout:     d.witness_layout,
                hash_config:        d.hash_config,
            }),
        }
    }

    pub fn abi(&self) -> &Abi {
        match self {
            Prover::Noir(p) => p.witness_generator.abi(),
            Prover::Mavros(p) => &p.abi,
        }
    }

    pub fn size(&self) -> (usize, usize) {
        match self {
            Prover::Noir(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
            Prover::Mavros(p) => (
                p.constraints_layout.algebraic_size,
                p.witness_layout.algebraic_size,
            ),
        }
    }

    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            Prover::Noir(p) => &p.whir_for_witness,
            Prover::Mavros(p) => &p.whir_for_witness,
        }
    }
}
