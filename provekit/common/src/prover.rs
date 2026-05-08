//! Backend-specific prover types that don't introduce a `provekit_groth16`
//! dependency.
//!
//! `NoirProver` lives here because it's referenced by the WHIR pipeline that
//! is shared by everything in the workspace. The Groth16 prover and the
//! `Prover` enum live in `provekit_prover::prover_types` so they can hold a
//! typed `provekit_groth16::ProvingKey` without creating a dependency cycle
//! (`provekit_groth16` depends on this crate for `R1CS`).

use {
    crate::{
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, NoirElement, R1CS,
    },
    acir::circuit::Program,
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
