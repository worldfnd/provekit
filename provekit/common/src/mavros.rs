//! Mavros-specific types for the prover and compilation pipeline.
//!
//! This module is only available on native targets (not WASM) because the
//! Mavros VM and its artifacts depend on C bindings.

use {
    crate::{whir_r1cs::WhirR1CSScheme, HashConfig, R1CS},
    mavros_vm::{ConstraintsLayout, WitnessLayout},
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

/// Mavros-specific prover data serialized into `.pkp` files.
///
/// Unlike [`super::NoirProver`], the Mavros prover omits the R1CS matrices
/// (they are reconstructed at prove-time from the AD binary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavrosProver {
    #[serde(with = "crate::utils::serde_jsonify")]
    pub abi:                Abi,
    pub num_public_inputs:  usize,
    pub whir_for_witness:   WhirR1CSScheme,
    pub witgen_binary:      Vec<u64>,
    pub ad_binary:          Vec<u64>,
    pub constraints_layout: ConstraintsLayout,
    pub witness_layout:     WitnessLayout,
    pub hash_config:        HashConfig,
}

/// Mavros-specific compilation output (in-memory counterpart of
/// [`MavrosProver`]).
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
