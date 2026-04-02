#[cfg(target_arch = "wasm32")]
pub use self::wasm_stubs::{ConstraintsLayout, WitnessLayout};
#[cfg(not(target_arch = "wasm32"))]
pub use mavros_vm::{ConstraintsLayout, WitnessLayout};
use {
    crate::{whir_r1cs::WhirR1CSScheme, HashConfig, R1CS},
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

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

// Wire-compatible stubs for WASM targets where mavros_vm (C bindings) is
// unavailable. Field names, types, and ordering MUST match the real mavros_vm
// types exactly.
#[cfg(target_arch = "wasm32")]
mod wasm_stubs {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct WitnessLayout {
        pub algebraic_size:      usize,
        pub multiplicities_size: usize,
        pub challenges_size:     usize,
        pub tables_data_size:    usize,
        pub lookups_data_size:   usize,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct ConstraintsLayout {
        pub algebraic_size:    usize,
        pub tables_data_size:  usize,
        pub lookups_data_size: usize,
    }
}
