#[cfg(target_arch = "wasm32")]
pub use self::wasm_stubs::{ConstraintsLayout, WitnessLayout};
#[cfg(not(target_arch = "wasm32"))]
pub use mavros_vm::{ConstraintsLayout, WitnessLayout};
use {
    crate::{whir_r1cs::WhirR1CSScheme, HashConfig, R1CS},
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

/// Serialized prover data for Mavros-backed circuits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavrosProver {
    /// Noir ABI for user-facing input encoding.
    #[serde(with = "crate::utils::serde_jsonify")]
    pub abi:                Abi,
    /// Number of public inputs expected by the circuit.
    pub num_public_inputs:  usize,
    /// WHIR scheme used for the committed witness proof.
    pub whir_for_witness:   WhirR1CSScheme,
    /// Mavros witness-generation program.
    pub witgen_binary:      Vec<u64>,
    /// Mavros automatic-differentiation program.
    pub ad_binary:          Vec<u64>,
    /// Layout of Mavros constraint buffers.
    pub constraints_layout: ConstraintsLayout,
    /// Layout of Mavros witness buffers.
    pub witness_layout:     WitnessLayout,
    /// Hash configuration for WHIR and public input binding.
    pub hash_config:        HashConfig,
}

/// Full scheme data for a Mavros-backed circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavrosSchemeData {
    /// Noir ABI for user-facing input encoding.
    #[serde(with = "crate::utils::serde_jsonify")]
    pub abi:                Abi,
    /// Number of public inputs expected by the circuit.
    pub num_public_inputs:  usize,
    /// R1CS representation used for verification and tooling.
    pub r1cs:               R1CS,
    /// WHIR scheme used for the committed witness proof.
    pub whir_for_witness:   WhirR1CSScheme,
    /// Mavros witness-generation program.
    pub witgen_binary:      Vec<u64>,
    /// Mavros automatic-differentiation program.
    pub ad_binary:          Vec<u64>,
    /// Layout of Mavros constraint buffers.
    pub constraints_layout: ConstraintsLayout,
    /// Layout of Mavros witness buffers.
    pub witness_layout:     WitnessLayout,
    /// Hash configuration for WHIR and public input binding.
    pub hash_config:        HashConfig,
}

// Wire-compatible stubs for WASM targets where mavros_vm (C bindings) is
// unavailable. Field names, types, and ordering MUST match the real mavros_vm
// types exactly.
#[cfg(target_arch = "wasm32")]
mod wasm_stubs {
    use serde::{Deserialize, Serialize};

    /// WASM-side mirror of `mavros_artifacts::WitnessLayout`.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct WitnessLayout {
        /// Number of algebraic witness slots.
        pub algebraic_size:      usize,
        /// Number of lookup multiplicity witness slots.
        pub multiplicities_size: usize,
        /// Number of Fiat-Shamir challenge slots.
        pub challenges_size:     usize,
        /// Number of lookup table metadata slots.
        pub tables_data_size:    usize,
        /// Number of lookup witness data slots.
        pub lookups_data_size:   usize,
    }

    impl WitnessLayout {
        /// Return the total number of Mavros witness values.
        pub const fn size(&self) -> usize {
            self.algebraic_size
                + self.multiplicities_size
                + self.challenges_size
                + self.tables_data_size
                + self.lookups_data_size
        }

        /// Return the number of witness values committed before challenges.
        pub const fn pre_commitment_size(&self) -> usize {
            self.algebraic_size + self.multiplicities_size
        }

        /// Return the number of witness values computed after challenges.
        pub const fn post_commitment_size(&self) -> usize {
            self.challenges_size + self.tables_data_size + self.lookups_data_size
        }

        /// Offset of the challenge section in the full witness layout.
        pub const fn challenges_start(&self) -> usize {
            self.pre_commitment_size()
        }

        /// Offset of the table metadata section in the full witness layout.
        pub const fn tables_data_start(&self) -> usize {
            self.challenges_start() + self.challenges_size
        }

        /// Offset of lookup witness data in the full witness layout.
        pub const fn lookups_data_start(&self) -> usize {
            self.tables_data_start() + self.tables_data_size
        }

        /// Offset of lookup multiplicities in the full witness layout.
        pub const fn multiplicities_start(&self) -> usize {
            self.algebraic_size
        }
    }

    /// WASM-side mirror of `mavros_artifacts::ConstraintsLayout`.
    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    pub struct ConstraintsLayout {
        /// Number of algebraic constraints.
        pub algebraic_size:    usize,
        /// Number of lookup table metadata constraint slots.
        pub tables_data_size:  usize,
        /// Number of lookup data constraint slots.
        pub lookups_data_size: usize,
    }

    impl ConstraintsLayout {
        /// Return the total number of Mavros constraint values.
        pub const fn size(&self) -> usize {
            self.algebraic_size + self.tables_data_size + self.lookups_data_size
        }

        /// Offset of lookup table metadata in constraint buffers.
        pub const fn tables_data_start(&self) -> usize {
            self.algebraic_size
        }

        /// Offset of lookup data in constraint buffers.
        pub const fn lookups_data_start(&self) -> usize {
            self.tables_data_start() + self.tables_data_size
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    struct WasmWitnessLayoutMirror {
        algebraic_size:      usize,
        multiplicities_size: usize,
        challenges_size:     usize,
        tables_data_size:    usize,
        lookups_data_size:   usize,
    }

    #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
    struct WasmConstraintsLayoutMirror {
        algebraic_size:    usize,
        tables_data_size:  usize,
        lookups_data_size: usize,
    }

    #[test]
    fn wasm_layout_stubs_match_mavros_wire_format() {
        let upstream_witness = mavros_artifacts::WitnessLayout {
            algebraic_size:      3,
            multiplicities_size: 5,
            challenges_size:     7,
            tables_data_size:    11,
            lookups_data_size:   13,
        };
        let wasm_witness = WasmWitnessLayoutMirror {
            algebraic_size:      upstream_witness.algebraic_size,
            multiplicities_size: upstream_witness.multiplicities_size,
            challenges_size:     upstream_witness.challenges_size,
            tables_data_size:    upstream_witness.tables_data_size,
            lookups_data_size:   upstream_witness.lookups_data_size,
        };
        assert_eq!(
            postcard::to_allocvec(&upstream_witness).unwrap(),
            postcard::to_allocvec(&wasm_witness).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&upstream_witness).unwrap(),
            serde_json::to_string(&wasm_witness).unwrap()
        );

        let upstream_constraints = mavros_artifacts::ConstraintsLayout {
            algebraic_size:    17,
            tables_data_size:  19,
            lookups_data_size: 23,
        };
        let wasm_constraints = WasmConstraintsLayoutMirror {
            algebraic_size:    upstream_constraints.algebraic_size,
            tables_data_size:  upstream_constraints.tables_data_size,
            lookups_data_size: upstream_constraints.lookups_data_size,
        };
        assert_eq!(
            postcard::to_allocvec(&upstream_constraints).unwrap(),
            postcard::to_allocvec(&wasm_constraints).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&upstream_constraints).unwrap(),
            serde_json::to_string(&wasm_constraints).unwrap()
        );
    }
}
