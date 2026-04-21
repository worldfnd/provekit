mod binops;
mod digits;
mod limbs;
mod ram;
mod scheduling;
mod witness_builder;
mod witness_generator;

use {
    crate::{
        hash_config::fe_to_bytes_le,
        utils::{serde_ark, serde_ark_vec},
        FieldElement, HashConfig,
    },
    ark_ff::One,
    serde::{Deserialize, Serialize},
};
pub use {
    binops::BINOP_ATOMIC_BITS,
    digits::{decompose_into_digits, DigitalDecompositionWitnesses},
    limbs::{Limbs, MAX_LIMBS},
    ram::{SpiceMemoryOperation, SpiceWitnesses},
    scheduling::{
        DependencyInfo, Layer, LayerScheduler, LayerType, LayeredWitnessBuilders, SplitError,
        SplitWitnessBuilders, WitnessIndexRemapper,
    },
    witness_builder::{
        CombinedTableEntryInverseData, ConstantTerm, NonNativeEcOp, ProductLinearTerm, SumTerm,
        WitnessBuilder, WitnessCoefficient,
    },
    witness_generator::NoirWitnessGenerator,
};

/// The index of the constant 1 witness in the R1CS instance
pub const WITNESS_ONE_IDX: usize = 0;

/// Compute spread(val): interleave bits of val with zeros.
/// E.g., `0b1011` → `0b01_00_01_01`.
pub fn compute_spread(val: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..32 {
        result |= ((val >> i) & 1) << (2 * i);
    }
    result
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConstantOrR1CSWitness {
    Constant(#[serde(with = "serde_ark")] FieldElement),
    Witness(usize),
}

impl ConstantOrR1CSWitness {
    #[must_use]
    pub fn to_tuple(&self) -> (FieldElement, usize) {
        match self {
            ConstantOrR1CSWitness::Constant(c) => (*c, WITNESS_ONE_IDX),
            ConstantOrR1CSWitness::Witness(w) => (FieldElement::one(), *w),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicInputs(#[serde(with = "serde_ark_vec")] pub Vec<FieldElement>);

impl PublicInputs {
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn from_vec(vec: Vec<FieldElement>) -> Self {
        Self(vec)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Instance-binding hash of these public inputs under `config`.
    ///
    /// Absorbed into the Fiat-Shamir transcript by the prover and recomputed
    /// by the verifier; a mismatch fails verification. Delegates to
    /// [`HashConfig::hash_field_elements`].
    #[inline]
    #[must_use]
    pub fn hash(&self, config: HashConfig) -> FieldElement {
        config.hash_field_elements(&self.0)
    }

    /// Returns [`Self::hash`] as canonical 32-byte little-endian output.
    ///
    /// Used as the Fiat-Shamir instance tag binding the transcript to these
    /// public inputs.
    #[inline]
    #[must_use]
    pub fn hash_bytes(&self, config: HashConfig) -> [u8; 32] {
        fe_to_bytes_le(&self.hash(config))
    }
}

impl Default for PublicInputs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, proptest::prelude::*};

    const ALL_CONFIGS: [HashConfig; 5] = [
        HashConfig::Skyscraper,
        HashConfig::Sha256,
        HashConfig::Keccak,
        HashConfig::Blake3,
        HashConfig::Poseidon2,
    ];

    fn fe(n: u64) -> FieldElement {
        FieldElement::from(n)
    }

    fn pi(vals: &[u64]) -> PublicInputs {
        PublicInputs::from_vec(vals.iter().copied().map(fe).collect())
    }

    // --- determinism ---

    #[test]
    fn hash_is_deterministic_for_all_configs() {
        let inputs = pi(&[1, 2, 3]);
        for config in ALL_CONFIGS {
            assert_eq!(
                inputs.hash(config),
                inputs.hash(config),
                "{config:?}: hash must be deterministic"
            );
        }
    }

    #[test]
    fn hash_bytes_is_deterministic_for_all_configs() {
        let inputs = pi(&[42]);
        for config in ALL_CONFIGS {
            assert_eq!(
                inputs.hash_bytes(config),
                inputs.hash_bytes(config),
                "{config:?}: hash_bytes must be deterministic"
            );
        }
    }

    #[test]
    fn hash_bytes_is_le_serialization_of_hash() {
        let inputs = pi(&[7, 13]);
        for config in ALL_CONFIGS {
            assert_eq!(
                inputs.hash_bytes(config),
                fe_to_bytes_le(&inputs.hash(config)),
                "{config:?}: hash_bytes must equal LE(hash())"
            );
        }
    }

    // --- empty input ---

    #[test]
    fn skyscraper_empty_returns_zero() {
        // Transcript-visible back-compat: Skyscraper hashes [] to 0.
        assert_eq!(
            PublicInputs::new().hash(HashConfig::Skyscraper),
            FieldElement::from(0u64),
        );
    }

    #[test]
    fn empty_input_is_deterministic_for_all_configs() {
        let empty = PublicInputs::new();
        for config in ALL_CONFIGS {
            assert_eq!(
                empty.hash(config),
                empty.hash(config),
                "{config:?}: empty hash must be deterministic"
            );
        }
    }

    // --- cross-variant isolation ---

    #[test]
    fn different_configs_produce_different_hashes() {
        // Non-trivial input so Skyscraper's empty-→-0 behaviour doesn't collide
        // with any other variant's H(DST) mod p by coincidence.
        let inputs = pi(&[1, 2]);
        let hashes: Vec<_> = ALL_CONFIGS.iter().map(|&c| inputs.hash(c)).collect();
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(
                    hashes[i], hashes[j],
                    "{:?} and {:?} must produce different hashes for the same input",
                    ALL_CONFIGS[i], ALL_CONFIGS[j],
                );
            }
        }
    }

    // --- input sensitivity ---

    #[test]
    fn hash_depends_on_order_for_all_configs() {
        let input = pi(&[1, 2]);
        let reversed = pi(&[2, 1]);
        for config in ALL_CONFIGS {
            assert_ne!(
                input.hash(config),
                reversed.hash(config),
                "{config:?}: hash must be order-sensitive"
            );
        }
    }

    #[test]
    fn hash_depends_on_values_for_all_configs() {
        let a = pi(&[1, 2, 3]);
        let b = pi(&[1, 2, 4]);
        for config in ALL_CONFIGS {
            assert_ne!(
                a.hash(config),
                b.hash(config),
                "{config:?}: hash must differ when values differ"
            );
        }
    }

    // --- no ambient state ---

    #[test]
    fn hashing_is_independent_of_prior_calls() {
        // Pins the no-global-state contract: an intervening call with a
        // different config must not influence a later call.
        let inputs = pi(&[55, 89]);
        let first = inputs.hash(HashConfig::Sha256);
        let _ = inputs.hash(HashConfig::Keccak);
        let third = inputs.hash(HashConfig::Sha256);
        assert_eq!(
            first, third,
            "Sha256 result must not depend on an intervening Keccak call"
        );
    }

    // --- known-answer tests (regression pins) ---
    //
    // Byte-exact outputs of `PublicInputs::from_vec(..).hash_bytes(config)` for
    // fixed inputs. Any change to the encoding (DST, per-element serialization,
    // mod-reduction, Skyscraper compression order) will fail these and must be
    // a deliberate, reviewed format change.

    #[test]
    fn kat_empty_skyscraper() {
        // Skyscraper on empty input is 0 by construction; no DST.
        let got = PublicInputs::new().hash_bytes(HashConfig::Skyscraper);
        assert_eq!(got, [0u8; 32], "Skyscraper empty-input KAT drift");
    }

    #[test]
    fn kat_one_two_skyscraper() {
        let got = pi(&[1, 2]).hash_bytes(HashConfig::Skyscraper);
        assert_eq!(
            got,
            [
                0x7c, 0x38, 0x2a, 0x25, 0xa9, 0x25, 0x53, 0x1f, 0x7e, 0x26, 0xa8, 0xab, 0xdc, 0x91,
                0x1a, 0x03, 0x95, 0x2a, 0x46, 0x9e, 0xfb, 0xb5, 0x71, 0xe9, 0x86, 0x3f, 0x1c, 0xcd,
                0x56, 0x7e, 0xe6, 0x2d,
            ],
            "Skyscraper [1, 2] KAT drift"
        );
    }

    #[test]
    fn kat_empty_sha256() {
        let got = PublicInputs::new().hash_bytes(HashConfig::Sha256);
        assert_eq!(got, KAT_EMPTY_SHA256, "SHA-256 empty-input KAT drift");
    }

    #[test]
    fn kat_one_two_sha256() {
        let got = pi(&[1, 2]).hash_bytes(HashConfig::Sha256);
        assert_eq!(got, KAT_ONE_TWO_SHA256, "SHA-256 [1, 2] KAT drift");
    }

    #[test]
    fn kat_empty_keccak() {
        let got = PublicInputs::new().hash_bytes(HashConfig::Keccak);
        assert_eq!(got, KAT_EMPTY_KECCAK, "Keccak-256 empty-input KAT drift");
    }

    #[test]
    fn kat_one_two_keccak() {
        let got = pi(&[1, 2]).hash_bytes(HashConfig::Keccak);
        assert_eq!(got, KAT_ONE_TWO_KECCAK, "Keccak-256 [1, 2] KAT drift");
    }

    #[test]
    fn kat_empty_blake3() {
        let got = PublicInputs::new().hash_bytes(HashConfig::Blake3);
        assert_eq!(got, KAT_EMPTY_BLAKE3, "BLAKE3 empty-input KAT drift");
    }

    #[test]
    fn kat_one_two_blake3() {
        let got = pi(&[1, 2]).hash_bytes(HashConfig::Blake3);
        assert_eq!(got, KAT_ONE_TWO_BLAKE3, "BLAKE3 [1, 2] KAT drift");
    }

    #[test]
    fn kat_empty_poseidon2() {
        // Non-zero because the capacity-lane IV still permutes on empty input.
        let got = PublicInputs::new().hash_bytes(HashConfig::Poseidon2);
        assert_eq!(got, KAT_EMPTY_POSEIDON2, "Poseidon2 empty-input KAT drift");
    }

    #[test]
    fn kat_one_two_poseidon2() {
        let got = pi(&[1, 2]).hash_bytes(HashConfig::Poseidon2);
        assert_eq!(got, KAT_ONE_TWO_POSEIDON2, "Poseidon2 [1, 2] KAT drift");
    }

    // Frozen outputs. Regenerate only for a deliberate, reviewed format change.

    const KAT_EMPTY_SHA256: [u8; 32] = [
        0xc6, 0xa2, 0x48, 0x23, 0x44, 0xd4, 0x29, 0xf5, 0x53, 0x37, 0xc3, 0xb6, 0x87, 0xb5, 0xc3,
        0x54, 0x47, 0x5c, 0x7c, 0x7f, 0x17, 0xac, 0x26, 0xeb, 0x47, 0x92, 0x78, 0x00, 0x11, 0xfe,
        0xa0, 0x26,
    ];
    const KAT_ONE_TWO_SHA256: [u8; 32] = [
        0x0f, 0x7b, 0x4c, 0xec, 0x9b, 0x45, 0x3f, 0xe5, 0x2f, 0xf4, 0x32, 0x96, 0x96, 0x60, 0xd2,
        0xd8, 0x92, 0x5e, 0x7c, 0x34, 0xdd, 0x27, 0x59, 0x05, 0x7f, 0xc0, 0xf2, 0x73, 0x43, 0x53,
        0x76, 0x1d,
    ];
    const KAT_EMPTY_KECCAK: [u8; 32] = [
        0xb2, 0x2f, 0xf9, 0x91, 0x4f, 0xaf, 0xbd, 0xd0, 0x3c, 0x4f, 0xa2, 0x7a, 0xb0, 0x8a, 0x34,
        0x5f, 0x0e, 0x1c, 0x62, 0x53, 0xf4, 0xc0, 0x02, 0x37, 0x2b, 0xaa, 0x50, 0x3c, 0x82, 0xb1,
        0x2d, 0x23,
    ];
    const KAT_ONE_TWO_KECCAK: [u8; 32] = [
        0xb1, 0xe0, 0x10, 0xfa, 0x01, 0x19, 0xcf, 0x35, 0x85, 0xac, 0x34, 0xb3, 0xdb, 0xb0, 0x11,
        0x17, 0x57, 0xa9, 0x63, 0xff, 0x8d, 0x3c, 0x76, 0xc9, 0xf7, 0xc6, 0x79, 0xb0, 0xfb, 0xf1,
        0x41, 0x16,
    ];
    const KAT_EMPTY_BLAKE3: [u8; 32] = [
        0x7b, 0x01, 0x61, 0xea, 0x26, 0xb6, 0x36, 0xbc, 0x69, 0x23, 0xf3, 0x87, 0x7d, 0x4d, 0xca,
        0xb8, 0xf7, 0xa9, 0xb4, 0x8d, 0x38, 0x56, 0x01, 0x13, 0x93, 0x57, 0xa0, 0x55, 0x37, 0x0c,
        0xda, 0x27,
    ];
    const KAT_ONE_TWO_BLAKE3: [u8; 32] = [
        0x84, 0x08, 0x71, 0x4e, 0xb3, 0xb2, 0x8e, 0x8f, 0xd6, 0xb5, 0xd0, 0x3d, 0x35, 0x99, 0x08,
        0x4e, 0x47, 0x7d, 0x1f, 0xf9, 0xf5, 0x79, 0xc1, 0x46, 0xb4, 0x28, 0x84, 0xa5, 0x6b, 0xc5,
        0xa5, 0x25,
    ];
    // Poseidon2([]) = poseidon2_permutation([0; 4])[0], in LE bytes.
    const KAT_EMPTY_POSEIDON2: [u8; 32] = [
        0x2e, 0x73, 0xc6, 0x8b, 0x69, 0x5c, 0x78, 0x96, 0xb4, 0x36, 0x42, 0x84, 0x9d, 0x6d, 0xe9,
        0x1c, 0x8b, 0xf7, 0x8d, 0xfc, 0xfe, 0x4e, 0x97, 0xff, 0x9c, 0x22, 0x82, 0x9b, 0xdc, 0xb8,
        0xdf, 0x18,
    ];
    const KAT_ONE_TWO_POSEIDON2: [u8; 32] = [
        0x83, 0x73, 0xed, 0xe1, 0x1c, 0x64, 0xad, 0x9c, 0xaf, 0x0f, 0x03, 0x6f, 0x1f, 0x11, 0x5c,
        0x7c, 0xc7, 0x95, 0x2a, 0x43, 0xda, 0x13, 0x3f, 0x0a, 0x4e, 0xae, 0xb5, 0x1c, 0xaa, 0x82,
        0x86, 0x03,
    ];

    // --- property tests ---

    fn any_hash_config() -> impl Strategy<Value = HashConfig> {
        prop_oneof![
            Just(HashConfig::Skyscraper),
            Just(HashConfig::Sha256),
            Just(HashConfig::Keccak),
            Just(HashConfig::Blake3),
            Just(HashConfig::Poseidon2),
        ]
    }

    fn any_public_inputs() -> impl Strategy<Value = PublicInputs> {
        prop::collection::vec(any::<u64>(), 0..32)
            .prop_map(|v| PublicInputs::from_vec(v.into_iter().map(FieldElement::from).collect()))
    }

    proptest! {
        #[test]
        fn prop_hash_is_deterministic(
            config in any_hash_config(),
            inputs in any_public_inputs(),
        ) {
            prop_assert_eq!(inputs.hash(config), inputs.hash(config));
        }

        #[test]
        fn prop_hash_bytes_is_deterministic(
            config in any_hash_config(),
            inputs in any_public_inputs(),
        ) {
            prop_assert_eq!(inputs.hash_bytes(config), inputs.hash_bytes(config));
        }

        #[test]
        fn prop_distinct_inputs_distinct_hashes(
            config in any_hash_config(),
            a in prop::collection::vec(any::<u64>(), 1..32),
            b in prop::collection::vec(any::<u64>(), 1..32),
        ) {
            prop_assume!(a != b);
            let ha = PublicInputs::from_vec(
                a.iter().copied().map(FieldElement::from).collect()
            ).hash(config);
            let hb = PublicInputs::from_vec(
                b.iter().copied().map(FieldElement::from).collect()
            ).hash(config);
            prop_assert_ne!(ha, hb);
        }
    }
}
