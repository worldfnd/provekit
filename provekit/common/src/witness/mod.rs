mod binops;
mod digits;
mod limbs;
mod ram;
mod scheduling;
mod witness_builder;
mod witness_generator;

use {
    crate::{
        utils::{serde_ark, serde_ark_vec},
        FieldElement,
    },
    ark_ff::{BigInt, BigInteger, One, PrimeField},
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

/// Serialize a field element to its canonical 32-byte little-endian form.
///
/// Panics if the serialized representation exceeds 32 bytes, which would
/// indicate a field larger than BN254
fn fe_to_bytes_le(fe: &FieldElement) -> [u8; 32] {
    let bytes = fe.into_bigint().to_bytes_le();
    debug_assert!(
        bytes.len() <= 32,
        "field element serialized to {} bytes; expected ≤ 32 (BN254 is 254-bit)",
        bytes.len()
    );
    let mut result = [0u8; 32];
    result[..bytes.len()].copy_from_slice(&bytes);
    result
}

fn hash_with_skyscraper(elements: &[FieldElement]) -> FieldElement {
    fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
        let out = skyscraper::simple::compress(l.into_bigint().0, r.into_bigint().0);
        FieldElement::new(BigInt(out))
    }
    match elements.len() {
        // Preserve the long-standing Skyscraper empty-input behavior; changing
        // this would change transcript-visible public-input binding semantics.
        0 => FieldElement::from(0u64),
        1 => compress(elements[0], FieldElement::from(0u64)),
        _ => {
            let first = elements[0];
            elements[1..].iter().copied().fold(first, compress)
        }
    }
}

fn hash_with_sha256(elements: &[FieldElement]) -> FieldElement {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for fe in elements {
        hasher.update(fe_to_bytes_le(fe));
    }
    FieldElement::from_le_bytes_mod_order(&hasher.finalize())
}

fn hash_with_keccak(elements: &[FieldElement]) -> FieldElement {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    for fe in elements {
        hasher.update(fe_to_bytes_le(fe));
    }
    FieldElement::from_le_bytes_mod_order(&hasher.finalize())
}

fn hash_with_blake3(elements: &[FieldElement]) -> FieldElement {
    let mut hasher = blake3::Hasher::new();
    for fe in elements {
        hasher.update(&fe_to_bytes_le(fe));
    }
    FieldElement::from_le_bytes_mod_order(hasher.finalize().as_bytes())
}

/// Returns the field hasher function for the given hash configuration.
pub(crate) fn field_hasher_for(config: crate::HashConfig) -> fn(&[FieldElement]) -> FieldElement {
    match config {
        crate::HashConfig::Skyscraper => hash_with_skyscraper,
        crate::HashConfig::Sha256 => hash_with_sha256,
        crate::HashConfig::Keccak => hash_with_keccak,
        crate::HashConfig::Blake3 => hash_with_blake3,
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

    /// Compute the public-inputs commitment as a field element for the given
    /// hash configuration.
    ///
    /// Used as a prover transcript message (bound to the Fiat-Shamir instance)
    /// and checked by the verifier.
    #[must_use]
    pub fn hash_with(&self, config: crate::HashConfig) -> FieldElement {
        field_hasher_for(config)(&self.0)
    }

    /// Compute the public-inputs hash as a 32-byte array (little-endian) for
    /// the given hash configuration.
    ///
    /// Used to bind public inputs to the Fiat-Shamir transcript instance.
    #[must_use]
    pub fn hash_bytes_with(&self, config: crate::HashConfig) -> [u8; 32] {
        fe_to_bytes_le(&self.hash_with(config))
    }
}

impl Default for PublicInputs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::HashConfig};

    const ALL_CONFIGS: [HashConfig; 4] = [
        HashConfig::Skyscraper,
        HashConfig::Sha256,
        HashConfig::Keccak,
        HashConfig::Blake3,
    ];

    fn fe(n: u64) -> FieldElement {
        FieldElement::from(n)
    }

    fn pi(vals: &[u64]) -> PublicInputs {
        PublicInputs::from_vec(vals.iter().copied().map(fe).collect())
    }

    fn hash(config: HashConfig, inputs: &PublicInputs) -> FieldElement {
        field_hasher_for(config)(&inputs.0)
    }

    fn hash_bytes(config: HashConfig, inputs: &PublicInputs) -> [u8; 32] {
        fe_to_bytes_le(&hash(config, inputs))
    }

    #[test]
    fn public_inputs_hash_with_matches_helper_for_all_configs() {
        let inputs = pi(&[3, 5, 8]);
        for config in ALL_CONFIGS {
            assert_eq!(
                inputs.hash_with(config),
                hash(config, &inputs),
                "{config:?}: hash_with must match the configured helper"
            );
        }
    }

    #[test]
    fn public_inputs_hash_bytes_with_matches_helper_for_all_configs() {
        let inputs = pi(&[13, 21]);
        for config in ALL_CONFIGS {
            assert_eq!(
                inputs.hash_bytes_with(config),
                hash_bytes(config, &inputs),
                "{config:?}: hash_bytes_with must match the configured helper"
            );
        }
    }

    #[test]
    fn public_inputs_hashing_requires_no_prior_registration() {
        let inputs = pi(&[1, 1, 2, 3, 5]);
        for config in ALL_CONFIGS {
            let _ = inputs.hash_with(config);
            let _ = inputs.hash_bytes_with(config);
        }
    }

    #[test]
    fn public_inputs_hashing_is_order_independent_across_configs() {
        let inputs = pi(&[55, 89]);
        let first = inputs.hash_with(HashConfig::Sha256);
        let second = inputs.hash_with(HashConfig::Keccak);
        let third = inputs.hash_with(HashConfig::Sha256);

        assert_eq!(
            first, third,
            "Sha256 result must not depend on prior Keccak call"
        );
        assert_ne!(
            first, second,
            "different configs must still produce different hashes"
        );
    }

    #[test]
    fn known_answer_vectors_for_empty_input_are_stable() {
        let empty = PublicInputs::new();
        let expected = [
            (HashConfig::Skyscraper, [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]),
            (HashConfig::Sha256, [
                0xe2, 0xb0, 0xc4, 0x52, 0x04, 0x07, 0x3b, 0xd0, 0x08, 0x8b, 0x3b, 0x4f, 0x51, 0x87,
                0x85, 0xfc, 0xc9, 0x55, 0xc0, 0x62, 0xae, 0x55, 0x43, 0x94, 0x7a, 0xf5, 0x67, 0x3a,
                0x05, 0x04, 0x54, 0x25,
            ]),
            (HashConfig::Keccak, [
                0xc3, 0xd2, 0x46, 0x21, 0x5e, 0x0c, 0x60, 0xb4, 0x6f, 0x9d, 0x0a, 0xbf, 0x4b, 0xf7,
                0x9b, 0x6f, 0x2b, 0x50, 0xb3, 0x50, 0x5d, 0xf7, 0x86, 0xca, 0x27, 0xba, 0x75, 0x42,
                0x77, 0xe8, 0xdb, 0x0f,
            ]),
            (HashConfig::Blake3, [
                0xad, 0x13, 0x49, 0xd9, 0xcd, 0x0e, 0xde, 0x1e, 0x7e, 0x5f, 0xda, 0xf6, 0xa5, 0x0b,
                0x62, 0xf9, 0xe0, 0x1a, 0x23, 0xc6, 0x40, 0x36, 0x72, 0x46, 0x79, 0x5a, 0x30, 0x08,
                0xff, 0x82, 0x69, 0x01,
            ]),
        ];

        for (config, expected_bytes) in expected {
            assert_eq!(
                empty.hash_bytes_with(config),
                expected_bytes,
                "{config:?}: empty-input vector changed"
            );
        }
    }

    #[test]
    fn known_answer_vectors_for_one_two_are_stable() {
        let one_two = pi(&[1, 2]);
        let expected = [
            (HashConfig::Skyscraper, [
                0x7c, 0x38, 0x2a, 0x25, 0xa9, 0x25, 0x53, 0x1f, 0x7e, 0x26, 0xa8, 0xab, 0xdc, 0x91,
                0x1a, 0x03, 0x95, 0x2a, 0x46, 0x9e, 0xfb, 0xb5, 0x71, 0xe9, 0x86, 0x3f, 0x1c, 0xcd,
                0x56, 0x7e, 0xe6, 0x2d,
            ]),
            (HashConfig::Sha256, [
                0xfc, 0x55, 0xc9, 0xa9, 0xba, 0xc7, 0x9a, 0xe8, 0x1a, 0x88, 0x38, 0x80, 0x70, 0x2a,
                0xde, 0xcc, 0x7c, 0xb1, 0xbb, 0xe2, 0x2e, 0x67, 0xc4, 0xd4, 0xa8, 0xf1, 0xed, 0x12,
                0xb7, 0x84, 0x74, 0x03,
            ]),
            (HashConfig::Keccak, [
                0x4d, 0x44, 0x53, 0xa7, 0xd6, 0x82, 0x09, 0xf1, 0x87, 0x49, 0xbd, 0x41, 0x7e, 0x8e,
                0xde, 0x31, 0xa7, 0x86, 0x9b, 0xee, 0x89, 0x32, 0x7e, 0x0f, 0xb6, 0x63, 0xb0, 0xe9,
                0x12, 0x9e, 0x4a, 0x23,
            ]),
            (HashConfig::Blake3, [
                0x58, 0x22, 0xd9, 0xc8, 0xc4, 0x69, 0xe6, 0xea, 0x92, 0x6b, 0xb6, 0x54, 0x12, 0x09,
                0x5d, 0x30, 0x25, 0x7f, 0xbc, 0xd2, 0x95, 0x6e, 0x46, 0x39, 0x12, 0x73, 0xc6, 0x75,
                0x32, 0x4a, 0x19, 0x06,
            ]),
        ];

        for (config, expected_bytes) in expected {
            assert_eq!(
                one_two.hash_bytes_with(config),
                expected_bytes,
                "{config:?}: [1, 2] vector changed"
            );
        }
    }

    // --- determinism ---

    #[test]
    fn hash_is_deterministic_for_all_configs() {
        let inputs = pi(&[1, 2, 3]);
        for config in ALL_CONFIGS {
            assert_eq!(
                hash(config, &inputs),
                hash(config, &inputs),
                "{config:?}: hash must be deterministic"
            );
        }
    }

    #[test]
    fn hash_bytes_is_deterministic_for_all_configs() {
        let inputs = pi(&[42]);
        for config in ALL_CONFIGS {
            assert_eq!(
                hash_bytes(config, &inputs),
                hash_bytes(config, &inputs),
                "{config:?}: hash_bytes must be deterministic"
            );
        }
    }

    // --- empty input edge case ---

    #[test]
    fn skyscraper_empty_returns_zero() {
        assert_eq!(
            hash(HashConfig::Skyscraper, &PublicInputs::new()),
            FieldElement::from(0u64),
        );
    }

    #[test]
    fn empty_input_is_deterministic_for_all_configs() {
        let empty = PublicInputs::new();
        for config in ALL_CONFIGS {
            assert_eq!(
                hash(config, &empty),
                hash(config, &empty),
                "{config:?}: empty hash must be deterministic"
            );
        }
    }

    // --- cross-variant isolation ---

    #[test]
    fn different_configs_produce_different_hashes() {
        // Use a non-trivial input so Skyscraper empty=0 doesn't collide by accident.
        let inputs = pi(&[1, 2]);
        let hashes: Vec<_> = ALL_CONFIGS.iter().map(|&c| hash(c, &inputs)).collect();
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
                hash(config, &input),
                hash(config, &reversed),
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
                hash(config, &a),
                hash(config, &b),
                "{config:?}: hash must differ when values differ"
            );
        }
    }

    // --- hash_bytes consistency ---

    #[test]
    fn hash_bytes_is_le_serialization_of_hash() {
        let inputs = pi(&[7, 13]);
        for config in ALL_CONFIGS {
            let h = hash(config, &inputs);
            let expected = fe_to_bytes_le(&h);
            assert_eq!(
                hash_bytes(config, &inputs),
                expected,
                "{config:?}: hash_bytes must equal LE serialization of hash()"
            );
        }
    }
}
