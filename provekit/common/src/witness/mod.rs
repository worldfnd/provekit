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
    assert!(
        bytes.len() <= 32,
        "field element serialized to {} bytes; expected ≤ 32 (BN254 is 254-bit)",
        bytes.len()
    );
    let mut result = [0u8; 32];
    result[..bytes.len()].copy_from_slice(&bytes);
    result
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

    /// Compute the public-inputs commitment as a field element using the
    /// specified hash algorithm.
    ///
    /// Used as a prover transcript message (bound to the Fiat-Shamir instance)
    /// and checked by the verifier. Both prover and verifier must call this
    /// with the same `hash_config` to produce matching transcripts.
    #[must_use]
    pub fn hash(&self, hash_config: crate::HashConfig) -> FieldElement {
        match hash_config {
            crate::HashConfig::Skyscraper => {
                fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
                    let out = skyscraper::simple::compress(l.into_bigint().0, r.into_bigint().0);
                    FieldElement::new(BigInt(out))
                }
                match self.0.len() {
                    0 => FieldElement::from(0u64),
                    1 => compress(self.0[0], FieldElement::from(0u64)),
                    _ => self.0.iter().copied().reduce(compress).unwrap(),
                }
            }
            crate::HashConfig::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                for fe in &self.0 {
                    hasher.update(fe_to_bytes_le(fe));
                }
                FieldElement::from_le_bytes_mod_order(&hasher.finalize())
            }
            crate::HashConfig::Keccak => {
                use sha3::{Digest, Keccak256};
                let mut hasher = Keccak256::new();
                for fe in &self.0 {
                    hasher.update(fe_to_bytes_le(fe));
                }
                FieldElement::from_le_bytes_mod_order(&hasher.finalize())
            }
            crate::HashConfig::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                for fe in &self.0 {
                    hasher.update(&fe_to_bytes_le(fe));
                }
                FieldElement::from_le_bytes_mod_order(hasher.finalize().as_bytes())
            }
        }
    }

    /// Compute the public-inputs hash as a 32-byte array (little-endian).
    ///
    /// Used to bind public inputs to the Fiat-Shamir transcript instance.
    #[must_use]
    pub fn hash_bytes(&self, hash_config: crate::HashConfig) -> [u8; 32] {
        fe_to_bytes_le(&self.hash(hash_config))
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

    // --- empty input edge case ---

    #[test]
    fn skyscraper_empty_returns_zero() {
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
        // Use a non-trivial input so Skyscraper empty=0 doesn't collide by accident.
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

    // --- hash_bytes consistency ---

    #[test]
    fn hash_bytes_is_le_serialization_of_hash() {
        let inputs = pi(&[7, 13]);
        for config in ALL_CONFIGS {
            let h = inputs.hash(config);
            let expected = fe_to_bytes_le(&h);
            assert_eq!(
                inputs.hash_bytes(config),
                expected,
                "{config:?}: hash_bytes must equal LE serialization of hash()"
            );
        }
    }
}
