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
fn fe_to_bytes_le(fe: &FieldElement) -> [u8; 32] {
    let bytes = fe.into_bigint().to_bytes_le();
    let mut result = [0u8; 32];
    let len = bytes.len().min(32);
    result[..len].copy_from_slice(&bytes[..len]);
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
        let hash = self.hash(hash_config);
        let bytes = hash.into_bigint().to_bytes_le();
        let mut result = [0u8; 32];
        let len = bytes.len().min(32);
        result[..len].copy_from_slice(&bytes[..len]);
        result
    }
}

impl Default for PublicInputs {
    fn default() -> Self {
        Self::new()
    }
}
