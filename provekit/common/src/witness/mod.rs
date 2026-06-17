mod binops;
mod digits;
mod limbs;
mod ram;
mod scheduling;
mod witness_builder;

use {
    crate::{
        utils::{field_to_bytes_le, serde_ark, serde_ark_vec},
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
    /// [`HashConfig::hash_field_elements`]. The Skyscraper/Poseidon2 paths
    /// require the field hash provider to be registered (see
    /// [`crate::register_field_hash_provider`]); KATs live in
    /// `provekit-field-bn254`.
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
        field_to_bytes_le(self.hash(config))
    }
}

impl Default for PublicInputs {
    fn default() -> Self {
        Self::new()
    }
}
