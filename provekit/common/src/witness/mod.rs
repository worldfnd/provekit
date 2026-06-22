mod binops;
mod digits;
mod limbs;
mod ram;
mod scheduling;
mod witness_builder;

use {
    crate::{
        field::{Ext, FieldHash},
        utils::{serde_ark, serde_ark_vec},
        FieldElement, HashConfig,
    },
    ark_ff::{Field, One},
    serde::{Deserialize, Serialize},
    whir::algebra::embedding::Embedding,
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
#[serde(bound = "")]
pub struct PublicInputs<F: Field = FieldElement>(#[serde(with = "serde_ark_vec")] pub Vec<F>);

impl<F: Field> PublicInputs<F> {
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn from_vec(vec: Vec<F>) -> Self {
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
}

impl<F: Field> Default for PublicInputs<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Binds public inputs to the Fiat-Shamir transcript instance under a chosen
/// proof field `P`.
///
/// The field-element hashing is provided by `P`'s [`FieldHash`] impl, so every
/// backend reuses this with no extra code; `P` selects the field at the call
/// site (e.g. `pi.hash_bytes::<Bn254Field>(config)`). `P` is a method
/// parameter — not a trait parameter — so the impl stays plain over the
/// element type `F`, and the `Source = F` bound ties `Base<P>` back to `F`.
pub trait PublicInputsHash<F: Field> {
    /// Instance-binding hash of these public inputs under `config`.
    ///
    /// Absorbed into the Fiat-Shamir transcript by the prover and recomputed
    /// by the verifier; a mismatch fails verification.
    fn hash<P>(&self, config: HashConfig) -> Ext<P>
    where
        P: FieldHash,
        P::Embedding: Embedding<Source = F>;

    /// [`Self::hash`] as little-endian bytes — the Fiat-Shamir instance tag.
    fn hash_bytes<P>(&self, config: HashConfig) -> Vec<u8>
    where
        P: FieldHash,
        P::Embedding: Embedding<Source = F>;
}

impl<F: Field> PublicInputsHash<F> for PublicInputs<F> {
    #[inline]
    fn hash<P>(&self, config: HashConfig) -> Ext<P>
    where
        P: FieldHash,
        P::Embedding: Embedding<Source = F>,
    {
        P::hash_public_inputs(config, &self.0)
    }

    #[inline]
    fn hash_bytes<P>(&self, config: HashConfig) -> Vec<u8>
    where
        P: FieldHash,
        P::Embedding: Embedding<Source = F>,
    {
        P::ext_to_bytes_le(&self.hash::<P>(config))
    }
}
