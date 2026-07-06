mod binops;
mod digits;
mod limbs;
mod ram;
mod scheduling;
mod witness_builder;

use {
    crate::FieldElement,
    ark_ff::One,
    provekit_common::utils::serde_ark,
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
