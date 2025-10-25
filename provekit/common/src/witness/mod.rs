mod binops;
mod digits;
mod layer_scheduler;
mod ram;
mod witness_builder;
mod witness_generator;

use {
    crate::{utils::serde_ark, FieldElement},
    ark_ff::One,
    serde::{Deserialize, Serialize},
};
pub use {
    binops::{BINOP_ATOMIC_BITS, BINOP_BITS, NUM_DIGITS},
    digits::{decompose_into_digits, DigitalDecompositionWitnesses},
    layer_scheduler::{Layer, LayerType, LayeredWitnessBuilders, SplitWitnessBuilders},
    ram::{SpiceMemoryOperation, SpiceWitnesses},
    witness_builder::{
        ConstantTerm, ProductLinearTerm, SumTerm, WitnessBuilder, WitnessCoefficient,
    },
    witness_generator::NoirWitnessGenerator,
};

/// The index of the constant 1 witness in the R1CS instance
pub const WITNESS_ONE_IDX: usize = 0;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConstantOrR1CSWitness {
    Constant(#[serde(with = "serde_ark")] FieldElement),
    Witness(usize),
}

impl ConstantOrR1CSWitness {
    pub fn to_tuple(&self) -> (FieldElement, usize) {
        match self {
            ConstantOrR1CSWitness::Constant(c) => (*c, WITNESS_ONE_IDX),
            ConstantOrR1CSWitness::Witness(w) => (FieldElement::one(), *w),
        }
    }
}
