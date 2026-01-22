mod binops;
mod digits;
mod ram;
mod scheduling;
mod witness_builder;
mod witness_generator;
mod witness_io_pattern;

use {
    crate::{
        skyscraper::SkyscraperCRH,
        utils::{serde_ark, serde_ark_vec},
        FieldElement,
    },
    ark_crypto_primitives::crh::CRHScheme,
    ark_ff::One,
    serde::{Deserialize, Serialize},
};
pub use {
    binops::{BINOP_ATOMIC_BITS, BINOP_BITS, NUM_DIGITS},
    digits::{decompose_into_digits, DigitalDecompositionWitnesses},
    ram::{SpiceMemoryOperation, SpiceWitnesses},
    scheduling::{Layer, LayerType, LayeredWitnessBuilders, SplitError, SplitWitnessBuilders},
    witness_builder::{
        ConstantTerm, ProductLinearTerm, SumTerm, WitnessBuilder, WitnessCoefficient,
    },
    witness_generator::NoirWitnessGenerator,
    witness_io_pattern::WitnessIOPattern,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicInputs(#[serde(with = "serde_ark_vec")] pub Vec<FieldElement>);

impl PublicInputs {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn from_vec(vec: Vec<FieldElement>) -> Self {
        Self(vec)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn hash(&self) -> FieldElement {
        match self.0.len() {
            0 => FieldElement::from(0u64),
            1 => {
                // For single element, hash it with zero to ensure it gets properly hashed
                let padded = vec![self.0[0], FieldElement::from(0u64)];
                SkyscraperCRH::evaluate(&(), &padded[..]).expect("hash should succeed")
            }
            _ => SkyscraperCRH::evaluate(&(), &self.0[..])
                .expect("hash should succeed for multiple inputs"),
        }
    }
}

impl Default for PublicInputs {
    fn default() -> Self {
        Self::new()
    }
}
