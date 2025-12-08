mod binops;
mod digits;
mod ram;
mod scheduling;
mod witness_builder;
mod witness_generator;
mod witness_io_pattern;

use {
    crate::{utils::{serde_ark, serde_ark_vec}, FieldElement},
    ark_ff::{BigInt, One, PrimeField},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
};
pub use {
    binops::{BINOP_ATOMIC_BITS, BINOP_BITS, NUM_DIGITS},
    digits::{decompose_into_digits, DigitalDecompositionWitnesses},
    ram::{SpiceMemoryOperation, SpiceWitnesses},
    scheduling::{Layer, LayerType, LayeredWitnessBuilders, SplitWitnessBuilders},
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
    /// Creates a new `PublicInputs` with a constant 1 field element at the
    /// start.
    pub fn new() -> Self {
        Self(vec![FieldElement::one()])
    }

    /// Creates a new `PublicInputs` from a vector, adding a constant 1 field
    /// element at the start. To emulate the constant 1 witness in the R1CS
    /// instance.
    pub fn from_vec(mut vec: Vec<FieldElement>) -> Self {
        vec.insert(0, FieldElement::one());
        Self(vec)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Hashes the public input values using SHA-256 and converts the result to
    /// a FieldElement.
    pub fn hash(&self) -> FieldElement {
        let mut hasher = Sha256::new();

        // Hash all public values from witness
        for value in self.0.iter() {
            let bigint = value.into_bigint();
            for limb in bigint.0.iter() {
                hasher.update(&limb.to_le_bytes());
            }
        }

        let result = hasher.finalize();

        let limbs = result
            .chunks_exact(8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
            .collect::<Vec<_>>();

        FieldElement::new(BigInt::new(limbs.try_into().unwrap()))
    }
}
