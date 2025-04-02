pub mod file_io;
mod print_abi;

pub use self::print_abi::{PrintAbi, PrintType};
use {
    crate::{FieldElement, NoirElement},
    ark_ff::{BigInt, PrimeField},
    ruint::aliases::U256,
};

pub const fn uint_to_field(i: U256) -> FieldElement {
    FieldElement::new(BigInt(i.into_limbs()))
}

/// Convert a Noir field element to a native FieldElement
#[inline(always)]
pub fn noir_to_native(n: NoirElement) -> FieldElement {
    let limbs = n.into_repr().into_bigint().0;
    FieldElement::from(BigInt(limbs))
}
