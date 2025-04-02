mod print_abi;
pub mod sumcheck;

pub use self::print_abi::PrintAbi;
use {
    crate::{FieldElement, NoirElement},
    ark_ff::{BigInt, PrimeField},
    ruint::{aliases::U256, uint},
    tracing::instrument,
};

/// 1/2 for the BN254
pub const HALF: FieldElement = uint_to_field(uint!(
    10944121435919637611123202872628637544274182200208017171849102093287904247809_U256
));

pub const fn uint_to_field(i: U256) -> FieldElement {
    FieldElement::new(BigInt(i.into_limbs()))
}

/// Convert a Noir field element to a native FieldElement
#[inline(always)]
pub fn noir_to_native(n: NoirElement) -> FieldElement {
    let limbs = n.into_repr().into_bigint().0;
    FieldElement::from(BigInt(limbs))
}

/// Calculates the degree of the next smallest power of two
pub fn next_power_of_two(n: usize) -> usize {
    let mut power = 1;
    let mut ans = 0;
    while power < n {
        power <<= 1;
        ans += 1;
    }
    ans
}

/// Pads the vector with 0 so that the number of elements in the vector is a
/// power of 2
#[instrument(skip_all)]
pub fn pad_to_power_of_two<T: Default>(mut witness: Vec<T>) -> Vec<T> {
    let target_len = 1 << next_power_of_two(witness.len());
    witness.reserve_exact(target_len - witness.len());
    while witness.len() < target_len {
        witness.push(T::default());
    }
    witness
}
