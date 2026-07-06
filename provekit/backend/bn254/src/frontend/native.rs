use {
    crate::FieldElement,
    acir::FieldElement as NoirElement,
    ark_ff::{BigInt, PrimeField},
};

/// Convert a Noir field element to a native `FieldElement`.
#[inline(always)]
pub fn noir_to_native(n: NoirElement) -> FieldElement {
    let limbs = n.into_repr().into_bigint().0;
    FieldElement::from(BigInt(limbs))
}
