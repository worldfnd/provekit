//! bn254-welded bridges between 256-bit `[u64; 4]` limbs and `FieldElement`.
//!
//! These cannot be field-generic: the 4-limb width is fixed to a 256-bit
//! field, and the modulus check is the BN254 prime.

use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
};

/// Convert a `[u64; 4]` bigint to a `FieldElement`.
pub fn bigint_to_fe(val: &[u64; 4]) -> FieldElement {
    FieldElement::from_bigint(BigInt(*val)).expect("bigint value exceeds BN254 field modulus")
}

/// Read a `FieldElement` witness as a `[u64; 4]` bigint.
pub fn fe_to_bigint(fe: FieldElement) -> [u64; 4] {
    fe.into_bigint().0
}
