//! Bridge between the Noir/ACIR field representation and the native bn254
//! [`FieldElement`].
//!
//! `NoirElement` is the bn254 scalar field as the Noir toolchain (`acir`)
//! represents it. This conversion lives in the bn254 field crate — not in the
//! field-agnostic spine — because it only type-checks when the native field
//! *is* bn254; a non-bn254 build (e.g. Goldilocks) never compiles it and so
//! never needs an ACIR bridge it could not satisfy.

use {
    ark_ff::{BigInt, PrimeField},
    provekit_common::FieldElement,
};

/// A Noir/ACIR field element (the bn254 scalar field as seen by `acir`).
pub type NoirElement = acir::FieldElement;

/// Convert a Noir field element to the native bn254 [`FieldElement`].
#[inline(always)]
pub fn noir_to_native(n: NoirElement) -> FieldElement {
    let limbs = n.into_repr().into_bigint().0;
    FieldElement::from(BigInt(limbs))
}
