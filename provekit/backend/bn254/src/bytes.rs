//! Canonical little-endian byte bridges for the bn254 field element.
//!
//! Used by the Merkle/sponge hashers and `FieldHash` byte methods to move
//! between `Fr` and its 32-byte little-endian encoding.

use {crate::FieldElement, ark_ff::PrimeField};

/// Deserializes a BN254 field element from up to 32 little-endian bytes.
#[inline]
pub(crate) fn bytes_to_field(bytes: &[u8]) -> FieldElement {
    FieldElement::from_le_bytes_mod_order(bytes)
}

/// Serializes a BN254 field element to its canonical 32-byte little-endian
/// representation. Zero-allocation: copies the 4 canonical limbs directly
/// instead of routing through `BigInt::to_bytes_le`'s `Vec<u8>`.
#[inline]
pub(crate) fn field_to_bytes_le(fe: FieldElement) -> [u8; 32] {
    let limbs = fe.into_bigint().0;
    let mut out = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}
