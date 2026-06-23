//! Little-endian byte bridges for the extension field element.

use {
    ark_ff::{Field, PrimeField},
    whir::algebra::fields::{Field64, Field64_3},
};

/// Width of the canonical little-endian encoding: three 8-byte Goldilocks
/// base-field coefficients.
pub(crate) const EXT_BYTES: usize = 24;

/// Serializes an extension element to its canonical 24-byte little-endian
/// representation: three 8-byte base coefficients, low coordinate first.
/// Zero-allocation — copies each base limb directly.
#[inline]
pub(crate) fn field_to_bytes_le(fe: Field64_3) -> [u8; EXT_BYTES] {
    let mut out = [0u8; EXT_BYTES];
    for (i, coord) in fe.to_base_prime_field_elements().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&coord.into_bigint().0[0].to_le_bytes());
    }
    out
}

/// Deserializes an extension element from up to 24 little-endian bytes,
/// reducing each 8-byte coefficient mod the base prime (total — never fails,
/// matching the prime-field `from_le_bytes_mod_order` contract). A short input
/// is zero-padded; bytes beyond the 24th are ignored.
#[inline]
pub(crate) fn bytes_to_field(bytes: &[u8]) -> Field64_3 {
    let mut buf = [0u8; EXT_BYTES];
    let n = bytes.len().min(EXT_BYTES);
    buf[..n].copy_from_slice(&bytes[..n]);
    let c0 = Field64::from_le_bytes_mod_order(&buf[0..8]);
    let c1 = Field64::from_le_bytes_mod_order(&buf[8..16]);
    let c2 = Field64::from_le_bytes_mod_order(&buf[16..24]);
    Field64_3::new(c0, c1, c2)
}
