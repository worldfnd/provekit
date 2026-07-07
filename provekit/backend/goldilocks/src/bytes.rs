//! Little-endian byte bridges for the extension field element.

use {
    ark_ff::{Field, PrimeField},
    whir::algebra::fields::{Field64, Field64_3},
};

/// Width of the canonical little-endian encoding: three 8-byte Goldilocks
/// base-field coefficients.
pub(crate) const EXT_BYTES: usize = 24;

/// The Goldilocks base prime, `2^64 − 2^32 + 1`. A canonical little-endian
/// coefficient encodes a value strictly below this.
const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

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

/// Deserializes an extension element from up to 24 little-endian bytes: three
/// 8-byte base coefficients, low coordinate first. A short input is zero-padded;
/// bytes beyond the 24th are ignored.
///
/// Each coefficient must be canonical (`< GOLDILOCKS_MODULUS`); the debug
/// assertion catches non-canonical limbs, which `from_le_bytes_mod_order` would
/// otherwise silently alias to a canonical value (the `2^32 − 1` encodings in
/// `[p, 2^64)`). This must become a hard rejection before the function ever
/// sits on a real (non-test) deserialization path.
#[inline]
pub(crate) fn bytes_to_field(bytes: &[u8]) -> Field64_3 {
    let mut buf = [0u8; EXT_BYTES];
    let n = bytes.len().min(EXT_BYTES);
    buf[..n].copy_from_slice(&bytes[..n]);
    let limb = |chunk: &[u8]| {
        let value = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        debug_assert!(
            value < GOLDILOCKS_MODULUS,
            "non-canonical Goldilocks limb: {value} >= modulus"
        );
        Field64::from_le_bytes_mod_order(chunk)
    };
    Field64_3::new(limb(&buf[0..8]), limb(&buf[8..16]), limb(&buf[16..24]))
}
