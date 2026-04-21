//! Poseidon2 duplex sponge for use as a Fiat-Shamir transcript.
//!
//! # Design: byte-bridge pattern
//!
//! The spongefish [`DuplexSponge`] interface operates over a byte alphabet
//! (`type U = u8`), matching the existing [`TranscriptSponge`] abstraction.
//! The Poseidon2 permutation natively operates over `[Fr; 4]`.
//!
//! [`Poseidon2Wrapper`] bridges the two: it interprets a 128-byte state as
//! four BN254 field elements, applies the permutation, and converts back.
//! In a Noir recursive circuit the byte↔field conversion is free (bit
//! reinterpretation), so this adds no constraint overhead vs a native
//! field-element sponge.
//!
//! # Important: two distinct Poseidon2 modes
//!
//! - **This sponge** (`Poseidon2Sponge`): duplex mode, absorb/squeeze
//!   interleaved. Used for the Fiat-Shamir transcript.
//! - **`poseidon2::hash::poseidon2_hash`**: one-shot mode with a length IV.
//!   Used for public input hashing (matches Noir's `Poseidon2::hash()`).
//!
//! Do NOT substitute one for the other — the IV encoding makes them produce
//! different outputs.

use {
    crate::utils::{bytes_to_field, field_to_bytes_le},
    ark_bn254::Fr,
    poseidon2::permutation::poseidon2_permutation,
    spongefish::{DuplexSponge, Permutation},
};

// ============================================================================
// Permutation wrapper
// ============================================================================

/// Byte-oriented wrapper around the BN254 Poseidon2 permutation.
///
/// Implements [`Permutation<128>`] (state = 4 × 32-byte field elements) so
/// that it can be used with spongefish's generic [`DuplexSponge`].
#[derive(Clone, Default)]
pub struct Poseidon2Wrapper;

impl Permutation<128> for Poseidon2Wrapper {
    type U = u8;

    fn permute(&self, state: &[u8; 128]) -> [u8; 128] {
        // Convert 128 bytes → four BN254 field elements
        let inputs: [Fr; 4] = std::array::from_fn(|i| bytes_to_field(&state[i * 32..(i + 1) * 32]));

        let output = poseidon2_permutation(&inputs);

        // Convert four field elements → 128 bytes
        let mut out = [0u8; 128];
        for (i, fe) in output.iter().enumerate() {
            out[i * 32..(i + 1) * 32].copy_from_slice(&field_to_bytes_le(*fe));
        }
        out
    }
}

// ============================================================================
// Sponge type alias
// ============================================================================

/// Poseidon2 duplex sponge.
///
/// - State width: 128 bytes = 4 × 32-byte BN254 field elements
/// - Rate:        96 bytes  = 3 field elements
/// - Capacity:    32 bytes  = 1 field element
pub type Poseidon2Sponge = DuplexSponge<Poseidon2Wrapper, 128, 96>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use {super::*, spongefish::DuplexSpongeInterface};

    /// Smoke test: verify the zero-input permutation output matches the known
    /// value from `poseidon2/src/permutation.rs`. Guards against any parameter
    /// drift between the sponge wrapper and the underlying permutation.
    ///
    /// Lane 0 canonical value:
    /// `18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E`
    /// Encoded as 4 × u64 LE limbs → 32 bytes.
    #[test]
    fn permutation_matches_known_output() {
        let wrapper = Poseidon2Wrapper;
        let state = [0u8; 128]; // four zero field elements
        let out = wrapper.permute(&state);

        // field_to_bytes_le(poseidon2_permutation([Fr::zero(); 4])[0])
        // Canonical integer:
        // 0x18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E
        // Stored as limbs[0..4] (LE), each limb in little-endian bytes:
        //   limb[0]=0x96785C698BC6732E  limb[1]=0x1CE96D9D844236B4
        //   limb[2]=0xFF974EFEFC8DF78B  limb[3]=0x18DFB8DC9B82229C
        #[rustfmt::skip]
        let expected_lane0: [u8; 32] = [
            0x2e, 0x73, 0xc6, 0x8b, 0x69, 0x5c, 0x78, 0x96,
            0xb4, 0x36, 0x42, 0x84, 0x9d, 0x6d, 0xe9, 0x1c,
            0x8b, 0xf7, 0x8d, 0xfc, 0xfe, 0x4e, 0x97, 0xff,
            0x9c, 0x22, 0x82, 0x9b, 0xdc, 0xb8, 0xdf, 0x18,
        ];

        assert_eq!(
            &out[..32],
            &expected_lane0,
            "Lane 0 mismatch — poseidon2 parameters may have drifted"
        );
    }

    #[test]
    fn absorb_squeeze_roundtrip() {
        let mut sponge = Poseidon2Sponge::default();

        // Absorb some bytes and squeeze — should not panic
        let input = [42u8; 96]; // exactly one rate block
        sponge.absorb(&input);

        let mut output = [0u8; 32];
        sponge.squeeze(&mut output);

        // Output should be non-zero after absorbing non-trivial input
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn two_absorb_sequences_differ() {
        let mut s1 = Poseidon2Sponge::default();
        let mut s2 = Poseidon2Sponge::default();

        s1.absorb(&[1u8; 32]);
        s2.absorb(&[2u8; 32]);

        let mut o1 = [0u8; 32];
        let mut o2 = [0u8; 32];
        s1.squeeze(&mut o1);
        s2.squeeze(&mut o2);

        assert_ne!(o1, o2, "Different inputs must produce different outputs");
    }

    #[test]
    fn deterministic() {
        let absorb_val = [0xde, 0xad, 0xbe, 0xef];

        let output1 = {
            let mut s = Poseidon2Sponge::default();
            s.absorb(&absorb_val);
            let mut o = [0u8; 32];
            s.squeeze(&mut o);
            o
        };

        let output2 = {
            let mut s = Poseidon2Sponge::default();
            s.absorb(&absorb_val);
            let mut o = [0u8; 32];
            s.squeeze(&mut o);
            o
        };

        assert_eq!(output1, output2);
    }
}
