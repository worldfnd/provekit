//! Poseidon2 duplex sponge for Fiat-Shamir.
//!
//! spongefish's [`DuplexSponge`] works over a byte alphabet (`type U = u8`)
//! to match [`crate::TranscriptSponge`]; Poseidon2 natively operates over
//! `[Fr; 4]`. [`Poseidon2Wrapper`] bridges the two: each 32-byte chunk is
//! decoded as a little-endian integer mod the BN254 prime, permuted, and
//! re-encoded via canonical LE bytes. Between permutations the state is
//! always canonical, so the reduction is a no-op.
//!
//! # Canonical-lane invariant
//!
//! [`crate::bytes::bytes_to_field`] is `from_le_bytes_mod_order`, which
//! reduces each 32-byte lane mod p. This adapter is therefore only
//! **byte-injective** when every absorbed lane is already < p. spongefish
//! writes raw bytes straight into `permutation_state` (see
//! `duplex_sponge.rs:197-213`), and the domain separator absorbs arbitrary
//! byte strings (`protocol_id`, `session_id`, and instance bytes), so the
//! sponge layer cannot enforce canonicality on its own. In particular, the
//! transcript domain separator includes 32/64-byte hash outputs that are not
//! guaranteed to be canonical field encodings, so this adapter is lossy for
//! part of the transcript state today. Prover and verifier still agree
//! because they apply the same reduction, but issue #419 tracks replacing
//! this with an injective byte-to-field transcript adapter.
//! [`crate::skyscraper::SkyscraperSponge`] shares the same adapter
//! (`bytes_to_field` / `field_to_bytes_le`) and inherits the same
//! invariant.
//!
//! Not interchangeable with [`poseidon2::poseidon2_hash`] — that is the
//! one-shot hash with a length-encoded IV (matches Noir's
//! `Poseidon2::hash()`); this is the duplex transcript sponge.

use {
    crate::bytes::{bytes_to_field, field_to_bytes_le},
    ark_bn254::Fr,
    poseidon2::permutation::poseidon2_permutation,
    spongefish::{DuplexSponge, Permutation},
};

/// Byte-oriented wrapper around the BN254 Poseidon2 permutation for use with
/// spongefish's generic [`DuplexSponge`] (state = 4 × 32-byte field elements).
#[derive(Clone, Default)]
pub struct Poseidon2Wrapper;

impl Permutation<128> for Poseidon2Wrapper {
    type U = u8;

    fn permute(&self, state: &[u8; 128]) -> [u8; 128] {
        let inputs: [Fr; 4] = std::array::from_fn(|i| bytes_to_field(&state[i * 32..(i + 1) * 32]));
        let output = poseidon2_permutation(&inputs);
        let mut out = [0u8; 128];
        for (i, fe) in output.iter().enumerate() {
            out[i * 32..(i + 1) * 32].copy_from_slice(&field_to_bytes_le(*fe));
        }
        out
    }
}

/// Poseidon2 duplex sponge: 128-byte state (4 field elements), 96-byte rate
/// (3 elements), 32-byte capacity (1 element).
pub type Poseidon2Sponge = DuplexSponge<Poseidon2Wrapper, 128, 96>;

#[cfg(test)]
mod tests {
    use {super::*, spongefish::DuplexSpongeInterface};

    /// KAT for the zero-input permutation; drift here means Poseidon2
    /// parameters diverged from the underlying `poseidon2` crate.
    #[test]
    fn permutation_matches_known_output() {
        let out = Poseidon2Wrapper.permute(&[0u8; 128]);
        // field_to_bytes_le(poseidon2_permutation([Fr::zero(); 4])[0])
        // = 0x18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E
        #[rustfmt::skip]
        let expected_lane0: [u8; 32] = [
            0x2e, 0x73, 0xc6, 0x8b, 0x69, 0x5c, 0x78, 0x96,
            0xb4, 0x36, 0x42, 0x84, 0x9d, 0x6d, 0xe9, 0x1c,
            0x8b, 0xf7, 0x8d, 0xfc, 0xfe, 0x4e, 0x97, 0xff,
            0x9c, 0x22, 0x82, 0x9b, 0xdc, 0xb8, 0xdf, 0x18,
        ];
        assert_eq!(&out[..32], &expected_lane0);
    }

    #[test]
    fn absorb_squeeze_roundtrip() {
        let mut sponge = Poseidon2Sponge::default();
        sponge.absorb(&[42u8; 96]);
        let mut output = [0u8; 32];
        sponge.squeeze(&mut output);
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
        assert_ne!(o1, o2);
    }

    #[test]
    fn deterministic() {
        let run = || {
            let mut s = Poseidon2Sponge::default();
            s.absorb(&[0xde, 0xad, 0xbe, 0xef]);
            let mut o = [0u8; 32];
            s.squeeze(&mut o);
            o
        };
        assert_eq!(run(), run());
    }
}
