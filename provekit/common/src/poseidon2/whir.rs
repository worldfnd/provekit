//! Poseidon2 WHIR hash engine for Merkle tree commitments.
//!
//! Messages are multiples of 32 bytes; each 32-byte chunk is a BN254 field
//! element absorbed into the rate portion of a 4-lane state seeded with
//! `IV = num_fes * 2^64` in the capacity lane. `state[0]` after the final
//! permutation is the 32-byte output.

use {
    crate::utils::{bytes_to_field, field_to_bytes_le},
    ark_bn254::Fr,
    ark_ff::Zero,
    poseidon2::permutation::poseidon2_permutation,
    std::{borrow::Cow, sync::LazyLock},
    whir::{
        engines::EngineId,
        hash::{Hash, HashEngine},
    },
};

/// Pre-computed `EngineId` for the Poseidon2 hash engine.
///
/// Derived as `SHA3-256("whir::hash" || "poseidon2")`.
pub const POSEIDON2: EngineId = EngineId::new([
    0xab, 0x4c, 0x81, 0x0f, 0x79, 0xdd, 0xf2, 0xa5, 0x4e, 0x81, 0x73, 0x1f, 0x97, 0x08, 0x23, 0x6a,
    0xcf, 0x5c, 0xc2, 0xcc, 0x35, 0xe9, 0xc4, 0x57, 0xa4, 0x35, 0x37, 0xdc, 0x01, 0x23, 0x6b, 0xb7,
]);

/// `2^64` as a BN254 field element; capacity-lane IV multiplier. Matches the
/// construction in [`poseidon2::poseidon2_hash`] so this engine and the
/// one-shot hash stay semantically aligned.
static TWO_POW_64: LazyLock<Fr> = LazyLock::new(|| Fr::from(1u64 << 32) * Fr::from(1u64 << 32));

/// WHIR hash engine backed by the BN254 Poseidon2 permutation; selected when
/// `HashConfig::Poseidon2` is used for Merkle commitments.
///
/// The capacity lane is seeded with `IV = num_fes * 2^64` so zero-padded
/// messages don't collide (`[A]` and `[A, 0, 0]` hash differently). Rate
/// lanes absorb up to 3 elements per permutation.
#[derive(Clone, Copy, Debug)]
pub struct Poseidon2HashEngine;

impl HashEngine for Poseidon2HashEngine {
    fn name(&self) -> Cow<'_, str> {
        "poseidon2".into()
    }

    fn supports_size(&self, size: usize) -> bool {
        size > 0 && size % 32 == 0
    }

    fn preferred_batch_size(&self) -> usize {
        4
    }

    fn hash_many(&self, size: usize, input: &[u8], output: &mut [Hash]) {
        assert!(
            self.supports_size(size),
            "poseidon2: unsupported message size {size} (must be a positive multiple of 32)"
        );

        let count = output.len();
        assert_eq!(
            input.len(),
            size * count,
            "poseidon2: input length {} != size {size} * count {count}",
            input.len()
        );

        let chunks_per_msg = size / 32;
        for (i, out_hash) in output.iter_mut().enumerate() {
            let msg = &input[i * size..(i + 1) * size];
            out_hash.0 = hash_message(msg, chunks_per_msg);
        }
    }
}

/// Sponge hash of a single `num_fes`-element message. The capacity lane is
/// pre-seeded with `IV = num_fes * 2^64` to prevent zero-padding collisions.
/// Output is `state[0]` after the final permutation.
fn hash_message(msg: &[u8], num_fes: usize) -> [u8; 32] {
    const RATE: usize = 3;
    let iv = Fr::from(num_fes as u64) * *TWO_POW_64;
    let mut state = [Fr::zero(), Fr::zero(), Fr::zero(), iv];

    let mut absorbed = 0;
    while absorbed < num_fes {
        let batch = (num_fes - absorbed).min(RATE);
        for j in 0..batch {
            let fe_bytes = &msg[(absorbed + j) * 32..(absorbed + j + 1) * 32];
            state[j] += bytes_to_field(fe_bytes);
        }
        state = poseidon2_permutation(&state);
        absorbed += batch;
    }

    field_to_bytes_le(state[0])
}

#[cfg(test)]
mod tests {
    use {super::*, whir::engines::Engine};

    #[test]
    fn engine_id_matches() {
        assert_eq!(Poseidon2HashEngine.engine_id(), POSEIDON2);
    }

    #[test]
    fn supports_expected_sizes() {
        let e = Poseidon2HashEngine;
        assert!(!e.supports_size(0));
        assert!(!e.supports_size(1));
        assert!(!e.supports_size(31));
        assert!(e.supports_size(32));
        assert!(e.supports_size(64));
        assert!(e.supports_size(96));
        assert!(e.supports_size(512));
    }

    #[test]
    fn hash_single_fe_deterministic() {
        let msg = [42u8; 32];
        let mut out1 = [Hash::default()];
        let mut out2 = [Hash::default()];
        Poseidon2HashEngine.hash_many(32, &msg, &mut out1);
        Poseidon2HashEngine.hash_many(32, &msg, &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_inputs_differ() {
        let msg_a = [1u8; 32];
        let msg_b = [2u8; 32];
        let mut out_a = [Hash::default()];
        let mut out_b = [Hash::default()];
        Poseidon2HashEngine.hash_many(32, &msg_a, &mut out_a);
        Poseidon2HashEngine.hash_many(32, &msg_b, &mut out_b);
        assert_ne!(out_a[0].0, out_b[0].0);
    }

    #[test]
    fn batch_matches_individual() {
        let data: Vec<u8> = (0..192u8).collect();
        let mut batch_out = [Hash::default(); 3];
        Poseidon2HashEngine.hash_many(64, &data, &mut batch_out);

        for i in 0..3 {
            let mut single_out = [Hash::default()];
            Poseidon2HashEngine.hash_many(64, &data[i * 64..(i + 1) * 64], &mut single_out);
            assert_eq!(batch_out[i].0, single_out[0].0);
        }
    }

    #[test]
    fn zero_input_nonzero_output() {
        let msg = [0u8; 32];
        let mut out = [Hash::default()];
        Poseidon2HashEngine.hash_many(32, &msg, &mut out);
        assert_ne!(out[0].0, [0u8; 32]);
    }

    /// Regression test for the zero-padding collision fixed by the
    /// capacity-lane IV: `[A]` and `[A, 0, 0]` must hash differently.
    #[test]
    fn zero_padding_does_not_collide() {
        let a = [42u8; 32];
        let mut a_padded = [0u8; 96];
        a_padded[..32].copy_from_slice(&a);

        let mut out_short = [Hash::default()];
        let mut out_long = [Hash::default()];
        Poseidon2HashEngine.hash_many(32, &a, &mut out_short);
        Poseidon2HashEngine.hash_many(96, &a_padded, &mut out_long);

        assert_ne!(out_short[0].0, out_long[0].0);
    }
}
