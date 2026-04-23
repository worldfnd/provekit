//! Poseidon2 sponge hash for BN254, matching Noir's stdlib implementation.
//!
//! Sponge parameters: width=4, rate=3, capacity=1 over BN254's scalar field.

use {
    crate::permutation::poseidon2_permute_in_place,
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    ark_std::Zero,
    std::sync::LazyLock,
};

const RATE: usize = 3;

static TWO_POW_64: LazyLock<Fr> = LazyLock::new(|| Fr::from(1u64 << 32) * Fr::from(1u64 << 32));

/// Poseidon2 sponge hash matching Noir's `Poseidon2::hash(inputs, len)`.
///
/// Sponge parameters: width=4, rate=3, capacity=1.
/// IV = message_length * 2^64, placed in `state[3]` (capacity lane).
pub fn poseidon2_hash(inputs: &[Fr]) -> Fr {
    let msg_len = inputs.len();
    let iv = Fr::from(msg_len as u64) * *TWO_POW_64;
    let zero = Fr::zero();

    let mut state: [Fr; 4] = [zero, zero, zero, iv];
    let mut cache: [Fr; RATE] = [zero; RATE];
    let mut cache_size: usize = 0;

    for &input in inputs {
        if cache_size == RATE {
            // Perform duplex: add cache into state, permute
            for i in 0..RATE {
                state[i] += cache[i];
            }
            cache = [zero; RATE];
            cache_size = 0;
            poseidon2_permute_in_place(&mut state);
        }
        cache[cache_size] = input;
        cache_size += 1;
    }

    // Final squeeze: add remaining cache into state, permute
    for i in 0..cache_size {
        state[i] += cache[i];
    }
    poseidon2_permute_in_place(&mut state);

    state[0]
}

/// Byte-oriented variant of [`poseidon2_hash`]. `msg` is `num_fes` canonical
/// 32-byte little-endian field elements concatenated; output is `state[0]`
/// serialized to 32 canonical LE bytes.
///
/// Semantically equivalent to
/// `field_to_bytes_le(poseidon2_hash(decode(msg, num_fes)))` for all
/// `num_fes >= 1`. For `num_fes = 0` this skips the final permutation and
/// returns `[0u8; 32]`, whereas [`poseidon2_hash`] over an empty slice runs
/// one permutation and returns a non-zero digest. The divergence is
/// intentional: the only caller (WHIR's Poseidon2 Merkle engine) rejects
/// zero-length messages at its `supports_size` gate, so the byte variant
/// never sees `num_fes = 0`.
///
/// Each 32-byte lane is decoded with `from_le_bytes_mod_order`, so inputs
/// must be canonical (< p) for the function to be byte-injective. WHIR
/// Merkle inputs are always engine outputs or canonical field encodings, so
/// this holds in practice — but nothing in the type system enforces it.
pub fn poseidon2_hash_bytes(msg: &[u8], num_fes: usize) -> [u8; 32] {
    let expected_len = num_fes
        .checked_mul(32)
        .expect("poseidon2_hash_bytes: num_fes overflow");
    assert_eq!(
        msg.len(),
        expected_len,
        "poseidon2_hash_bytes: msg length {} != num_fes {num_fes} * 32",
        msg.len()
    );

    let iv = Fr::from(num_fes as u64) * *TWO_POW_64;
    let mut state = [Fr::zero(), Fr::zero(), Fr::zero(), iv];

    let mut absorbed = 0;
    while absorbed < num_fes {
        let batch = (num_fes - absorbed).min(RATE);
        for j in 0..batch {
            let fe_bytes = &msg[(absorbed + j) * 32..(absorbed + j + 1) * 32];
            state[j] += decode_canonical_fr(fe_bytes);
        }
        poseidon2_permute_in_place(&mut state);
        absorbed += batch;
    }

    // Canonical LE serialization without routing through `BigInt::to_bytes_le`'s
    // `Vec<u8>`: copy the 4 limbs of `state[0].into_bigint()` straight out.
    let limbs = state[0].into_bigint().0;
    let mut out = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Decode a canonical 32-byte little-endian BN254 field element without
/// heap allocations.
///
/// Required precondition: `bytes` encodes an integer `< p` — this is part of
/// the `poseidon2_hash_bytes` contract (inputs are canonical encodings of
/// field elements produced by `field_to_bytes_le` or engine outputs). The
/// reduction is therefore a no-op on contract-respecting input, and we skip
/// the allocating `Fr::from_le_bytes_mod_order` fast path. Calling with a
/// non-canonical 32-byte value is a contract violation and yields an `Fr`
/// whose internal representation is `>= p`, which ark-ff's MontBackend
/// arithmetic does not guarantee to handle correctly.
#[inline]
fn decode_canonical_fr(bytes: &[u8]) -> Fr {
    debug_assert_eq!(bytes.len(), 32);
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Fr::new(BigInt(limbs))
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::fe};

    #[test]
    fn test_poseidon2_hash_single_element() {
        // From Noir test: Poseidon2::hash([1], 1)
        let inputs = [Fr::from(1u64)];
        let result = poseidon2_hash(&inputs);
        let expected = fe("0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373");
        assert_eq!(result, expected, "Poseidon2::hash([1], 1) mismatch");
    }

    #[test]
    fn test_poseidon2_hash_two_elements() {
        // From Noir test: Poseidon2::hash([e, e], 2) where e = hash([1], 1)
        let e = fe("0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373");
        let inputs = [e, e];
        let result = poseidon2_hash(&inputs);
        let expected = fe("0x113d8ff59c2e15d711241797c380264e39dc1b9e00f2713e707d8d7773b6d912");
        assert_eq!(result, expected, "Poseidon2::hash([e, e], 2) mismatch");
    }

    /// Single-bit avalanche at the hash level (catches mid-stream state
    /// corruption that the permutation-level avalanche test would miss).
    #[test]
    fn hash_single_bit_avalanche() {
        let a = poseidon2_hash(&[Fr::from(100u64)]);
        let b = poseidon2_hash(&[Fr::from(101u64)]);
        assert_ne!(a, b);
    }

    /// Length is mixed into the IV, so the same prefix with a different
    /// length must hash to a different value. Guards the capacity-lane IV.
    #[test]
    fn length_is_domain_separated() {
        let three = poseidon2_hash(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        let six = poseidon2_hash(&[
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
        ]);
        assert_ne!(three, six);
    }

    /// Order matters.
    #[test]
    fn order_sensitive() {
        let ab = poseidon2_hash(&[Fr::from(1u64), Fr::from(2u64)]);
        let ba = poseidon2_hash(&[Fr::from(2u64), Fr::from(1u64)]);
        assert_ne!(ab, ba);
    }

    /// Byte-oriented variant must match the field-oriented variant for all
    /// non-zero input lengths. (The two diverge at `num_fes = 0` by design;
    /// see `poseidon2_hash_bytes` doc.)
    #[test]
    fn byte_variant_matches_field_variant() {
        // Local canonical-limb serializer, mirroring the production path in
        // `poseidon2_hash_bytes` / `utils::field_to_bytes_le`.
        fn fe_to_bytes(fe: Fr) -> [u8; 32] {
            let limbs = fe.into_bigint().0;
            let mut out = [0u8; 32];
            for (i, &limb) in limbs.iter().enumerate() {
                out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
            }
            out
        }

        for n in 1..=10usize {
            let fes: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            let msg: Vec<u8> = fes.iter().flat_map(|f| fe_to_bytes(*f)).collect();

            let field_out = poseidon2_hash(&fes);
            let byte_out = poseidon2_hash_bytes(&msg, n);

            assert_eq!(
                byte_out,
                fe_to_bytes(field_out),
                "byte/field variant divergence at num_fes={n}"
            );
        }
    }
}
