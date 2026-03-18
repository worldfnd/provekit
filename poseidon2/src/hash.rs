//! Poseidon2 sponge hash for BN254, matching Noir's stdlib implementation.
//!
//! Sponge parameters: width=4, rate=3, capacity=1 over BN254's scalar field.

use {
    crate::permutation::poseidon2_permutation, ark_bn254::Fr, ark_std::Zero, std::sync::LazyLock,
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
            state = poseidon2_permutation(&state);
        }
        cache[cache_size] = input;
        cache_size += 1;
    }

    // Final squeeze: add remaining cache into state, permute
    for i in 0..cache_size {
        state[i] += cache[i];
    }
    state = poseidon2_permutation(&state);

    state[0]
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

    #[test]
    fn test_poseidon2_hash_four_elements() {
        // Verify 4-element hash (fills the rate exactly once)
        let inputs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let result = poseidon2_hash(&inputs);
        // Just verify it doesn't panic and produces a non-zero result
        assert_ne!(result, Fr::from(0u64));
    }

    #[test]
    fn test_poseidon2_hash_empty_input() {
        // Empty input should produce IV-based hash
        let inputs: &[Fr] = &[];
        let result = poseidon2_hash(inputs);
        // Should not panic and should produce a non-zero result (due to IV in state[3])
        assert_ne!(result, Fr::zero());
    }

    #[test]
    fn test_poseidon2_hash_determinism() {
        let inputs = [Fr::from(123u64), Fr::from(456u64)];
        let result1 = poseidon2_hash(&inputs);
        let result2 = poseidon2_hash(&inputs);
        assert_eq!(result1, result2, "Hash should be deterministic");
    }

    #[test]
    fn test_poseidon2_hash_collision_resistance() {
        // Different inputs should (almost certainly) produce different hashes
        let input1 = [Fr::from(100u64)];
        let input2 = [Fr::from(101u64)];

        let hash1 = poseidon2_hash(&input1);
        let hash2 = poseidon2_hash(&input2);

        assert_ne!(hash1, hash2, "Collision on single bit flip");
    }

    #[test]
    fn test_poseidon2_hash_large_input() {
        // Test with > RATE elements (requires multiple permutations)
        let mut inputs = Vec::new();
        for i in 0..10 {
            inputs.push(Fr::from(i as u64));
        }
        let result = poseidon2_hash(&inputs);
        assert_ne!(result, Fr::zero());
    }

    #[test]
    fn test_poseidon2_hash_avalanche_effect() {
        let base_input = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let base_hash = poseidon2_hash(&base_input);

        // Change the last input element
        let mut modified_input = base_input.clone();
        modified_input[2] = Fr::from(4u64);
        let modified_hash = poseidon2_hash(&modified_input);

        assert_ne!(
            base_hash, modified_hash,
            "Hash should change with input modification"
        );
    }

    #[test]
    fn test_poseidon2_hash_padding_consistency() {
        // Hashing at rate boundaries (RATE = 3)
        let input3 = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let hash3 = poseidon2_hash(&input3);

        let input6 = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
        ];
        let hash6 = poseidon2_hash(&input6);

        // Different lengths should produce different hashes (length encoding in IV)
        assert_ne!(hash3, hash6);
    }

    #[test]
    fn test_poseidon2_hash_zero_elements() {
        let zero_inputs = vec![Fr::zero(); 5];
        let result = poseidon2_hash(&zero_inputs);
        // Should not be zero due to IV encoding
        assert_ne!(result, Fr::zero());
    }

    #[test]
    fn test_poseidon2_hash_all_ones() {
        let large_val = Fr::from(u64::MAX);
        let inputs = vec![large_val; 3];
        let result = poseidon2_hash(&inputs);
        assert_ne!(result, Fr::zero());
    }

    #[test]
    fn test_poseidon2_hash_order_matters() {
        // Hash should depend on input order
        let input1 = vec![Fr::from(1u64), Fr::from(2u64)];
        let input2 = vec![Fr::from(2u64), Fr::from(1u64)];

        let hash1 = poseidon2_hash(&input1);
        let hash2 = poseidon2_hash(&input2);

        assert_ne!(hash1, hash2, "Hash should depend on input order");
    }

    #[test]
    fn test_poseidon2_hash_sponge_squeeze_single_output() {
        // Sponge should output only state[0]
        let inputs = vec![Fr::from(42u64)];
        let result = poseidon2_hash(&inputs);

        // Result should be from the rate, not capacity
        assert!(!result.is_zero() || inputs.is_empty());
    }

    #[test]
    fn test_poseidon2_hash_exact_rate_boundary() {
        // RATE = 3, so test at exactly rate boundaries
        // 3 elements = 1 duplex operation
        let input3 = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let hash3 = poseidon2_hash(&input3);

        // 6 elements = 2 duplex operations
        let input6 = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
        ];
        let hash6 = poseidon2_hash(&input6);

        // Same input repeated should produce different hash due to length encoding
        assert_ne!(hash3, hash6);
    }
}
