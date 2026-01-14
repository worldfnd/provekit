use {
    crate::hash::{CompressionScheme, HashScheme, PermutationScheme, PowScheme},
    ark_bn254::Fr,
    ark_ff::PrimeField,
    blake3::Hasher,
    serde::{Deserialize, Serialize},
    std::cell::RefCell,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3;

thread_local! {
    static BLAKE3_HASHER: RefCell<Hasher> = RefCell::new(Hasher::new());
}

impl CompressionScheme for Blake3 {
    fn compress(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        BLAKE3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();
            hasher.reset();

            let left_bytes: [u8; 32] = unsafe { std::mem::transmute(left) };
            let right_bytes: [u8; 32] = unsafe { std::mem::transmute(right) };

            hasher.update(&left_bytes);
            hasher.update(&right_bytes);

            let result = hasher.finalize();
            let mut output = [0u64; 4];

            // Reinterpret the 32-byte hash as 4 u64s
            unsafe {
                std::ptr::copy_nonoverlapping(
                    result.as_bytes().as_ptr(),
                    output.as_mut_ptr() as *mut u8,
                    32,
                );
            }
            output
        })
    }
}

impl PermutationScheme for Blake3 {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr) {
        BLAKE3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            // Hash Left
            hasher.reset();
            for limb in l.into_bigint().0.iter() {
                hasher.update(&limb.to_le_bytes());
            }
            let res_l = hasher.finalize();

            // Hash Right
            hasher.reset();
            for limb in r.into_bigint().0.iter() {
                hasher.update(&limb.to_le_bytes());
            }
            let res_r = hasher.finalize();

            let l_fr = Fr::from_be_bytes_mod_order(res_l.as_bytes());
            let r_fr = Fr::from_be_bytes_mod_order(res_r.as_bytes());

            (l_fr, r_fr)
        })
    }
}

impl PowScheme for Blake3 {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool {
        BLAKE3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();
            hasher.reset();

            let challenge_bytes: [u8; 32] = unsafe { std::mem::transmute(challenge) };
            hasher.update(&challenge_bytes);
            hasher.update(&nonce.to_le_bytes());

            let result = hasher.finalize();
            let result_bytes = result.as_bytes();

            let difficulty = 1u128 << (128 - bits as u32);

            let mut first_16 = [0u8; 16];
            first_16.copy_from_slice(&result_bytes[..16]);
            let hash_val = u128::from_le_bytes(first_16);

            hash_val < difficulty
        })
    }

    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64> {
        let difficulty = 1u128 << (128 - bits as u32);
        let challenge_bytes: [u8; 32] = unsafe { std::mem::transmute(challenge) };

        BLAKE3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            for nonce in 0..u64::MAX {
                hasher.reset();
                hasher.update(&challenge_bytes);
                hasher.update(&nonce.to_le_bytes());

                let result = hasher.finalize();
                let result_bytes = result.as_bytes();

                let mut first_16 = [0u8; 16];
                first_16.copy_from_slice(&result_bytes[..16]);
                let hash_val = u128::from_le_bytes(first_16);

                if hash_val < difficulty {
                    return Some(nonce);
                }
            }
            None
        })
    }
}

impl HashScheme for Blake3 {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_compression_consistency() {
        let left = [1u64, 2, 3, 4];
        let right = [5u64, 6, 7, 8];

        // Ensure hash is deterministic across multiple calls
        let hash1 = Blake3::compress(left, right);
        let hash2 = Blake3::compress(left, right);
        
        assert_eq!(hash1, hash2, "Blake3 compression must be deterministic");
        assert_ne!(hash1, [0u64; 4], "Hash result should not be trivial zero");
    }
    
    #[test]
    fn test_blake3_pow_logic() {
        let challenge = [0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00];
        let bits = 12.0; // Difficulty: 1 in 4096 nonces should pass

        // 1. Test Solving
        let nonce = Blake3::solve(challenge, bits)
            .expect("Blake3 should find a valid nonce quickly");

        // 2. Test Checking (The found nonce must pass)
        let is_valid = Blake3::check(challenge, bits, nonce);
        assert!(is_valid, "The solved nonce failed the check");

        // 3. Test Invalidity (A different nonce should fail)
        // Statistical check: highly likely to fail for 12 bits
        let is_invalid = Blake3::check(challenge, bits, nonce + 1);
        assert!(!is_invalid, "Incorrect nonce should not pass the difficulty check");
    }

    #[test]
    fn test_blake3_transmute_safety() {
        // Ensure our unsafe transmute correctly handles end-to-end data
        let input: [u64; 4] = [u64::MAX, 0, u64::MAX, 0];
        let bytes: [u8; 32] = unsafe { std::mem::transmute(input) };
        
        // On Little Endian: [255... (8 times), 0... (8 times), ...]
        assert_eq!(bytes[0], 255);
        assert_eq!(bytes[8], 0);
    }
}