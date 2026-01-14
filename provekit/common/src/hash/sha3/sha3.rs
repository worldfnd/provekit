use {
    crate::hash::{CompressionScheme, HashScheme, PermutationScheme, PowScheme},
    ark_bn254::Fr,
    ark_ff::PrimeField,
    serde::{Deserialize, Serialize},
    sha3::{Digest, Sha3_256},
    std::cell::RefCell,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha3;

thread_local! {
    static SHA3_HASHER: RefCell<Sha3_256> = RefCell::new(Sha3_256::new());
}

impl CompressionScheme for Sha3 {
    fn compress(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        SHA3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            // Zero-copy conversion using transmute
            let left_bytes: [u8; 32] = unsafe { std::mem::transmute(left) };
            let right_bytes: [u8; 32] = unsafe { std::mem::transmute(right) };

            hasher.update(left_bytes);
            hasher.update(right_bytes);

            let result = hasher.finalize_reset();
            let bytes: [u8; 32] = result.into();

            [
                u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
                u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
                u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            ]
        })
    }
}

impl PermutationScheme for Sha3 {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr) {
        SHA3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            // Hash Left
            for limb in l.into_bigint().0.iter() {
                hasher.update(limb.to_le_bytes());
            }
            let res_l = hasher.finalize_reset();

            // Hash Right
            for limb in r.into_bigint().0.iter() {
                hasher.update(limb.to_le_bytes());
            }
            let res_r = hasher.finalize_reset();

            let l_fr = Fr::from_be_bytes_mod_order(&res_l);
            let r_fr = Fr::from_be_bytes_mod_order(&res_r);

            (l_fr, r_fr)
        })
    }
}

impl PowScheme for Sha3 {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool {
        SHA3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            let challenge_bytes: [u8; 32] = unsafe { std::mem::transmute(challenge) };
            hasher.update(challenge_bytes);
            hasher.update(nonce.to_le_bytes());

            let result = hasher.finalize_reset();
            let difficulty = 1u128 << (128 - bits as u32);

            let mut first_16 = [0u8; 16];
            first_16.copy_from_slice(&result[..16]);
            let hash_val = u128::from_le_bytes(first_16);

            hash_val < difficulty
        })
    }

    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64> {
        let difficulty = 1u128 << (128 - bits as u32);
        let challenge_bytes: [u8; 32] = unsafe { std::mem::transmute(challenge) };

        SHA3_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            for nonce in 0..u64::MAX {
                hasher.update(challenge_bytes);
                hasher.update(nonce.to_le_bytes());

                let result = hasher.finalize_reset();

                let mut first_16 = [0u8; 16];
                first_16.copy_from_slice(&result[..16]);
                let hash_val = u128::from_le_bytes(first_16);

                if hash_val < difficulty {
                    return Some(nonce);
                }
            }
            None
        })
    }
}

impl HashScheme for Sha3 {}
