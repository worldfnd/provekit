use {
    crate::hash::{CompressionScheme, HashScheme, PermutationScheme, PowScheme},
    ark_bn254::Fr,
    ark_ff::PrimeField,
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{cell::RefCell, mem::transmute},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha2;

thread_local! {
    static SHA2_HASHER: RefCell<Sha256> = RefCell::new(Sha256::new());
}

impl CompressionScheme for Sha2 {
    fn compress(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        SHA2_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            for limb in &left {
                hasher.update(limb.to_le_bytes());
            }
            for limb in &right {
                hasher.update(limb.to_le_bytes());
            }

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

impl PermutationScheme for Sha2 {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr) {
        SHA2_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            fn fr_to_bytes(f: Fr) -> Vec<u8> {
                let mut bytes = Vec::new();
                for limb in f.into_bigint().0.iter() {
                    bytes.extend_from_slice(&limb.to_le_bytes());
                }
                bytes
            }
            hasher.update(fr_to_bytes(l));
            let hash_l = hasher.finalize_reset();

            hasher.update(fr_to_bytes(r));
            let hash_r = hasher.finalize_reset();

            let l_fr = Fr::from_be_bytes_mod_order(hash_l.as_slice());
            let r_fr = Fr::from_be_bytes_mod_order(hash_r.as_slice());

            (l_fr, r_fr)
        })
    }
}

impl PowScheme for Sha2 {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool {
        SHA2_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            let challenge_bytes: [u8; 32] = unsafe { transmute(challenge) };
            hasher.update(challenge_bytes);
            hasher.update(nonce.to_le_bytes());

            let result = hasher.finalize_reset();
            let difficulty = 1u128 << (128 - bits as u32);

            let mut first_16_bytes = [0u8; 16];
            first_16_bytes.copy_from_slice(&result[..16]);
            let hash_val = u128::from_le_bytes(first_16_bytes);

            hash_val < difficulty
        })
    }

    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64> {
        let difficulty = 1u128 << (128 - bits as u32);
        let challenge_bytes: [u8; 32] = unsafe { transmute(challenge) };

        SHA2_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            for nonce in 0..u64::MAX {
                hasher.update(challenge_bytes);
                hasher.update(nonce.to_le_bytes());

                let result = hasher.finalize_reset();

                // Fast u128 extraction without try_into().unwrap()
                let mut first_16_bytes = [0u8; 16];
                first_16_bytes.copy_from_slice(&result[..16]);
                let hash_val = u128::from_le_bytes(first_16_bytes);

                if hash_val < difficulty {
                    return Some(nonce);
                }
            }
            None
        })
    }
}

impl HashScheme for Sha2 {}
