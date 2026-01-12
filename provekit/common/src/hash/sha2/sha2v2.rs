use {
    crate::hash::{CompressionScheme, PermutationScheme, PowScheme},
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    sha2::{Sha256, Digest},
    zerocopy::transmute,
};
use std::cell::RefCell;

// gemini generated. will bench which one faster later

#[derive(Clone)]
pub struct Sha2;

thread_local! {
    static SHA2_HASHER: RefCell<Sha256> = RefCell::new(Sha256::new());
}

impl CompressionScheme for Sha2 {
    fn compress(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        SHA2_HASHER.with(|hasher_cell| {
            let mut hasher = hasher_cell.borrow_mut();

            hasher.update(unsafe { transmute!(left) });
            hasher.update(unsafe { transmute!(right) });
            
            let result = hasher.finalize_reset();
            
            let mut output = [0u64; 4];
            output.copy_from_slice(unsafe { &transmute!(result.into()) });
            output
        })
    }
}

impl PermutationScheme for Sha2 {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr) {
        let mut hasher = Sha256::new();
        
        hasher.update(l.into_bigint().to_bytes_le());
        hasher.update(r.into_bigint().to_bytes_le());
        
        let result = hasher.finalize();
        let (l_bytes, r_bytes) = result.split_at(16);
        
        let l_out = Fr::from_le_bytes_mod_order(l_bytes);
        let r_out = Fr::from_le_bytes_mod_order(r_bytes);
        
        (l_out, r_out)
    }
}

impl PowScheme for Sha2 {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool {
        let mut hasher = Sha256::new();
        let challenge_bytes: [u8; 32] = unsafe { transmute!(challenge) };
        
        hasher.update(challenge_bytes);
        hasher.update(nonce.to_le_bytes());
        
        let result = hasher.finalize();
        
        let difficulty = (1u128 << (128 - bits as u32));
        let hash_val = u128::from_le_bytes(result[0..16].try_into().unwrap());
        hash_val < difficulty
    }

    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64> {
        let mut nonce = 0u64;
        loop {
            if Self::check(challenge, bits, nonce) {
                return Some(nonce);
            }
            nonce += 1;
            if nonce == u64::MAX { return None; }
        }
    }
}