use {
    crate::hash::{CompressionScheme, PermutationScheme, PowScheme},
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    sha2::{Digest, Sha256},
};

#[derive(Clone)]
pub struct Sha2;

impl CompressionScheme for Sha2 {
    fn compress(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        let mut hasher = Sha256::new();

        for limb in &left {
            hasher.update(limb.to_le_bytes());
        }
        for limb in &right {
            hasher.update(limb.to_le_bytes());
        }

        let result = hasher.finalize();
        let bytes = result.as_slice();

        [
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        ]
    }
}

impl PermutationScheme for Sha2 {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr) {
        fn fr_to_bytes(f: Fr) -> Vec<u8> {
            let mut bytes = Vec::new();
            for limb in f.into_bigint().0.iter() {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
            bytes
        }

        let mut hasher = Sha256::new();
        hasher.update(fr_to_bytes(l));
        let hash_l = hasher.finalize_reset();

        hasher.update(fr_to_bytes(r));
        let hash_r = hasher.finalize();

        let l_fr = Fr::from_be_bytes_mod_order(hash_l.as_slice());
        let r_fr = Fr::from_be_bytes_mod_order(hash_r.as_slice());

        (l_fr, r_fr)
    }
}

impl PowScheme for Sha2 {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");

        let mut hasher = Sha256::new();
        for limb in &challenge {
            hasher.update(limb.to_le_bytes());
        }
        hasher.update(nonce.to_le_bytes());

        let result = hasher.finalize();
        let leading_zeros = result[0].leading_zeros() as f64;

        leading_zeros >= bits
    }

    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64> {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");

        for nonce in 0u64..u64::MAX {
            if Self::check(challenge, bits, nonce) {
                return Some(nonce);
            }
        }
        None
    }
}
