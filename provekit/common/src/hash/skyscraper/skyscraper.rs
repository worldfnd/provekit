use {
    crate::hash::{CompressionScheme, HashScheme, PermutationScheme, PowScheme},
    ark_bn254::Fr,
    serde::{Deserialize, Serialize},
    skyscraper::{
        pow::{solve, verify},
        reference::permute,
        simple::compress,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skyscraper;

impl CompressionScheme for Skyscraper {
    fn compress(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
        compress(left, right)
    }
}

impl PermutationScheme for Skyscraper {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr) {
        permute(l, r)
    }
}

impl PowScheme for Skyscraper {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool {
        verify(challenge, bits, nonce)
    }

    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64> {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Some(solve(challenge, bits))
    }
}

impl HashScheme for Skyscraper {}
