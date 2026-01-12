use {
    ark_bn254::Fr,
    serde::{Deserialize, Serialize},
};

pub trait PowScheme: Clone + Send + Sync + 'static {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool;
    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64>;
}

pub trait PermutationScheme: Clone + Send + Sync + 'static {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr);
}

pub trait CompressionScheme: Clone + Send + Sync + 'static {
    fn compress(l: [u64; 4], r: [u64; 4]) -> [u64; 4];
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashType {
    #[default]
    Skyscraper,
    Sha2,
    Sha3,
    Sha2v2,
    Blake3,
}

impl HashType {
    pub fn from_str(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "skyscraper" => HashType::Skyscraper,
            "Skyscraper" => HashType::Skyscraper,
            "sha2" => HashType::Sha2,
            "sha" => HashType::Sha2,
            "sha3" => HashType::Sha3,
            "sha2v2" => HashType::Sha2v2,
            "blake3" => HashType::Blake3,
            "blake" => HashType::Blake3,
            _ => HashType::Skyscraper,
        }
    }
}
