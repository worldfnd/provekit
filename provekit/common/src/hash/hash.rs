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

pub trait HashScheme:
    PowScheme
    + PermutationScheme
    + CompressionScheme
    + PartialEq
    + Serialize
    + for<'de> serde::Deserialize<'de>
{
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", from = "u8")]
pub enum HashType {
    #[default]
    Skyscraper,
    Sha2,
    Sha3,
    Blake3
}

impl From<HashType> for u8 {
    fn from(t: HashType) -> Self {
        t as u8
    }
}

impl From<u8> for HashType {
    fn from(v: u8) -> Self {
        match v {
            0 => HashType::Skyscraper,
            1 => HashType::Sha2,
            2 => HashType::Sha3,
            3 => HashType::Blake3,
            _ => HashType::Skyscraper,
        }
    }
}

impl HashType {
    pub fn from_str(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "skyscraper" => HashType::Skyscraper,
            "Skyscraper" => HashType::Skyscraper,
            "sha2" => HashType::Sha2,
            "sha" => HashType::Sha2,
            "sha3" => HashType::Sha3,
            "blake3" => HashType::Blake3,
            "blake" => HashType::Blake3,
            _ => HashType::Skyscraper,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            HashType::Skyscraper => "Skyscraper".to_string(),
            HashType::Sha2 => "SHA2".to_string(),
            HashType::Sha3 => "SHA3".to_string(),
            HashType::Blake3 => "BLAKE3".to_string(),
        }
    }
}
