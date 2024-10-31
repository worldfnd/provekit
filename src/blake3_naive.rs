use {crate::SmolHasher, std::fmt::Display};

pub struct Blake3Naive;

impl Display for Blake3Naive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blake3-naive")
    }
}

impl SmolHasher for Blake3Naive {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let result = blake3::hash(message);
            hash.copy_from_slice(result.as_bytes());
        }
    }
}
