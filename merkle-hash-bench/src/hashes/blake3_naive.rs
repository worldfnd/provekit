use crate::{register_hash, HashFn, SmolHasher};

register_hash!(Blake3Naive);

pub struct Blake3Naive;

impl SmolHasher for Blake3Naive {
    fn hash_fn(&self) -> HashFn {
        HashFn::Blake3
    }

    fn implementation(&self) -> &str {
        "crate"
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let result = blake3::hash(message);
            hash.copy_from_slice(result.as_bytes());
        }
    }
}
