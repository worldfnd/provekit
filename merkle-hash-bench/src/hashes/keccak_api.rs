use {
    crate::{register_hash, HashFn, SmolHasher},
    sha3::{Digest, Sha3_256},
};

register_hash!(KeccakApi);

pub struct KeccakApi;

impl SmolHasher for KeccakApi {
    fn hash_fn(&self) -> HashFn {
        HashFn::Keccak(24)
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let mut hasher = Sha3_256::new();
            hasher.update(message);
            let result = hasher.finalize();
            hash.copy_from_slice(result.as_slice());
        }
    }
}
