use {
    crate::{SmolHasher, HASHES},
    linkme::distributed_slice,
    sha3::{Digest, Sha3_256},
    std::fmt::Display,
};

#[allow(unsafe_code)] // Squelch the warning about using link_section
#[distributed_slice(HASHES)]
static HASH: fn() -> Box<dyn SmolHasher> = || Box::new(KeccakApi);

pub struct KeccakApi;

impl Display for KeccakApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("sha3-crate")
    }
}

impl SmolHasher for KeccakApi {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let mut hasher = Sha3_256::new();
            hasher.update(message);
            let result = hasher.finalize();
            hash.copy_from_slice(result.as_slice());
        }
    }
}
