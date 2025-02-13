#![cfg(feature = "icicle")]
use {
    crate::{SmolHasher, HASHES},
    icicle_bn254::curve::ScalarField,
    icicle_core::{
        hash::{HashConfig, Hasher},
        poseidon::create_poseidon_hasher,
    },
    icicle_runtime::memory::HostSlice,
    linkme::distributed_slice,
    std::fmt::Display,
};

#[allow(unsafe_code)] // Squelch the warning about using link_section
#[distributed_slice(HASHES)]
static HASH: fn() -> Box<dyn SmolHasher> = || Box::new(Poseidon2Icicle::new());

pub struct Poseidon2Icicle {
    hasher: Hasher,
}

impl Display for Poseidon2Icicle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("poseidon-bn254-icicle")
    }
}

impl Poseidon2Icicle {
    pub fn new() -> Self {
        let hasher = create_poseidon_hasher::<ScalarField>(3, None).unwrap();
        assert_eq!(hasher.output_size(), 32);
        Self { hasher }
    }
}

impl SmolHasher for Poseidon2Icicle {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        let config = HashConfig::default();
        let mut padded = [0u8; 96];
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            padded[0..64].copy_from_slice(message);
            self.hasher
                .hash(
                    HostSlice::from_slice(&padded),
                    &config,
                    HostSlice::from_mut_slice(hash),
                )
                .unwrap();
        }
    }
}
