#![cfg(feature = "icicle")]
use {
    crate::{SmolHasher, HASHES},
    icicle_core::hash::{HashConfig, Hasher},
    icicle_hash::blake2s::Blake2s,
    icicle_runtime::memory::HostSlice,
    linkme::distributed_slice,
    std::fmt::Display,
};

#[allow(unsafe_code)] // Squelch the warning about using link_section
#[distributed_slice(HASHES)]
static HASH: fn() -> Box<dyn SmolHasher> = || Box::new(Blake2Icicle::new());

pub struct Blake2Icicle {
    hasher: Hasher,
}

impl Display for Blake2Icicle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("blake2s-icicle")
    }
}

impl Blake2Icicle {
    pub fn new() -> Self {
        let hasher = Blake2s::new(0).unwrap();
        assert_eq!(hasher.output_size(), 32);
        Self { hasher }
    }
}

impl SmolHasher for Blake2Icicle {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        // Batch size is infered from output size
        self.hasher
            .hash(
                HostSlice::from_slice(messages),
                &HashConfig::default(),
                HostSlice::from_mut_slice(hashes),
            )
            .unwrap();
    }
}
