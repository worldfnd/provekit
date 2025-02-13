#![cfg(feature = "icicle")]
use {
    crate::{register_hash, SmolHasher},
    icicle_bn254::curve::ScalarField,
    icicle_core::{
        hash::{HashConfig, Hasher},
        poseidon2::create_poseidon2_hasher,
    },
    icicle_runtime::memory::HostSlice,
    std::fmt::Display,
};

register_hash!(Poseidon2T2Icicle::new());

pub struct Poseidon2T2Icicle {
    hasher: Hasher,
}

impl Display for Poseidon2T2Icicle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("poseidon2-t2-icicle")
    }
}

impl Poseidon2T2Icicle {
    pub fn new() -> Self {
        let hasher = create_poseidon2_hasher::<ScalarField>(2, None).unwrap();
        assert_eq!(hasher.output_size(), 32);
        Self { hasher }
    }
}

impl SmolHasher for Poseidon2T2Icicle {
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
