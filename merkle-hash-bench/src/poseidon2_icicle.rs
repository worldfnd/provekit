use {
    crate::SmolHasher,
    icicle_bn254::curve::ScalarField,
    icicle_core::{
        hash::{HashConfig, Hasher},
        poseidon2::create_poseidon2_hasher,
    },
    icicle_runtime::memory::HostSlice,
    std::fmt::Display,
};

pub struct PoseidonIcicle {
    hasher: Hasher,
}

impl Display for PoseidonIcicle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("poseidon2-bn254-icicle")
    }
}

impl PoseidonIcicle {
    pub fn new() -> Self {
        let hasher = create_poseidon2_hasher::<ScalarField>(3, None).unwrap();
        assert_eq!(hasher.output_size(), 32);
        Self { hasher }
    }
}

impl SmolHasher for PoseidonIcicle {
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
