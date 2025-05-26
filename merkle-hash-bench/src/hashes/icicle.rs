#![cfg(feature = "icicle")]
use {
    crate::{register_hash, Field, HashFn, SmolHasher},
    icicle_bn254::curve::ScalarField as Bn254,
    icicle_core::{
        hash::{HashConfig, Hasher},
        poseidon::create_poseidon_hasher,
        poseidon2::create_poseidon2_hasher,
    },
    icicle_hash::{blake2s::Blake2s, keccak::Keccak256},
    icicle_runtime::memory::HostSlice,
};

register_hash!(Icicle {
    hash_fn: HashFn::Keccak(24),
    field:   Field::None,
    hasher:  Keccak256::new(64).unwrap(),
});

register_hash!(Icicle {
    hash_fn: HashFn::Blake2s,
    field:   Field::None,
    hasher:  Blake2s::new(64).unwrap(),
});

register_hash!(Icicle {
    hash_fn: HashFn::Poseidon(3),
    field:   Field::Bn254,
    hasher:  create_poseidon_hasher::<Bn254>(3, None).unwrap(),
});

register_hash!(Icicle {
    hash_fn: HashFn::Poseidon2(2),
    field:   Field::Bn254,
    hasher:  create_poseidon2_hasher::<Bn254>(2, None).unwrap(),
});

register_hash!(Icicle {
    hash_fn: HashFn::Poseidon2(3),
    field:   Field::Bn254,
    hasher:  create_poseidon2_hasher::<Bn254>(3, None).unwrap(),
});

// register_hash!(Icicle {
//     hash_fn: HashFn::Poseidon2(16),
//     field:   Field::M31,
//     hasher:  create_poseidon2_hasher::<M31>(16, None).unwrap(),
// });

pub struct Icicle {
    hash_fn: HashFn,
    field:   Field,
    hasher:  Hasher,
}

impl SmolHasher for Icicle {
    fn hash_fn(&self) -> HashFn {
        self.hash_fn
    }

    fn implementation(&self) -> &str {
        "icicle"
    }

    fn field(&self) -> Field {
        self.field
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        // Batch size is infered from output size
        // assert_eq!(self.hasher.output_size(), 32);
        if matches!(self.hash_fn, HashFn::Poseidon(3) | HashFn::Poseidon2(3)) {
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
        } else {
            self.hasher
                .hash(
                    HostSlice::from_slice(messages),
                    &HashConfig::default(),
                    HostSlice::from_mut_slice(hashes),
                )
                .unwrap();
        }
    }
}
