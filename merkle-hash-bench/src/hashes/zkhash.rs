#![cfg(feature = "zkhash")]
use {
    crate::{register_hash, Field, HashFn, SmolHasher},
    bytemuck::cast,
    zkhash::{
        ff::{Field as _, PrimeField},
        fields::bn256::{FpBN256, FrRepr},
        poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
        skyscraper::{
            skyscraper::Skyscraper,
            skyscraper_instances::{BN256Ext1, SKYSCRAPER_L1_BN_PARAMS},
        },
    },
};

register_hash!(Poseidon2::new(&POSEIDON2_BN256_PARAMS));
register_hash!(Skyscraper::new(&SKYSCRAPER_L1_BN_PARAMS));

impl SmolHasher for Poseidon2<FpBN256> {
    fn hash_fn(&self) -> HashFn {
        HashFn::Poseidon2(3)
    }

    fn implementation(&self) -> &str {
        "zkhash"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        fn to_field(mut val: [u8; 32]) -> FpBN256 {
            val[31] = 0; // NOTE: Do not do in prod.
            FpBN256::from_raw_repr(FrRepr(cast::<[u8; 32], [u64; 4]>(val))).unwrap()
        }

        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state = [
                to_field(message[0..32].try_into().unwrap()),
                to_field(message[32..64].try_into().unwrap()),
                FpBN256::zero(),
            ];
            self.permutation(&state);

            // This allocates a Vec, which is dumb but it's the only way to get the bytes
            // our of arkworks.
            hash.copy_from_slice(&cast::<[u64; 4], [u8; 32]>(state[0].into_raw_repr().0));
        }
    }
}

impl SmolHasher for Skyscraper<FpBN256, 1, 0, BN256Ext1> {
    fn hash_fn(&self) -> HashFn {
        HashFn::Skyscraper1(1)
    }

    fn implementation(&self) -> &str {
        "zkhash"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        fn to_field(mut val: [u8; 32]) -> BN256Ext1 {
            val[31] = 0; // NOTE: Do not do in prod.
            let f = FpBN256::from_raw_repr(FrRepr(cast::<[u8; 32], [u64; 4]>(val))).unwrap();
            BN256Ext1::from([f])
        }

        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state = [
                to_field(message[0..32].try_into().unwrap()),
                to_field(message[32..64].try_into().unwrap()),
            ];
            self.permutation_extension(&state);

            // This allocates a Vec, which is dumb but it's the only way to get the bytes
            // our of arkworks.
            hash.copy_from_slice(&cast::<[u64; 4], [u8; 32]>(
                state[0].data[0].0.into_raw_repr().0,
            ));
        }
    }
}
