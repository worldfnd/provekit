#![cfg(feature = "zkhash")]
use {
    crate::{register_hash, Field, HashFn, SmolHasher}, bytemuck::cast, zkhash::{
        ff::{Field as _, PrimeField},
        fields::bn256::{FpBN256, FrRepr},
        poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
    }
};

register_hash!(Poseidon2T3Zkhash::new());

pub struct Poseidon2T3Zkhash(Poseidon2<FpBN256>);

impl SmolHasher for Poseidon2T3Zkhash {
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
        fn to_field(mut val: [u8;32]) -> FpBN256 {
            val[31] = 0; // NOTE: Do not do in prod.
            FpBN256::from_raw_repr(FrRepr(cast::<[u8;32],[u64;4]>(val))).unwrap()
        }


        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let mut state = [
                to_field(message[0..32].try_into().unwrap()),
                to_field(message[32..64].try_into().unwrap()),
                FpBN256::zero(),
            ];
            self.0.permutation(&mut state);

            // This allocates a Vec, which is dumb but it's the only way to get the bytes
            // our of arkworks.
            hash.copy_from_slice(&cast::<[u64;4],[u8;32]>(state[0].into_raw_repr().0));
        }
    }
}

impl Poseidon2T3Zkhash {
    pub fn new() -> Self {
        Self(zkhash::poseidon2::poseidon2::Poseidon2::new(
            &POSEIDON2_BN256_PARAMS,
        ))
    }
}
