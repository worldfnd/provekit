use {
    crate::{register_hash, Field, HashFn, SmolHasher},
    zkhash::{
        ark_ff::{BigInteger, PrimeField, Zero},
        fields::bn256::FpBN256,
        poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
    },
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
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let mut state = [
                FpBN256::from_le_bytes_mod_order(&message[0..32]),
                FpBN256::from_le_bytes_mod_order(&message[32..64]),
                FpBN256::zero(),
            ];
            self.0.permutation(&mut state);

            // This allocates a Vec, which is dumb but it's the only way to get the bytes
            // our of arkworks.
            hash.copy_from_slice(state[0].0.to_bytes_le().as_ref());
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
