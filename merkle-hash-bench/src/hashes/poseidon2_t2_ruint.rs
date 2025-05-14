use {
    crate::{
        mod_ring::{
            fields::{Bn254Element, Bn254Field},
            RingRefExt,
        },
        register_hash, Field, HashFn, SmolHasher,
    },
    rand::Rng,
    ruint::aliases::U256,
    std::array,
};

register_hash!(Poseidon2T2Ruint::new());

pub struct Poseidon2T2Ruint {
    first:  [[Bn254Element; 2]; 4],
    middle: [Bn254Element; 56],
    last:   [[Bn254Element; 2]; 4],
}

impl SmolHasher for Poseidon2T2Ruint {
    fn hash_fn(&self) -> HashFn {
        HashFn::Poseidon2(2)
    }

    fn implementation(&self) -> &str {
        "ruint"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let mut state = [from_bytes(&message[0..32]), from_bytes(&message[32..64])];
            self.permute(&mut state);
            hash.copy_from_slice(state[0].as_montgomery().as_le_slice());
        }
    }
}

fn from_bytes(bytes: &[u8]) -> Bn254Element {
    let mut bytes: [u8; 32] = bytes.try_into().unwrap();
    bytes[31] = 0;
    Bn254Field.from_montgomery(U256::from_le_bytes::<32>(bytes))
}

impl Poseidon2T2Ruint {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self {
            first:  rng.random(),
            middle: array::from_fn(|_| rng.random()),
            last:   rng.random(),
        }
    }

    fn permute(&self, state: &mut [Bn254Element; 2]) {
        let sum = state.iter().copied().sum();
        state.iter_mut().for_each(|s| *s += sum);
        for rc in self.first {
            state.iter_mut().zip(rc).for_each(|(x, rc)| *x += rc);
            state.iter_mut().for_each(|x| *x = x.pow(5));
            let sum = state.iter().copied().sum();
            state.iter_mut().for_each(|s| *s += sum);
        }
        for rc in self.middle {
            state[0] += rc;
            state[0] = state[0].pow(5);

            let sum = state.iter().copied().sum();
            state[1] += state[1];
            state.iter_mut().for_each(|s| *s += sum);
        }
        for rc in self.last {
            state.iter_mut().zip(rc).for_each(|(x, rc)| *x += rc);
            state.iter_mut().for_each(|x| *x = x.pow(5));
            let sum = state.iter().copied().sum();
            state.iter_mut().for_each(|s| *s += sum);
        }
    }
}
