use {
    crate::{
        mod_ring::{
            fields::{Bn254Element, Bn254Field},
            RingRefExt,
        },
        SmolHasher,
    },
    rand::Rng,
    ruint::aliases::U256,
    std::fmt::{self, Display, Formatter},
};

pub struct Poseidon2 {
    first: [[Bn254Element; 3]; 4],
    middle: [Bn254Element; 56],
    last: [[Bn254Element; 3]; 4],
}

impl Display for Poseidon2 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.pad("Poseidon2-Bn254-Ruint")
    }
}

impl SmolHasher for Poseidon2 {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let mut state = [
                from_bytes(&message[0..32]),
                from_bytes(&message[32..64]),
                Bn254Field.zero(),
            ];
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

impl Poseidon2 {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            first: rng.gen(),
            middle: rng.gen(),
            last: rng.gen(),
        }
    }

    fn permute(&self, state: &mut [Bn254Element; 3]) {
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

            // TODO: Why is this one more operations than the MDS matrix?
            let sum = state.iter().copied().sum();
            state[2] += state[2];
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
