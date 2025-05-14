#![cfg(feature = "plonky3")]
use {
    crate::{register_hash, Field, HashFn, SmolHasher},
    bytemuck::cast_slice_mut,
    p3_bn254_fr::{Bn254Fr, FFBn254Fr, Poseidon2Bn254},
    p3_field::{integers::QuotientMap as _, PrimeCharacteristicRing, PrimeField32, PrimeField64},
    p3_goldilocks::{Goldilocks, MdsMatrixGoldilocks, Poseidon2Goldilocks},
    p3_mersenne_31::{MdsMatrixMersenne31, Mersenne31, Poseidon2Mersenne31},
    p3_monolith::MonolithMersenne31,
    p3_rescue::Rescue,
    p3_symmetric::Permutation,
    rand::rng,
    std::mem::transmute,
};

type RescueGoldilocks = Rescue<Goldilocks, MdsMatrixGoldilocks, 8, 7>;
type RecueMersenne31 = Rescue<Mersenne31, MdsMatrixMersenne31, 16, 5>;

register_hash!(Poseidon2Mersenne31::<16>::new_from_rng_128(&mut rng()));
register_hash!(Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng()));
register_hash!(Poseidon2Bn254::<3>::new_from_rng(8, 22, &mut rng()));
register_hash!(MonolithMersenne31::<_, 16, 5>::new(MdsMatrixMersenne31));
register_hash!(RecueMersenne31::new(
    8,
    RecueMersenne31::get_round_constants_from_rng(8, &mut rng()),
    Default::default()
));
register_hash!(RescueGoldilocks::new(
    8,
    RescueGoldilocks::get_round_constants_from_rng(8, &mut rng()),
    Default::default()
));

impl SmolHasher for Poseidon2Mersenne31<16> {
    fn hash_fn(&self) -> HashFn {
        HashFn::Poseidon2(16)
    }

    fn implementation(&self) -> &str {
        "plonky3"
    }

    fn field(&self) -> Field {
        Field::M31
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state: &[u32; 16] = bytemuck::cast_slice::<u8, u32>(message).try_into().unwrap();
            let state = Mersenne31::new_array(*state);
            let state = self.permute(state);
            let out: &mut [u32] = cast_slice_mut(hash);
            for (out, state) in out.iter_mut().zip(state.as_slice()) {
                *out = state.as_canonical_u32();
            }
        }
    }
}

impl SmolHasher for Poseidon2Goldilocks<8> {
    fn hash_fn(&self) -> HashFn {
        HashFn::Poseidon2(8)
    }

    fn implementation(&self) -> &str {
        "plonky3"
    }

    fn field(&self) -> Field {
        Field::Goldilocks
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state: &[u64; 8] = bytemuck::cast_slice::<u8, u64>(message).try_into().unwrap();
            let state = state.map(Goldilocks::from_int);
            let state = self.permute(state);
            let out: &mut [u64] = cast_slice_mut(hash);
            for (out, state) in out.iter_mut().zip(state.as_slice()) {
                *out = state.as_canonical_u64();
            }
        }
    }
}

impl SmolHasher for Poseidon2Bn254<3> {
    fn hash_fn(&self) -> HashFn {
        HashFn::Poseidon2(3)
    }

    fn implementation(&self) -> &str {
        "plonky3"
    }

    fn field(&self) -> Field {
        Field::Bn254
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state = [
                fr_from_bytes(&message[..32]),
                fr_from_bytes(&message[32..]),
                Bn254Fr::ZERO,
            ];
            let state = self.permute(state);
            hash.copy_from_slice(bytes_from_fr(state[0]).as_slice());
        }
    }
}

fn fr_from_bytes(bytes: &[u8]) -> Bn254Fr {
    let mut bytes: [u8; 32] = bytes.try_into().unwrap();
    bytes[31] = 0; // Force smaller than modulus.
    let element = FFBn254Fr::from_bytes(&bytes).unwrap();
    unsafe { transmute(element) }
}

fn bytes_from_fr(element: Bn254Fr) -> [u8; 32] {
    unsafe { transmute(element) }
}

impl SmolHasher for MonolithMersenne31<MdsMatrixMersenne31, 16, 5> {
    fn hash_fn(&self) -> HashFn {
        HashFn::Monolith(16)
    }

    fn implementation(&self) -> &str {
        "plonky3"
    }

    fn field(&self) -> Field {
        Field::M31
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state: &[u32; 16] = bytemuck::cast_slice::<u8, u32>(message).try_into().unwrap();
            let mut state = Mersenne31::new_array(*state);
            self.permutation(&mut state);
            let out: &mut [u32] = cast_slice_mut(hash);
            for (out, state) in out.iter_mut().zip(state.as_slice()) {
                *out = state.as_canonical_u32();
            }
        }
    }
}

impl SmolHasher for RecueMersenne31 {
    fn hash_fn(&self) -> HashFn {
        HashFn::Rescue(16)
    }

    fn implementation(&self) -> &str {
        "plonky3"
    }

    fn field(&self) -> Field {
        Field::M31
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state: &[u32; 16] = bytemuck::cast_slice::<u8, u32>(message).try_into().unwrap();
            let mut state = Mersenne31::new_array(*state);
            self.permute_mut(&mut state);
            let out: &mut [u32] = cast_slice_mut(hash);
            for (out, state) in out.iter_mut().zip(state.as_slice()) {
                *out = state.as_canonical_u32();
            }
        }
    }
}
impl SmolHasher for RescueGoldilocks {
    fn hash_fn(&self) -> HashFn {
        HashFn::Rescue(8)
    }

    fn implementation(&self) -> &str {
        "plonky3"
    }

    fn field(&self) -> Field {
        Field::Goldilocks
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            let state: &[u64; 8] = bytemuck::cast_slice::<u8, u64>(message).try_into().unwrap();
            let state = state.map(Goldilocks::from_int);
            let state = self.permute(state);
            let out: &mut [u64] = cast_slice_mut(hash);
            for (out, state) in out.iter_mut().zip(state.as_slice()) {
                *out = state.as_canonical_u64();
            }
        }
    }
}
