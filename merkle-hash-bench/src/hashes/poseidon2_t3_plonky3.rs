use {
    crate::{SmolHasher, HASHES},
    linkme::distributed_slice,
    p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254, FFBn254Fr},
    p3_field::AbstractField,
    p3_poseidon2::Poseidon2ExternalMatrixGeneral,
    p3_symmetric::Permutation,
    std::fmt::Display,
};

#[allow(unsafe_code)] // Squelch the warning about using link_section
#[distributed_slice(HASHES)]
static HASH: fn() -> Box<dyn SmolHasher> = || Box::new(Poseidon2T3Plonky3::new());

type Poseidon2 =
    p3_poseidon2::Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>;

pub struct Poseidon2T3Plonky3 {
    poseidon: Poseidon2,
}

impl Display for Poseidon2T3Plonky3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("poseidon2-t3-plonky3")
    }
}

impl SmolHasher for Poseidon2T3Plonky3 {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            self.compress(message, hash);
        }
    }
}

impl Poseidon2T3Plonky3 {
    pub fn new() -> Self {
        const ROUNDS_F: usize = 8;
        const ROUDNS_P: usize = 56;
        let mut rng = rand::thread_rng();
        let poseidon = Poseidon2::new_from_rng(
            ROUNDS_F,
            Poseidon2ExternalMatrixGeneral,
            ROUDNS_P,
            DiffusionMatrixBN254,
            &mut rng,
        );
        Self { poseidon }
    }

    fn compress(&self, input: &[u8], output: &mut [u8]) {
        debug_assert_eq!(input.len(), 64);
        debug_assert_eq!(output.len(), 32);

        let state = [
            fr_from_bytes(&input[0..32]),
            fr_from_bytes(&input[32..64]),
            Bn254Fr::zero(),
        ];
        let state = self.poseidon.permute(state);
        output.copy_from_slice(state[0].value.to_bytes().as_slice());
    }
}

fn fr_from_bytes(bytes: &[u8]) -> Bn254Fr {
    let mut bytes: [u8; 32] = bytes.try_into().unwrap();
    bytes[31] = 0; // Force smaller than modulus.
    Bn254Fr {
        value: FFBn254Fr::from_bytes(&bytes).unwrap(),
    }
}
