use {
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    spongefish::{DuplexSponge, Permutation},
};

fn bytes_to_fr(bytes: &[u8]) -> Fr {
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    Fr::new(BigInt(limbs))
}

fn fr_to_bytes(f: Fr) -> [u8; 32] {
    let limbs = f.into_bigint().0;
    let mut out = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

#[derive(Clone, Default)]
pub struct Skyscraper;

impl Permutation<64> for Skyscraper {
    type U = u8;

    fn permute(&self, state: &[u8; 64]) -> [u8; 64] {
        let left = bytes_to_fr(&state[..32]);
        let right = bytes_to_fr(&state[32..]);
        let (l2, r2) = skyscraper::reference::permute(left, right);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&fr_to_bytes(l2));
        out[32..].copy_from_slice(&fr_to_bytes(r2));
        out
    }
}

pub type SkyscraperSponge = DuplexSponge<Skyscraper, 64, 32>;
