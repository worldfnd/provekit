use {
    crate::bytes::{bytes_to_field, field_to_bytes_le},
    spongefish::{DuplexSponge, Permutation},
};

#[derive(Clone, Default)]
pub struct Skyscraper;

impl Permutation<64> for Skyscraper {
    type U = u8;

    fn permute(&self, state: &[u8; 64]) -> [u8; 64] {
        let left = bytes_to_field(&state[..32]);
        let right = bytes_to_field(&state[32..]);
        let (l2, r2) = skyscraper::reference::permute(left, right);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&field_to_bytes_le(l2));
        out[32..].copy_from_slice(&field_to_bytes_le(r2));
        out
    }
}

pub type SkyscraperSponge = DuplexSponge<Skyscraper, 64, 32>;
