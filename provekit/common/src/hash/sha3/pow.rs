use {
    sha3::{Digest, Sha3_256},
    spongefish_pow::PowStrategy,
};

fn count_leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[derive(Clone, Copy)]
pub struct Sha3PoW {
    challenge: [u8; 32],
    bits: f64,
}

impl PowStrategy for Sha3PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(self.challenge);
        hasher.update(nonce.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        count_leading_zeros(&hash) as f64 >= self.bits
    }

    fn solve(&mut self) -> Option<u64> {
        for nonce in 0..u64::MAX {
            if self.check(nonce) {
                return Some(nonce);
            }
        }
        None
    }
}
