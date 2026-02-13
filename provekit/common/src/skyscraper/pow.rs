use {
    skyscraper::pow::{solve, verify},
    spongefish_pow::{PoWSolution, PowStrategy},
    zerocopy::transmute,
};

#[derive(Clone, Copy)]
pub struct SkyscraperPoW {
    challenge:     [u8; 32],
    challenge_u64: [u64; 4],
    bits:          f64,
}

impl PowStrategy for SkyscraperPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self {
            challenge,
            challenge_u64: transmute!(challenge),
            bits,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        verify(self.challenge_u64, self.bits, nonce)
    }

    fn solution(&self, nonce: u64) -> PoWSolution {
        PoWSolution {
            challenge: self.challenge,
            nonce,
        }
    }

    fn solve(&mut self) -> Option<PoWSolution> {
        let nonce = solve(self.challenge_u64, self.bits);
        Some(self.solution(nonce))
    }
}
