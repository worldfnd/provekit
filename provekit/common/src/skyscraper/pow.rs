use {
    skyscraper::pow::{solve, verify},
    spongefish_pow::{PoWSolution, PowStrategy},
    zerocopy::transmute,
};

/// Skyscraper proof of work
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SkyscraperPoW {
    challenge: [u8; 32],
    bits:      f64,
}

impl PowStrategy for SkyscraperPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        verify(transmute!(self.challenge), self.bits, nonce)
    }

    fn solution(&self, nonce: u64) -> PoWSolution {
        PoWSolution {
            challenge: self.challenge,
            nonce,
        }
    }

    fn solve(&mut self) -> Option<PoWSolution> {
        let nonce = solve(transmute!(self.challenge), self.bits);
        Some(self.solution(nonce))
    }
}

#[test]
fn test_pow_skyscraper() {
    let challenge = [42u8; 32];
    let bits = 10.0;
    let mut pow = SkyscraperPoW::new(challenge, bits);
    let solution = pow.solve().expect("should find nonce");
    assert_eq!(solution.challenge, challenge);
    assert!(pow.check(solution.nonce));
}
