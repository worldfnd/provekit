use {
    skyscraper::pow::{solve, verify},
    spongefish_pow::PowStrategy,
    zerocopy::transmute,
};

/// Skyscraper proof of work
#[derive(Clone, Copy)]
pub struct SkyscraperPoW {
    challenge: [u64; 4],
    bits:      f64,
}

impl PowStrategy for SkyscraperPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self {
            challenge: transmute!(challenge),
            bits,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        verify(self.challenge, self.bits, nonce)
    }

    fn solve(&mut self) -> Option<u64> {
        Some(solve(self.challenge, self.bits))
    }
}

#[ignore = "Takes a long time during testing"]
#[test]
fn test_pow_skyscraper() {
    use {
        spongefish::{
            ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, DefaultHash,
            DomainSeparator,
        },
        spongefish_pow::{PoWChallenge, PoWDomainSeparator},
    };

    const BITS: f64 = 10.0;

    let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
        .add_bytes(1, "something")
        .challenge_pow("rolling dices");

    let mut prover = iopattern.to_prover_state();
    prover.add_bytes(b"\0").expect("Invalid IOPattern");
    prover.challenge_pow::<SkyscraperPoW>(BITS).unwrap();

    let mut verifier = iopattern.to_verifier_state(prover.narg_string());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow::<SkyscraperPoW>(BITS).unwrap();
}
