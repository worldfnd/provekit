use {crate::hash::PowScheme, spongefish_pow::PowStrategy, zerocopy::transmute};

#[derive(Clone, Copy)]
pub struct PoW<P>
where
    P: PowScheme,
{
    challenge: [u64; 4],
    bits:      f64,
    _marker:   std::marker::PhantomData<P>,
}

impl<P: PowScheme> PowStrategy for PoW<P> {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self {
            challenge: transmute!(challenge),
            bits,
            _marker: std::marker::PhantomData,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        P::check(self.challenge, self.bits, nonce)
    }

    fn solve(&mut self) -> Option<u64> {
        P::solve(self.challenge, self.bits)
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::hash::{skyscraper::Skyscraper, PoW},
        spongefish::{
            ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, DefaultHash,
            DomainSeparator,
        },
        spongefish_pow::{PoWChallenge, PoWDomainSeparator},
    };

    #[test]
    fn test_pow_skyscraper() {
        const BITS: f64 = 10.0;

        let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
            .add_bytes(1, "something")
            .challenge_pow("rolling dices");

        let mut prover = iopattern.to_prover_state();
        prover.add_bytes(b"\0").expect("Invalid IOPattern");
        prover.challenge_pow::<PoW<Skyscraper>>(BITS).unwrap();

        let mut verifier = iopattern.to_verifier_state(prover.narg_string());
        let byte = verifier.next_bytes::<1>().unwrap();
        assert_eq!(&byte, b"\0");
        verifier.challenge_pow::<PoW<Skyscraper>>(BITS).unwrap();
    }
}
