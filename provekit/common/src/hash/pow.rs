use {
    super::traits::HashCore,
    spongefish_pow::PowStrategy,
    std::marker::PhantomData,
};

/// Generic proof-of-work using HashCore trait.
#[derive(Clone, Copy)]
pub struct HashPoW<H: HashCore> {
    challenge: [u8; 32],
    bits: f64,
    _marker: PhantomData<H>,
}

impl<H: HashCore> PowStrategy for HashPoW<H> {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        Self {
            challenge,
            bits,
            _marker: PhantomData,
        }
    }

    fn check(&mut self, nonce: u64) -> bool {
        H::check_pow(self.challenge, self.bits, nonce)
    }

    fn solve(&mut self) -> Option<u64> {
        H::solve_pow(self.challenge, self.bits)
    }
}
