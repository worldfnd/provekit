use {
    crate::{
        hash::{
            pow::HashPoW,
            sponge::{HashPermutation, HashSponge},
            traits::{HashCore, ProtocolHash},
        },
        FieldElement,
    },
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    zerocopy::transmute,
};

fn to_fr(x: FieldElement) -> Fr {
    Fr::new(BigInt(x.into_bigint().0))
}

fn from_fr(x: Fr) -> FieldElement {
    FieldElement::new(x.into_bigint())
}

#[derive(Clone)]
pub struct SkyscraperHasher;

impl HashCore for SkyscraperHasher {
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        let l64 = left.into_bigint().0;
        let r64 = right.into_bigint().0;
        let out = skyscraper::simple::compress(l64, r64);
        FieldElement::new(BigInt(out))
    }

    fn permute(left: FieldElement, right: FieldElement) -> (FieldElement, FieldElement) {
        let (l2, r2) = skyscraper::reference::permute(to_fr(left), to_fr(right));
        (from_fr(l2), from_fr(r2))
    }

    fn solve_pow(challenge: [u8; 32], bits: f64) -> Option<u64> {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        let challenge: [u64; 4] = transmute!(challenge);
        Some(skyscraper::pow::solve(challenge, bits))
    }

    fn check_pow(challenge: [u8; 32], bits: f64, nonce: u64) -> bool {
        let challenge: [u64; 4] = transmute!(challenge);
        skyscraper::pow::verify(challenge, bits, nonce)
    }
}

pub type SkyscraperPermutation = HashPermutation<SkyscraperHasher>;
pub type SkyscraperSponge = HashSponge<SkyscraperHasher>;
pub type SkyscraperPoW = HashPoW<SkyscraperHasher>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Skyscraper;

impl ProtocolHash for Skyscraper {
    type Permutation = SkyscraperPermutation;
    type Sponge = SkyscraperSponge;
    type MerkleConfig = SkyscraperMerkleConfig;
    type PoW = SkyscraperPoW;

    #[inline]
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement {
        SkyscraperHasher::compress(left, right)
    }

    fn name() -> &'static str {
        "skyscraper"
    }
}

crate::impl_hash_whir!(Skyscraper, SkyscraperHasher);

#[cfg(test)]
mod tests {
    use {
        super::*,
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
        prover.challenge_pow::<SkyscraperPoW>(BITS).unwrap();

        let mut verifier = iopattern.to_verifier_state(prover.narg_string());
        let byte = verifier.next_bytes::<1>().unwrap();
        assert_eq!(&byte, b"\0");
        verifier.challenge_pow::<SkyscraperPoW>(BITS).unwrap();
    }
}
