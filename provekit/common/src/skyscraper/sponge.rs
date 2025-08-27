use {
    crate::FieldElement,
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zeroize::Zeroize,
};

fn to_fr(x: FieldElement) -> Fr {
    Fr::new(BigInt(x.into_bigint().0))
}
fn from_fr(x: Fr) -> FieldElement {
    FieldElement::new(x.into_bigint())
}

fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
}

type State = [FieldElement; 2];

#[derive(Clone, Default, Zeroize)]
pub struct Skyscraper {
    state: State,
}

impl AsRef<[FieldElement]> for Skyscraper {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}
impl AsMut<[FieldElement]> for Skyscraper {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Skyscraper {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state: [0.into(), felt],
        }
    }

    fn permute(&mut self) {
        let (l2, r2) = skyscraper::reference::permute(to_fr(self.state[0]), to_fr(self.state[1]));
        self.state = [from_fr(l2), from_fr(r2)];
    }
}

pub type SkyscraperSponge = DuplexSponge<Skyscraper>;
