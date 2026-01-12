use {
    crate::{hash::PermutationScheme, FieldElement},
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    spongefish::duplex_sponge::{DuplexSponge, Permutation as Permutable},
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

#[derive(Clone, Zeroize)]
pub struct PermutationAdapter<P: PermutationScheme> {
    state:   State,
    _marker: std::marker::PhantomData<P>,
}

impl<P: PermutationScheme> Default for PermutationAdapter<P> {
    fn default() -> Self {
        Self {
            state:   [FieldElement::default(); 2],
            _marker: std::marker::PhantomData,
        }
    }
}

impl<P: PermutationScheme> AsRef<[FieldElement]> for PermutationAdapter<P> {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl<P: PermutationScheme> AsMut<[FieldElement]> for PermutationAdapter<P> {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl<P: PermutationScheme> Permutable for PermutationAdapter<P> {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state:   [0.into(), felt],
            _marker: std::marker::PhantomData,
        }
    }

    fn permute(&mut self) {
        let (l2, r2) = P::permute(to_fr(self.state[0]), to_fr(self.state[1]));
        self.state = [from_fr(l2), from_fr(r2)];
    }
}

pub type Sponge<P> = DuplexSponge<PermutationAdapter<P>>;
