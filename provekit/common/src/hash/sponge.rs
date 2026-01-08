use {
    super::{traits::HashCore, utils::bigint_from_bytes_le},
    crate::FieldElement,
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    std::marker::PhantomData,
    zeroize::Zeroize,
};

#[derive(Clone, Zeroize)]
pub struct HashPermutation<H: HashCore> {
    state:   [FieldElement; 2],
    #[zeroize(skip)]
    _marker: PhantomData<H>,
}

impl<H: HashCore> Default for HashPermutation<H> {
    fn default() -> Self {
        Self {
            state:   [FieldElement::from(0u64), FieldElement::from(0u64)],
            _marker: PhantomData,
        }
    }
}

impl<H: HashCore> AsRef<[FieldElement]> for HashPermutation<H> {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl<H: HashCore> AsMut<[FieldElement]> for HashPermutation<H> {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl<H: HashCore> Permutation for HashPermutation<H> {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state:   [FieldElement::from(0u64), felt],
            _marker: PhantomData,
        }
    }

    fn permute(&mut self) {
        let (new_left, new_right) = H::permute(self.state[0], self.state[1]);
        self.state = [new_left, new_right];
    }
}

pub type HashSponge<H> = DuplexSponge<HashPermutation<H>>;
