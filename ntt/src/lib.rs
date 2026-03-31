#![feature(vec_split_at_spare)]
pub mod ntt;
pub use ntt::*;
use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

pub trait NTTContainer<T>: AsRef<[T]> + AsMut<[T]> {}
impl<T, C: AsRef<[T]> + AsMut<[T]>> NTTContainer<T> for C {}

/// The NTT is optimized for NTTs of a power of two. Arbitrary sized NTTs are
/// not supported. Note: empty vectors (size 0) are also supported as a special
/// case.
///
/// NTTContainer can be a single polynomial or multiple polynomials that are
/// interleaved. interleaved polynomials; `[a0, b0, c0, d0, a1, b1, c1, d1,
/// ...]` for four polynomials `a`, `b`, `c`, and `d`. By operating on
/// interleaved data, you can perform the NTT on all polynomials in-place
/// without needing to first transpose the data
#[derive(Debug, Clone, PartialEq)]
pub struct NTT<T, C: NTTContainer<T>> {
    container:     C,
    codeword_size: usize,
    _phantom:      PhantomData<T>,
}

impl<T, C: NTTContainer<T>> NTT<T, C> {
    pub fn new(vec: C, number_of_polynomials: usize) -> Self {
        let n = vec.as_ref().len();

        let order = n / number_of_polynomials;
        assert!(n == 0 || order.is_power_of_two());

        // The order of the individual polynomials needs to be a power of two
        Self {
            container:     vec,
            codeword_size: order,
            _phantom:      PhantomData,
        }
    }

    pub fn order(&self) -> usize {
        self.codeword_size
    }

    pub fn into_inner(self) -> C {
        self.container
    }
}

impl<T, C: NTTContainer<T>> Deref for NTT<T, C> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.container.as_ref()
    }
}

impl<T, C: NTTContainer<T>> DerefMut for NTT<T, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.container.as_mut()
    }
}
