#![feature(vec_split_at_spare)]
pub mod ntt;
pub use ntt::*;
use std::{
    marker::PhantomData,
    num::NonZero,
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
    container: C,
    order:     Pow2<usize>,
    _phantom:  PhantomData<T>,
}

impl<T, C: NTTContainer<T>> NTT<T, C> {
    pub fn new(vec: C, number_of_polynomials: usize) -> Option<Self> {
        let n = vec.as_ref().len();
        // All polynomials of the same size
        if number_of_polynomials == 0 || n % number_of_polynomials != 0 {
            return None;
        }

        // The order of the individual polynomials needs to be a power of two
        match Pow2::new(n / number_of_polynomials) {
            Some(order) => Some(Self {
                container: vec,
                order,
                _phantom: PhantomData,
            }),
            _ => None,
        }
    }

    pub fn order(&self) -> Pow2<usize> {
        self.order
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

/// Represents the valid length of an NTT (Number Theoretic Transform).
///
/// The allowed values depend on the type parameter:
/// - `Pow2<usize>`: length is 0 or a power of two (`{0} ∪ {2ⁿ : n ≥ 0}`).
/// - `Pow2<NonZero<usize>>`: length is a nonzero power of two (`{2ⁿ : n ≥ 0}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pow2<T = usize>(T);

impl<T: InPowerOfTwoSet> Pow2<T> {
    pub fn new(value: T) -> Option<Self> {
        match value.in_set() {
            true => Some(Self(value)),
            false => None,
        }
    }
}

// Only Deref is implement as DerefMut allows for breaking the proof.
impl<T> Deref for Pow2<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait InPowerOfTwoSet {
    fn in_set(&self) -> bool;
}

impl InPowerOfTwoSet for usize {
    fn in_set(&self) -> bool {
        usize::is_power_of_two(*self) || *self == 0
    }
}

impl InPowerOfTwoSet for NonZero<usize> {
    fn in_set(&self) -> bool {
        self.get().is_power_of_two()
    }
}
