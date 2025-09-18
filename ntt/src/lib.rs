#![feature(vec_split_at_spare)]
pub mod ntt;
pub use ntt::*;

/// The NTT is optimized for NTTs of a power of two. Arbitrary sized NTTs are
/// not supported. Note: empty vectors (size 0) are also supported as a special
/// case.
#[derive(Debug, Clone, PartialEq)]
pub struct NTT<T>(Vec<T>);

/// Length of an NTT
#[derive(Clone, Copy)]
pub struct Pow2OrZero(usize);

impl Pow2OrZero {
    pub fn new(size: usize) -> Option<Pow2OrZero> {
        match size {
            size if size == 0 || size.is_power_of_two() => Some(Pow2OrZero(size)),
            _ => None,
        }
    }

    pub fn next_power_of_two(size: usize) -> Pow2OrZero {
        Self(size.next_power_of_two())
    }
}

impl<T> NTT<T> {
    pub fn new(vec: Vec<T>) -> Option<Self> {
        match Pow2OrZero::new(vec.len()) {
            Some(_) => Some(Self(vec)),
            _ => None,
        }
    }

    pub fn len(&self) -> Pow2OrZero {
        Pow2OrZero(self.0.len())
    }
}
