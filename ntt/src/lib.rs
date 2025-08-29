pub mod ntt;
pub use ntt::*;
mod proptest;

/// The NTT is optimized for NTTs of a power of two. Arbitrary sized NTTs are
/// not supported.
#[derive(Debug, Clone, PartialEq)]
pub struct NTT<T>(Vec<T>);

pub struct Pow2(usize);

impl<T> NTT<T> {
    pub fn new(vec: Vec<T>) -> Option<Self> {
        match vec.len() {
            0 => Some(Self(vec)),
            n if n.is_power_of_two() => Some(Self(vec)),
            _ => None,
        }
    }

    pub fn len(&self) -> Pow2 {
        Pow2(self.0.len())
    }
}
