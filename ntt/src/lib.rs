pub mod ntt;
pub use ntt::*;
mod matrix;

/// The NTT is optimized for NTTs of a power of two. Arbitrary sized NTTs are
/// not supported. Note: empty vectors (size 0) are also supported as a special
/// case.
#[derive(Debug, Clone, PartialEq)]
pub struct NTT<T>(Vec<T>);

/// Length of an NTT
pub struct Pow2OrZero(usize);

impl<T> NTT<T> {
    pub fn new(vec: Vec<T>) -> Option<Self> {
        match vec.len() {
            0 => Some(Self(vec)),
            n if n.is_power_of_two() => Some(Self(vec)),
            _ => None,
        }
    }

    pub fn len(&self) -> Pow2OrZero {
        Pow2OrZero(self.0.len())
    }
}
