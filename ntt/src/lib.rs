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
#[derive(Debug, Clone, PartialEq)]
pub struct NTT<T, C: NTTContainer<T>> {
    container: C,
    _phantom:  PhantomData<T>,
}

impl<T, C: NTTContainer<T>> NTT<T, C> {
    pub fn new(vec: C) -> Option<Self> {
        match Pow2::<usize>::new(vec.as_ref().len()) {
            Some(_) => Some(Self {
                container: vec,
                _phantom:  PhantomData,
            }),
            _ => None,
        }
    }

    pub fn order(&self) -> Pow2<usize> {
        Pow2(self.container.as_ref().len())
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

/// Length of an NTT
#[derive(Clone, Copy)]
pub struct Pow2<T = usize>(T);

impl<T: IsPowerOfTwo> Pow2<T> {
    pub fn new(value: T) -> Option<Self> {
        match value.is_power_of_two() {
            true => Some(Self(value)),
            false => None,
        }
    }

    // next power of two
    // pow
}

// Only Deref is implement as DerefMut allows for breaking the proof.
impl<T> Deref for Pow2<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// There is no built-in trait nor num-trait that captures this
pub trait IsPowerOfTwo {
    fn is_power_of_two(&self) -> bool;
}

impl IsPowerOfTwo for usize {
    fn is_power_of_two(&self) -> bool {
        usize::is_power_of_two(*self)
    }
}

impl IsPowerOfTwo for NonZero<usize> {
    fn is_power_of_two(&self) -> bool {
        self.get().is_power_of_two()
    }
}
