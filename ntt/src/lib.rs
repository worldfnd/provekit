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
#[derive(Debug, Clone, PartialEq)]
pub struct NTT<T, C: NTTContainer<T>> {
    container: C,
    _phantom:  PhantomData<T>,
}

impl<T, C: NTTContainer<T>> NTT<T, C> {
    pub fn new(vec: C) -> Option<Self> {
        match Pow2OrZero::new(vec.as_ref().len()) {
            Some(_) => Some(Self {
                container: vec,
                _phantom:  PhantomData,
            }),
            _ => None,
        }
    }

    pub fn order(&self) -> Pow2OrZero {
        Pow2OrZero(self.container.as_ref().len())
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

// Only Deref is implement as DerefMut allows for breaking the proof.
impl Deref for Pow2OrZero {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
