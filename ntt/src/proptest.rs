#![cfg(test)]
use {
    crate::NTT,
    proptest::{num::sample_uniform_incl, prelude::*, sample::SizeRange, strategy::ValueTree},
};

#[derive(Debug)]
pub struct NTTValueTree<T: ValueTree> {
    vec: NTT<T>,
    len: usize,
}

#[derive(Debug)]
pub struct NTTStrategy<T: Strategy> {
    element: T,
    // power of 2
    size:    SizeRange,
}

impl<T: Strategy> Strategy for NTTStrategy<T> {
    type Tree = NTTValueTree<T::Tree>;

    type Value = NTT<T::Value>;

    fn new_tree(
        &self,
        runner: &mut prop::test_runner::TestRunner,
    ) -> prop::strategy::NewTree<Self> {
        // Based on VecStrategy in proptest
        let (start, end) = self.size.start_end_incl();
        let max_size = sample_uniform_incl(runner, start, end);
        let mut elements = Vec::with_capacity(max_size);
        let n = 2_usize.pow(max_size as u32);
        while elements.len() < n {
            elements.push(self.element.new_tree(runner)?);
        }

        Ok(NTTValueTree {
            vec: NTT(elements),
            len: n,
        })
    }
}

/// Create a strategy to generate `NTT`s of length 2^size

pub fn ntt<T: Strategy>(element: T, size: impl Into<SizeRange>) -> NTTStrategy<T> {
    let size = size.into();
    NTTStrategy { element, size }
}

impl<T: ValueTree> ValueTree for NTTValueTree<T> {
    type Value = NTT<T::Value>;

    fn current(&self) -> Self::Value {
        let vec = self.vec.0[..self.len]
            .iter()
            .map(|element| element.current())
            .collect();
        NTT::new(vec).unwrap()
    }

    // Simplifies only the structure and not the values.
    fn simplify(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }

        self.len /= 2;
        true
    }

    fn complicate(&mut self) -> bool {
        // Undo the last simplification and signal that there is nothing more to do.
        self.len *= 2;
        false
    }
}
