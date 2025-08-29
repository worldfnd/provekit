#![cfg(test)]
use {
    crate::Vec2n,
    proptest::{num::sample_uniform_incl, prelude::*, sample::SizeRange, strategy::ValueTree},
    std::fmt,
};

impl<T: fmt::Debug> fmt::Debug for Vec2n<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Vec2n").field(&self.0).finish()
    }
}

impl<T> Vec2n<T> {
    pub fn new(vec: Vec<T>) -> Option<Self> {
        match vec.len() {
            0 => Some(Self(vec)),
            n if n.is_power_of_two() => Some(Self(vec)),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Vec2nValueTree<T: ValueTree> {
    vec: Vec2n<T>,
    len: usize,
}

#[derive(Debug)]
pub struct Vec2nStrategy<T: Strategy> {
    element: T,
    // power of 2
    size:    SizeRange,
}

impl<T: Strategy> Strategy for Vec2nStrategy<T> {
    type Tree = Vec2nValueTree<T::Tree>;

    type Value = Vec2n<T::Value>;

    fn new_tree(
        &self,
        runner: &mut prop::test_runner::TestRunner,
    ) -> prop::strategy::NewTree<Self> {
        let (start, end) = self.size.start_end_incl();
        let max_size = sample_uniform_incl(runner, start, end);
        let mut elements = Vec::with_capacity(max_size);
        let n = 2_usize.pow(max_size as u32);
        while elements.len() < n {
            elements.push(self.element.new_tree(runner)?);
        }

        Ok(Vec2nValueTree {
            vec: Vec2n(elements),
            len: n,
        })
    }
}

/// Create a strategy to generate `Vec`s containing elements drawn from
/// `element` and with a size range given by `size`.
///
/// To make a `Vec` with a fixed number of elements, each with its own
/// strategy, you can instead make a `Vec` of strategies (boxed if necessary).
pub fn vec2n<T: Strategy>(element: T, size: impl Into<SizeRange>) -> Vec2nStrategy<T> {
    let size = size.into();
    Vec2nStrategy { element, size }
}

impl<T: ValueTree> ValueTree for Vec2nValueTree<T> {
    type Value = Vec2n<T::Value>;

    fn current(&self) -> Self::Value {
        let vec = self.vec.0[..self.len]
            .iter()
            .map(|element| element.current())
            .collect();
        Vec2n::new(vec).unwrap()
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
