#![cfg(test)]
use {
    proptest::{num::sample_uniform_incl, prelude::*, sample::SizeRange, strategy::ValueTree},
    std::fmt,
};

// Incorporate ordering in the type as well? For most things it doesn't matter
// but for the NTT it could be nice.
// TODO(xrvdg) make this an into
pub struct Vec2n<T>(pub Vec<T>);

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

// How to give a length to the strategy?
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

#[cfg(test)]
mod tests {
    use {
        crate::{proptest::vec2n, reverse_bits},
        proptest::prelude::*,
    };

    fn failure_test(len: usize) {
        let n = len / 2;
        match n {
            0 => return,
            // Maybe there shouldn't be a roots when the size is 1
            // and there should only be one if it's two.
            n => {
                assert!(n.is_power_of_two());

                for index in 0..n {
                    let _rev = reverse_bits(index, n.trailing_zeros());
                }
            }
        }
    }

    proptest! {
        #[test]
        fn min_size_test(s in vec2n(0u128.., 0..10)){
            let s = s.0;
            failure_test(s.len());
        }
    }

    #[test]
    fn min_size_test_concrete() {
        let s = vec![
            105922996067648041916664138293903301621u128,
            262602152062922063258535639029822315735u128,
        ];
        failure_test(s.len());
    }

    proptest! {
        #[test]
        fn min_size_direct(v in (0u32..63).prop_map(|k|2_usize.pow(k))){
            failure_test(v);
        }
    }
}
