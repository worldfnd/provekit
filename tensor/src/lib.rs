//! A simple generic tensor library in Rust.
#![allow(unsafe_code)]

mod layout;

pub use layout::Layout;
use std::{
    marker::PhantomData,
    ops::{Index, IndexMut, Range},
};

/// A multi-dimensional slice-like structure that represents a tensor.
///
/// For efficiency, internally sizes are represented by `u32` and not `usize`.
/// This means that the maximum size of a tensor is `2^32 - 1` elements.
pub struct TensorMut<'a, T, const MAX_RANK: usize = 3> {
    /// Pointer to the data of the tensor.
    data: *mut T,

    /// Memory layout of tensor dimensions.
    layout: Layout<MAX_RANK>,

    /// Lifetime marker for the data
    _lifetime: PhantomData<&'a mut T>,
}

impl<T, const MAX_RANK: usize> TensorMut<'_, T, MAX_RANK> {
    /// Returns the number of dimensions in the tensor.
    ///
    /// A rank of `0` indicates a scalar, `1` indicates a vector, and so on.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.layout.rank()
    }

    /// The sizes of each dimension of the tensor.
    #[must_use]
    pub fn shape(&self, dim: usize) -> usize {
        self.layout.shape(dim)
    }

    /// Total size of the tensor, which is the product of all dimensions.
    #[must_use]
    pub fn size(&self) -> usize {
        self.layout.size()
    }

    /// Return a mutable slice of the tensor data.
    ///
    /// Returns `None` if the tensor is not a 1D tensor with a contiguous
    /// layout.
    pub fn as_mut_slice(&mut self) -> Option<&mut [T]> {
        // TODO:
        // if self.rank() != 1 || self.layout.stride[0] != 1 {
        //     return None;
        // }
        // let slice =
        //     unsafe { std::slice::from_raw_parts_mut(self.data, self.layout.shape[0]
        // as usize) }; Some(slice)
        todo!()
    }

    /// Adjusts the `MAX_RANK` of the tensor to a new value.
    ///
    /// # Panics
    ///
    /// Panics if the new `MAX_RANK` is less than the current rank of the
    /// tensor.
    pub fn with_max_rank<const N: usize>(&mut self) -> TensorMut<'_, T, N> {
        TensorMut {
            data:      self.data,
            layout:    self.layout.with_max_rank(),
            _lifetime: PhantomData,
        }
    }

    /// Permute the dimensions of the tensor according to the specified axes.
    ///
    /// A traditional matrix transpose would be `transpose(&[1, 0])`.
    ///
    /// # Panics
    ///
    /// Panics if the size of `axes` does not match the rank of the tensor,
    /// if any axis is out of bounds, or if any axis is used multiple times.
    #[must_use]
    pub fn transpose(&mut self, axes: &[usize]) -> TensorMut<'_, T, MAX_RANK> {
        TensorMut {
            data:      self.data,
            layout:    self.layout.transpose(axes),
            _lifetime: PhantomData,
        }
    }

    /// Get the subtensor at the specified dimension and index.
    ///
    /// The returned tensor will have lower rank by one.
    ///
    /// # Panics
    ///
    /// Panics if the dimension is out of bounds or if the index is out of
    /// bounds for the dimension.
    #[must_use]
    pub fn select(&mut self, dim: usize, index: usize) -> TensorMut<'_, T, MAX_RANK> {
        let (offset, layout) = self.layout.select(dim, index);
        TensorMut {
            data: unsafe { self.data.add(offset) },
            layout,
            _lifetime: PhantomData,
        }
    }

    /// Split the tensor into two along the specified dimension.
    ///
    /// # Panics
    ///
    /// Panics if the dimension is out of bounds or if the index is out of
    /// bounds.
    #[must_use]
    pub fn split_at_mut(
        &mut self,
        dim: usize,
        index: usize,
    ) -> (TensorMut<'_, T, MAX_RANK>, TensorMut<'_, T, MAX_RANK>) {
        let left = self.layout.chunk(dim, 0..index);
        let right = self.layout.chunk(dim, index..self.layout.shape(dim));
        (
            TensorMut {
                data:      unsafe { self.data.add(left.0) },
                layout:    left.1,
                _lifetime: PhantomData,
            },
            TensorMut {
                data:      unsafe { self.data.add(right.0) },
                layout:    right.1,
                _lifetime: PhantomData,
            },
        )
    }

    /// Split a dimension of the tensor into dimensions of specified
    /// sis.
    ///
    /// The existing dimension will be interpreted in row-major order.
    ///
    /// This is useful for reshaping tensors, for example, to turn a vector into
    /// a matrix.
    ///
    /// # Panics
    ///
    /// Panics if the dimension is out of bounds, or if the product of the new
    /// sis does not equal the original size of the dimension.
    #[must_use]
    pub fn unflatten(
        &mut self,
        dim: usize,
        sizes: impl AsRef<[usize]>,
    ) -> TensorMut<'_, T, MAX_RANK> {
        TensorMut {
            data:      self.data,
            layout:    self.layout.unflatten(dim, sizes),
            _lifetime: PhantomData,
        }
    }

    /// Flatten a set of dimensions into a single dimension.
    ///
    /// Returns `None` if the dimensions are not in row-major order.
    ///
    /// # Panics
    /// Panics if the dimensions are out of bounds or if the tensor rank is less
    /// than 1.
    pub fn flatten(&mut self, dims: Range<usize>) -> Option<TensorMut<'_, T, MAX_RANK>> {
        Some(TensorMut {
            data:      self.data,
            layout:    self.layout.flatten(dims)?,
            _lifetime: PhantomData,
        })
    }
}

impl<'a, T, const MAX_RANK: usize> From<&'a mut [T]> for TensorMut<'a, T, MAX_RANK> {
    fn from(value: &mut [T]) -> Self {
        TensorMut {
            data:      value.as_mut_ptr(),
            layout:    Layout::from_size(value.len()),
            _lifetime: PhantomData,
        }
    }
}

impl<T, const MAX_RANK: usize, I> Index<I> for TensorMut<'_, T, MAX_RANK>
where
    I: AsRef<[usize]>,
{
    type Output = T;

    fn index(&self, index: I) -> &Self::Output {
        let offset = self.layout.offset(index);
        unsafe { &*self.data.add(offset) }
    }
}

impl<T, const MAX_RANK: usize, I> IndexMut<I> for TensorMut<'_, T, MAX_RANK>
where
    I: AsRef<[usize]>,
{
    fn index_mut(&mut self, index: I) -> &mut T {
        let offset = self.layout.offset(index);
        unsafe { &mut *self.data.add(offset) }
    }
}

// TODO: tensor[(.., 2, 3..4, ..)] notation to get subtensors

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_mut() {
        let mut data = [1_u32, 2, 3, 4, 5, 6, 7, 8];
        let tensor: TensorMut<_> = TensorMut::from(&mut data[..]);
        assert_eq!(tensor.rank(), 1);
        assert_eq!(tensor[[0]], 1);
        assert_eq!(tensor[[7]], 8);
    }

    #[test]
    fn test_split() {
        let mut data = [1_u32, 2, 3, 4, 5, 6, 7, 8];
        let mut tensor: TensorMut<_> = TensorMut::from(&mut data[..]);
        let (left, right) = tensor.split_at_mut(0, 4);
        assert_eq!(left.rank(), 1);
        assert_eq!(left.size(), 4);
        assert_eq!(left[[0]], 1);
        assert_eq!(left[[3]], 4);
        assert_eq!(right.rank(), 1);
        assert_eq!(right.size(), 4);
        assert_eq!(right[[0]], 5);
        assert_eq!(right[[3]], 8);
    }

    #[test]
    fn test_unflatten() {
        let mut data = [1_u32, 2, 3, 4, 5, 6, 7, 8];
        let mut tensor: TensorMut<_> = data.as_mut_slice().into();
        let tensor = tensor.unflatten(0, [2, 2, 2]);
        assert_eq!(tensor.rank(), 3);
        // assert_eq!(tensor.shape, [2, 2, 2]);
        // assert_eq!(tensor.stride, [4, 2, 1]);
        assert_eq!(tensor[[0, 0, 0]], 1);
        assert_eq!(tensor[[1, 0, 0]], 5);
        assert_eq!(tensor[[0, 1, 1]], 4);
        assert_eq!(tensor[[1, 1, 1]], 8);
    }
}
