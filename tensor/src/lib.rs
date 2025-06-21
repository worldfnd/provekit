//! A simple generic tensor library in Rust.
#![allow(unsafe_code)]

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

    /// Size of each dimension in the tensor, zero padded to fit `MAX_RANK`.
    shape: [u32; MAX_RANK],

    /// Stride for each dimension, zero padded to fit `MAX_RANK`.
    stride: [u32; MAX_RANK],

    _lifetime: PhantomData<&'a mut T>,
}

impl<T, const MAX_RANK: usize> TensorMut<'_, T, MAX_RANK> {
    /// Returns the number of dimensions in the tensor.
    ///
    /// A rank of `0` indicates a scalar, `1` indicates a vector, and so on.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.shape.iter().position(|&s| s == 0).unwrap_or(MAX_RANK)
    }

    /// The sizes of each dimension of the tensor.
    #[must_use]
    pub fn shape(&self) -> &[u32] {
        &self.shape[..self.rank()]
    }

    /// Total size of the tensor, which is the product of all dimensions.
    #[must_use]
    pub fn size(&self) -> u32 {
        self.shape().iter().product()
    }

    /// Return a mutable slice of the tensor data.
    ///
    /// Returns `None` if the tensor is not a 1D tensor with a contiguous
    /// layout.
    pub fn as_mut_slice(&mut self) -> Option<&mut [T]> {
        if self.rank() != 1 || self.stride[0] != 1 {
            return None;
        }
        let slice = unsafe { std::slice::from_raw_parts_mut(self.data, self.shape[0] as usize) };
        Some(slice)
    }

    /// Adjusts the `MAX_RANK` of the tensor to a new value.
    ///
    /// # Panics
    ///
    /// Panics if the new `MAX_RANK` is less than the current rank of the
    /// tensor.
    pub fn with_max_rank<const N: usize>(&mut self) -> TensorMut<'_, T, N> {
        assert!(
            N >= self.rank(),
            "New MAX_RANK must be at least the current rank"
        );
        let mut shape = [0; N];
        let mut stride = [0; N];
        for i in 0..self.rank() {
            shape[i] = self.shape[i];
            stride[i] = self.stride[i];
        }
        TensorMut {
            data: self.data,
            shape,
            stride,
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
        assert!(axes.len() == self.rank(), "Invalid axes size for transpose");
        let mut shape = [0; MAX_RANK];
        let mut stride = [0; MAX_RANK];
        let mut used = [false; MAX_RANK];
        for (i, &axis) in axes.iter().enumerate() {
            assert!(
                axis < self.rank(),
                "Axis {axis} out of bounds for rank {}",
                self.rank()
            );
            assert!(
                !used[axis],
                "Axis {axis} is used multiple times in transpose",
            );
            used[axis] = true;
            shape[i] = self.shape[axis];
            stride[i] = self.stride[axis];
        }
        TensorMut {
            data: self.data,
            shape,
            stride,
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
    pub fn get(&mut self, dim: usize, index: usize) -> TensorMut<'_, T, MAX_RANK> {
        assert!(dim < self.rank(), "Dimension {dim} out of bounds");
        assert!(
            index < self.shape[dim] as usize,
            "Index {index} out of bounds for dimension {dim}",
        );
        let offset = index * self.stride[dim] as usize;
        let mut shape = [0; MAX_RANK];
        let mut stride = [0; MAX_RANK];
        for i in 0..self.rank() {
            if i < dim {
                shape[i] = self.shape[i];
                stride[i] = self.stride[i];
            } else if i > dim {
                shape[i - 1] = self.shape[i];
                stride[i - 1] = self.stride[i];
            }
        }
        TensorMut {
            data: unsafe { self.data.add(offset) },
            shape,
            stride,
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
    pub fn split(
        &mut self,
        dim: usize,
        index: usize,
    ) -> (TensorMut<'_, T, MAX_RANK>, TensorMut<'_, T, MAX_RANK>) {
        assert!(dim < self.rank(), "Dimension {dim} out of bounds");
        assert!(
            index < self.shape[dim] as usize,
            "Index {index} out of bounds for dimension {dim}",
        );
        let mut left_shape = self.shape;
        let mut right_shape = self.shape;
        left_shape[dim] = index as u32;
        right_shape[dim] -= index as u32;
        let right_offset = index * self.stride[dim] as usize;
        (
            TensorMut {
                data:      self.data,
                shape:     left_shape,
                stride:    self.stride,
                _lifetime: PhantomData,
            },
            TensorMut {
                data:      unsafe { self.data.add(right_offset) },
                shape:     right_shape,
                stride:    self.stride,
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
        let sizes = sizes.as_ref();
        assert!(dim < self.rank(), "Dimension {dim} out of bounds");
        assert!(
            self.rank() + sizes.len() > MAX_RANK,
            "Resulting tensor rank exceeds MAX_RANK"
        );
        assert_eq!(
            sizes.iter().product::<usize>(),
            self.shape[dim] as usize,
            "The product of sis must equal the original size."
        );

        let mut shape = self.shape;
        let mut stride = self.stride;
        let mut s = self.stride[dim];
        for (i, &size) in sizes.iter().enumerate().rev() {
            shape[dim + i] = size as u32;
            stride[dim + i] = s;
            s *= size as u32;
        }
        for i in (dim + sizes.len())..self.rank() {
            shape[i] = self.shape[i + 1 - sizes.len()];
            stride[i] = self.stride[i + 1 - sizes.len()];
        }

        TensorMut {
            data: self.data,
            shape,
            stride,
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
        assert!(
            dims.end <= self.rank(),
            "Dimension {} out of bounds",
            dims.end
        );
        // Check if the dimensions are in row-major order
        let mut stride = self.stride[dims.end - 1];
        for d in dims.clone().rev() {
            if self.stride[d] != stride {
                return None; // Not in row-major order
            }
            stride *= self.shape[d];
        }

        let mut shape = [0; MAX_RANK];
        let mut stride = [0; MAX_RANK];
        for d in 0..dims.start {
            shape[d] = self.shape[d];
            stride[d] = self.stride[d];
        }
        shape[dims.start] = self.shape[dims.clone()].iter().product::<u32>();
        stride[dims.start] = self.stride[dims.end - 1];
        for d in dims.end..self.rank() {
            shape[d - dims.len() + 1] = self.shape[d];
            stride[d - dims.len() + 1] = self.stride[d];
        }
        Some(TensorMut {
            data: self.data,
            shape,
            stride,
            _lifetime: PhantomData,
        })
    }
}

impl<'a, T, const MAX_RANK: usize> From<&'a mut [T]> for TensorMut<'a, T, MAX_RANK> {
    fn from(value: &mut [T]) -> Self {
        assert!(MAX_RANK >= 1, "Tesnor rank must be at least 1");
        let mut shape = [0; MAX_RANK];
        let mut stride = [0; MAX_RANK];
        shape[0] = value.len().try_into().expect("Tensor size out of range");
        stride[0] = 1;
        TensorMut {
            data: value.as_mut_ptr(),
            shape,
            stride,
            _lifetime: PhantomData,
        }
    }
}

impl<'a, T, const MAX_RANK: usize, I> Index<I> for TensorMut<'a, T, MAX_RANK>
where
    I: AsRef<[usize]>,
{
    type Output = T;

    fn index(&self, index: I) -> &Self::Output {
        let index = index.as_ref();
        assert!(
            index.len() == self.rank(),
            "Index size {} does not match tensor rank {}",
            index.len(),
            self.rank()
        );
        let mut offset = 0;
        for (d, &i) in index.iter().enumerate() {
            assert!(
                i < self.shape[d] as usize,
                "Index {i} out of bounds for dimension {d} with size {}",
                self.shape[d]
            );
            offset += i * self.stride[d] as usize;
        }
        unsafe { &*self.data.add(offset) }
    }
}

impl<T, const MAX_RANK: usize, I> IndexMut<I> for TensorMut<'_, T, MAX_RANK>
where
    I: AsRef<[usize]>,
{
    fn index_mut(&mut self, index: I) -> &mut T {
        let index = index.as_ref();
        assert!(
            index.len() == self.rank(),
            "Index size {} does not match tensor rank {}",
            index.len(),
            self.rank()
        );
        let mut offset = 0;
        for (d, &i) in index.iter().enumerate() {
            assert!(
                i < self.shape[d] as usize,
                "Index {i} out of bounds for dimension {d} with size {}",
                self.shape[d]
            );
            offset += i * self.stride[d] as usize;
        }
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
        let (left, right) = tensor.split(0, 4);
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
        assert_eq!(tensor.shape, [2, 2, 2]);
        assert_eq!(tensor.stride, [4, 2, 1]);
        assert_eq!(tensor[[0, 0, 0]], 1);
        assert_eq!(tensor[[1, 0, 0]], 5);
        assert_eq!(tensor[[0, 1, 1]], 4);
        assert_eq!(tensor[[1, 1, 1]], 8);
    }
}
