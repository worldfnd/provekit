use std::ops::Range;

/// Tensor memory layout
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Layout<const MAX_RANK: usize = 3> {
    /// Size of each dimension in the tensor, zero padded to fit `MAX_RANK`.
    shape: [u32; MAX_RANK],

    /// Stride for each dimension, zero padded to fit `MAX_RANK`.
    stride: [u32; MAX_RANK],
}

impl<const MAX_RANK: usize> Default for Layout<MAX_RANK> {
    fn default() -> Self {
        Self {
            shape:  [0; MAX_RANK],
            stride: [0; MAX_RANK],
        }
    }
}

impl<const MAX_RANK: usize> Layout<MAX_RANK> {
    /// Create a contiguous one dimensional vector.
    #[must_use]
    pub fn from_size(size: usize) -> Self {
        assert!(MAX_RANK >= 1, "Tensor rank must be at least 1");
        let mut result = Self::default();
        result.shape[0] = size.try_into().expect("Size exceeds u32");
        result.stride[0] = 1;
        result
    }

    /// Returns the number of dimensions in the tensor.
    ///
    /// A rank of `0` indicates a scalar, `1` indicates a vector, and so on.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.shape.iter().position(|&s| s == 0).unwrap_or(MAX_RANK)
    }

    /// Total size of the tensor, which is the product of all dimensions.
    #[must_use]
    pub fn size(&self) -> usize {
        self.shape.iter().take_while(|&&x| x != 0).product::<u32>() as usize
    }

    /// The sizes of each dimension of the tensor.
    #[must_use]
    pub fn shape(&self, dim: usize) -> usize {
        assert!(dim < self.rank(), "Dimension {dim} out of bounds");
        self.shape[dim] as usize
    }

    #[must_use]
    #[inline(always)]
    pub fn offset(&self, index: impl AsRef<[usize]>) -> usize {
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
        offset
    }

    /// Adjusts the `MAX_RANK` of the tensor to a new value.
    ///
    /// # Panics
    ///
    /// Panics if the new `MAX_RANK` is less than the current rank of the
    /// tensor.
    #[must_use]
    pub fn with_max_rank<const N: usize>(&self) -> Layout<N> {
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
        Layout { shape, stride }
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
    pub fn transpose(&self, axes: &[usize]) -> Self {
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
        Self { shape, stride }
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
    pub fn select(&self, dim: usize, index: usize) -> (usize, Self) {
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
        (offset, Self { shape, stride })
    }

    #[must_use]
    pub fn chunk(&self, dim: usize, range: Range<usize>) -> (usize, Self) {
        assert!(dim < self.rank(), "Dimension {dim} out of bounds");
        assert!(
            range.end <= self.shape[dim] as usize,
            "Index {} out of bounds for dimension {dim}",
            range.end - 1
        );
        // TODO: If start > end then .len() will be zero?
        let offset = range.start * self.stride[dim] as usize;
        let mut result = *self;
        result.shape[dim] = range.len() as u32;
        (offset, result)
    }

    /// Split a dimension of the tensor into dimensions of specified
    /// sizes.
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
    pub fn unflatten(&self, dim: usize, sizes: impl AsRef<[usize]>) -> Self {
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

        let mut result = *self;
        let mut stride = self.stride[dim];
        for (i, &size) in sizes.iter().enumerate().rev() {
            result.shape[dim + i] = size as u32;
            result.stride[dim + i] = stride;
            stride *= size as u32;
        }
        for i in (dim + sizes.len())..self.rank() {
            result.shape[i] = self.shape[i + 1 - sizes.len()];
            result.stride[i] = self.stride[i + 1 - sizes.len()];
        }
        result
    }

    /// Flatten a set of dimensions into a single dimension.
    ///
    /// Returns `None` if the dimensions are not in row-major order.
    ///
    /// # Panics
    /// Panics if the dimensions are out of bounds or if the tensor rank is less
    /// than 1.
    pub fn flatten(&self, dims: Range<usize>) -> Option<Layout<MAX_RANK>> {
        if dims.start >= dims.end {
            // Empty range
            return Some(*self);
        }
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

        let mut result = *self;
        result.shape[dims.start] = self.shape[dims.clone()].iter().product::<u32>();
        result.stride[dims.start] = self.stride[dims.end - 1];
        for d in dims.end..self.rank() {
            result.shape[d - dims.len() + 1] = self.shape[d];
            result.stride[d - dims.len() + 1] = self.stride[d];
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {

    // TODO: enumerate the set of accessible offsets and make sure they satisfy
    // invariants.
    // - No offsets out of bounds,
    // - No overlap in disjunct views using `select` and `chunk`.
}
