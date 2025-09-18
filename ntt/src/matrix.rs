use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

pub struct MatrixView<'a, T> {
    data: &'a mut [T],
    rows: usize,
    cols: usize,
}

impl<'a, T> MatrixView<'a, T> {
    pub fn new(data: &'a mut [T], rows: usize, cols: usize) -> Self {
        Self { data, rows, cols }
    }

    pub fn column_stride(self) -> impl Iterator<Item = ColumnView<'a, T>> {
        let cols = self.cols;
        (0..cols).map(move |i| ColumnView {
            data:     self.data as *mut [T],
            offset:   i,
            step:     self.cols,
            n:        self.rows,
            _phantom: PhantomData,
        })
    }
}

/// A view into a single column of a matrix stored in row-major order.
///
/// This allows efficient access to matrix columns without copying data.
/// Elements are accessed with stride `step` starting from `offset`.
///
/// # Examples
///
/// ```ignore
/// let mut data = vec![1, 2, 3, 4, 5, 6]; // Matrix: [[1, 2, 3], [4, 5, 6]]
/// let matrix = MatrixView { data: &mut data, rows: 2, cols: 3 };
/// let mut columns: Vec<_> = stride_matrix(matrix).collect();
///
/// // Access column 0: elements [1, 4]
/// assert_eq!(columns[0][0], 1);
/// assert_eq!(columns[0][1], 4);
///
/// // Modify elements
/// columns[0][0] = 10;
/// assert_eq!(columns[0][0], 10);
/// ```
pub struct ColumnView<'a, T> {
    data:     *mut [T],
    offset:   usize, // the actual column
    step:     usize, // elements in a row
    n:        usize, // number of rows in data / elements in a column
    _phantom: PhantomData<&'a mut T>,
}

unsafe impl<'a, T> Send for ColumnView<'a, T> {}

impl<'a, T> ColumnView<'a, T> {
    /// Returns the number of elements in this column view.
    pub fn len(&self) -> usize {
        self.n
    }

    /// Returns `true` if the column view contains no elements.
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Returns a reference to the element at the given index, or `None` if out
    /// of bounds.
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.n {
            unsafe {
                let slice = &*self.data;
                Some(&slice[self.offset + index * self.step])
            }
        } else {
            None
        }
    }

    /// Returns a mutable reference to the element at the given index, or `None`
    /// if out of bounds.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.n {
            unsafe {
                let slice = &mut *self.data;
                Some(&mut slice[self.offset + index * self.step])
            }
        } else {
            None
        }
    }
}

// Standard Rust pattern: Index/IndexMut reuse get/get_mut logic
// This avoids code duplication and ensures consistency between the two access
// patterns
impl<'a, T> Index<usize> for ColumnView<'a, T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).unwrap_or_else(|| {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                self.n, index
            )
        })
    }
}

impl<'a, T> IndexMut<usize> for ColumnView<'a, T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let len = self.n; // Capture len before mutable borrow
        self.get_mut(index).unwrap_or_else(|| {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                len, index
            )
        })
    }
}
