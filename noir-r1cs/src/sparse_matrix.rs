use {
    crate::{FieldElement, InternedFieldElement, Interner},
    ark_std::Zero,
    rayon::iter::{
        IndexedParallelIterator, IntoParallelIterator, ParallelBridge, ParallelIterator,
    },
    serde::{Deserialize, Serialize},
    std::{
        cell::UnsafeCell,
        fmt::Debug,
        ops::{Mul, Range},
    },
};
/// A sparse matrix with interned field elements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMatrix {
    /// The number of rows in the matrix.
    pub num_rows: usize,

    /// The number of columns in the matrix.
    pub num_cols: usize,

    // List of indices in `col_indices` such that the column index is the start of a new row.
    new_row_indices: Vec<u32>,

    // List of column indices that have values
    col_indices: Vec<u32>,

    // List of values
    values: Vec<InternedFieldElement>,
}

/// A hydrated sparse matrix with uninterned field elements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydratedSparseMatrix<'a> {
    matrix:   &'a SparseMatrix,
    interner: &'a Interner,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            num_rows:        rows,
            num_cols:        cols,
            new_row_indices: vec![0; rows],
            col_indices:     Vec::new(),
            values:          Vec::new(),
        }
    }

    pub const fn hydrate<'a>(&'a self, interner: &'a Interner) -> HydratedSparseMatrix<'a> {
        HydratedSparseMatrix {
            matrix: self,
            interner,
        }
    }

    pub const fn num_entries(&self) -> usize {
        self.values.len()
    }

    pub fn grow(&mut self, rows: usize, cols: usize) {
        // TODO: Make it default infinite size instead.
        assert!(rows >= self.num_rows);
        assert!(cols >= self.num_cols);
        self.num_rows = rows;
        self.num_cols = cols;
        self.new_row_indices.resize(rows, self.values.len() as u32);
    }

    /// Set the value at the given row and column.
    pub fn set(&mut self, row: usize, col: usize, value: InternedFieldElement) {
        assert!(row < self.num_rows, "row index out of bounds");
        assert!(col < self.num_cols, "column index out of bounds");

        // Find the row
        let row_range = self.row_range(row);
        let cols = &self.col_indices[row_range.clone()];

        // Find the column
        match cols.binary_search(&(col as u32)) {
            Ok(i) => {
                // Column already exists
                self.values[row_range][i] = value;
            }
            Err(i) => {
                // Need to insert column at i
                let i = i + row_range.start;
                self.col_indices.insert(i, col as u32);
                self.values.insert(i, value);
                for index in &mut self.new_row_indices[row + 1..] {
                    *index += 1;
                }
            }
        }
    }

    /// Iterate over the non-default entries of a row of the matrix.
    pub fn iter_row(
        &self,
        row: usize,
    ) -> impl Iterator<Item = (usize, InternedFieldElement)> + use<'_> {
        let row_range = self.row_range(row);
        let cols = self.col_indices[row_range.clone()].iter().copied();
        let values = self.values[row_range].iter().copied();
        cols.zip(values).map(|(col, value)| (col as usize, value))
    }

    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), InternedFieldElement)> + use<'_> {
        (0..self.new_row_indices.len()).flat_map(|row| {
            self.iter_row(row)
                .map(move |(col, value)| ((row, col), value))
        })
    }

    fn row_range(&self, row: usize) -> Range<usize> {
        let start = *self
            .new_row_indices
            .get(row)
            .expect("Row index out of bounds") as usize;
        let end = self
            .new_row_indices
            .get(row + 1)
            .map_or(self.values.len(), |&v| v as usize);
        start..end
    }
}

impl HydratedSparseMatrix<'_> {
    /// Iterate over the non-default entries of a row of the matrix.
    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, FieldElement)> + use<'_> {
        self.matrix.iter_row(row).map(|(col, value)| {
            (
                col,
                self.interner.get(value).expect("Value not in interner."),
            )
        })
    }

    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), FieldElement)> + use<'_> {
        self.matrix.iter().map(|((i, j), v)| {
            (
                (i, j),
                self.interner.get(v).expect("Value not in interner."),
            )
        })
    }
}

/// Right multiplication by vector
impl Mul<&[FieldElement]> for HydratedSparseMatrix<'_> {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: &[FieldElement]) -> Self::Output {
        assert_eq!(
            self.matrix.num_cols,
            rhs.len(),
            "Vector length does not match number of columns."
        );

        let mut result = Vec::with_capacity(self.matrix.num_rows);

        (0..self.matrix.num_rows)
            .into_par_iter()
            .map(|i| {
                self.iter_row(i)
                    .fold(FieldElement::zero(), |sum, (j, value)| sum + value * rhs[j])
            })
            .collect_into_vec(&mut result);
        result
    }
}

// Provide interior mutability where
struct LockFreeArray<T>(UnsafeCell<Box<[T]>>);
unsafe impl<T: Sync + Send> Send for LockFreeArray<T> {}
unsafe impl<T: Sync + Send> Sync for LockFreeArray<T> {}

impl<T> LockFreeArray<T> {
    fn new(vec: Vec<T>) -> Self {
        let arr = vec.into_boxed_slice();
        LockFreeArray(UnsafeCell::new(arr))
    }

    // Requires that only one thread has access to index and that the index is
    // within bounds.
    unsafe fn insert(&self, index: usize, value: T) {
        let vec = { &mut **self.0.get() };
        vec[index] = value;
    }
}

/// Left multiplication by vector
impl Mul<HydratedSparseMatrix<'_>> for &[FieldElement] {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: HydratedSparseMatrix<'_>) -> Self::Output {
        assert_eq!(
            self.len(),
            rhs.matrix.num_rows,
            "Vector length does not match number of rows."
        );

        let intermediate_multiplication =
            LockFreeArray::new(vec![(0, FieldElement::zero()); rhs.matrix.num_entries()]);

        let intermediate_reference = &intermediate_multiplication;

        // Mapping phase
        //
        // Parallelize the multiplication
        // Use a lock-free array to prevent constant resizing when collecting the
        // iterator as the size is not known to Rayon. Collecting without a
        // preallocating the intermediate vector is >15% slower
        // Other options that have been explored
        // - An IndexedParallelIterator on the values of the sparse matrix also wasn't
        //   an option as it requires random access which we can't provide as we
        //   wouldn't know the row a value belongs to. That's why the rows drive the
        //   iterator below.
        // - Acquiring a mutex per column in the result was too expensive (even with
        //   parking_lot)

        (0..rhs.matrix.num_rows).into_par_iter().for_each(|row| {
            let range = rhs.matrix.row_range(row);
            rhs.iter_row(row)
                .zip(range)
                .for_each(move |((col, value), ind)| unsafe {
                    intermediate_reference.insert(ind, (col, value * self[row]))
                })
        });

        let mut result = vec![FieldElement::zero(); rhs.matrix.num_cols];

        // Reduce phase
        // Single thread for folding to not have a mutex per column in the result.

        for (j, value) in intermediate_multiplication.0.into_inner() {
            result[j] += value;
        }

        result
    }
}
