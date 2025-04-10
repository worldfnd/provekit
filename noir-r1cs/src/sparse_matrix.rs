use {
    crate::{FieldElement, InternedFieldElement, Interner},
    ark_std::Zero,
    itertools::Itertools as _,
    serde::{Deserialize, Serialize},
    std::{
        fmt::Debug,
        iter::once,
        ops::{Mul, Range},
    },
};
/// A sparse matrix with interned field elements
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SparseMatrix {
    /// The number of rows in the matrix.
    pub rows: usize,

    /// The number of columns in the matrix.
    pub cols: usize,

    // Start of each row
    row_indices: Vec<u32>,

    // List of column indices that have values
    col_indices: Vec<u32>,

    // List of values
    values: Vec<InternedFieldElement>,
}

/// A hydrated sparse matrix with uninterned field elements
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HydratedSparseMatrix<'a> {
    matrix:   &'a SparseMatrix,
    interner: &'a Interner,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            row_indices: vec![0; rows],
            col_indices: Vec::new(),
            values: Vec::new(),
        }
    }

    pub fn hydrate<'a>(&'a self, interner: &'a Interner) -> HydratedSparseMatrix<'a> {
        HydratedSparseMatrix {
            matrix: self,
            interner,
        }
    }

    pub fn num_entries(&self) -> usize {
        self.values.len()
    }

    pub fn grow(&mut self, rows: usize, cols: usize) {
        // TODO: Make it default infinite size instead.
        assert!(rows >= self.rows);
        assert!(cols >= self.cols);
        self.rows = rows;
        self.cols = cols;
        self.row_indices.resize(rows, self.values.len() as u32);
    }

    /// Set the value at the given row and column.
    pub fn set(&mut self, row: usize, col: usize, value: InternedFieldElement) {
        assert!(row < self.rows, "row index out of bounds");
        assert!(col < self.cols, "column index out of bounds");

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
                if row_range.end < self.row_indices.len() {
                    for index in &mut self.row_indices[row_range.end..] {
                        *index += 1;
                    }
                }
            }
        }
    }

    fn row_range(&self, row: usize) -> Range<usize> {
        let start = *self.row_indices.get(row).expect("Row index out of bounds") as usize;
        let end = self
            .row_indices
            .get(row + 1)
            .map(|&v| v as usize)
            .unwrap_or(self.values.len());
        start..end
    }
}

impl<'a> HydratedSparseMatrix<'a> {
    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), FieldElement)> + use<'_> {
        // Get row ranges
        let rows = self
            .matrix
            .row_indices
            .iter()
            .copied()
            .chain(once(self.matrix.values.len() as u32))
            .tuple_windows()
            .map(|(start, end)| (start as usize..end as usize))
            .enumerate();

        // Iterate over rows
        rows.flat_map(|(row, row_range)| {
            let cols = self.matrix.col_indices[row_range.clone()].iter().copied();
            let values = self.matrix.values[row_range.clone()]
                .iter()
                .copied()
                .map(|v| self.interner.get(v).expect("Value not in interner."));
            cols.zip(values)
                .map(move |(col, value)| ((row, col as usize), value))
        })
    }

    /// Iterate over the non-default entries of a row of the matrix.
    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, FieldElement)> + use<'_> {
        let row_range = self.matrix.row_range(row);
        let cols = self.matrix.col_indices[row_range.clone()].iter().copied();
        let values = self.matrix.values[row_range.clone()]
            .iter()
            .copied()
            .map(|v| self.interner.get(v).expect("Value not in interner."));
        cols.zip(values).map(|(col, value)| (col as usize, value))
    }
}

/// Right multiplication by vector
impl Mul<&[FieldElement]> for HydratedSparseMatrix<'_> {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: &[FieldElement]) -> Self::Output {
        assert_eq!(
            self.matrix.cols,
            rhs.len(),
            "Vector length does not match number of columns."
        );
        let mut result = vec![FieldElement::zero(); self.matrix.rows];
        for ((i, j), value) in self.iter() {
            result[i] += value * &rhs[j];
        }
        result
    }
}

/// Left multiplication by vector
impl Mul<HydratedSparseMatrix<'_>> for &[FieldElement] {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: HydratedSparseMatrix<'_>) -> Self::Output {
        assert_eq!(
            self.len(),
            rhs.matrix.rows,
            "Vector length does not match number of rows."
        );
        let mut result = vec![FieldElement::zero(); rhs.matrix.cols];
        for ((i, j), value) in rhs.iter() {
            result[j] += value * &self[i];
        }
        result
    }
}
