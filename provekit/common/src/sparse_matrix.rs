use {
    crate::{FieldElement, InternedFieldElement, Interner},
    ark_std::Zero,
    rayon::iter::{IntoParallelRefMutIterator, ParallelIterator},
    serde::{Deserialize, Serialize},
    std::{
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
    pub matrix: &'a SparseMatrix,
    interner:   &'a Interner,
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

    /// Remap column indices using provided mapping function - in-place and
    /// parallel
    pub fn remap_columns<F>(&mut self, remap_fn: F)
    where
        F: Fn(usize) -> usize + Send + Sync,
    {
        // Step 1: Remap all column indices in parallel
        self.col_indices.par_iter_mut().for_each(|col| {
            *col = remap_fn(*col as usize) as u32;
        });

        // Step 2: Re-sort each row sequentially (fast enough, avoids unsafe)
        for row in 0..self.num_rows {
            let start = self.new_row_indices[row] as usize;
            let end = self
                .new_row_indices
                .get(row + 1)
                .map_or(self.col_indices.len(), |&v| v as usize);

            let row_cols = &mut self.col_indices[start..end];
            let row_vals = &mut self.values[start..end];

            let mut pairs: Vec<_> = row_cols
                .iter()
                .zip(row_vals.iter())
                .map(|(&c, &v)| (c, v))
                .collect();
            pairs.sort_unstable_by_key(|(c, _)| *c);

            for (i, (c, v)) in pairs.into_iter().enumerate() {
                row_cols[i] = c;
                row_vals[i] = v;
            }
        }
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
// OPT: Paralelize
impl Mul<&[FieldElement]> for HydratedSparseMatrix<'_> {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: &[FieldElement]) -> Self::Output {
        assert_eq!(
            self.matrix.num_cols,
            rhs.len(),
            "Vector length does not match number of columns."
        );
        let mut result = vec![FieldElement::zero(); self.matrix.num_rows];
        for ((i, j), value) in self.iter() {
            result[i] += value * rhs[j];
        }
        result
    }
}

/// Left multiplication by vector
// OPT: Paralelize
impl Mul<HydratedSparseMatrix<'_>> for &[FieldElement] {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: HydratedSparseMatrix<'_>) -> Self::Output {
        assert_eq!(
            self.len(),
            rhs.matrix.num_rows,
            "Vector length does not match number of rows."
        );
        let mut result = vec![FieldElement::zero(); rhs.matrix.num_cols];
        for ((i, j), value) in rhs.iter() {
            result[j] += value * self[i];
        }
        result
    }
}
