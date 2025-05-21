use {
    acir::{AcirField, FieldElement},
    std::{
        collections::BTreeMap,
        fmt::{Debug, Display, Formatter},
        ops::{AddAssign, Index, IndexMut, Mul},
    },
};

/// A sparse matrix with elements of type `F`.
#[derive(Debug, Clone, Default)]
pub struct SparseMatrix<F> {
    /// The number of rows in the matrix.
    pub rows: usize,

    /// The number of columns in the matrix.
    pub cols: usize,

    /// The default value of the matrix.
    pub default: F,

    /// The non-default entries of the matrix.
    pub entries: BTreeMap<(usize, usize), F>,
}

impl<F> SparseMatrix<F> {
    pub fn new(rows: usize, cols: usize, default: F) -> Self {
        Self {
            rows,
            cols,
            default,
            entries: BTreeMap::new(),
        }
    }

    pub fn grow(&mut self, rows: usize, cols: usize) {
        // TODO: Make it default infinite size instead.
        assert!(rows >= self.rows);
        assert!(cols >= self.cols);
        self.rows = rows;
        self.cols = cols;
    }

    /// Set the value at the given row and column.
    pub fn set(&mut self, row: usize, col: usize, value: F) {
        assert!(row < self.rows, "row index out of bounds");
        assert!(col < self.cols, "column index out of bounds");
        self.entries.insert((row, col), value);
    }

    /// Return a dense representation of the matrix.
    /// (This is a helper method for debugging.)
    fn to_dense(&self) -> Vec<Vec<F>>
    where
        F: Clone,
    {
        let mut result = vec![vec![self.default.clone(); self.cols]; self.rows];
        for ((i, j), value) in self.entries.iter() {
            result[*i][*j] = value.clone();
        }
        result
    }
}

/// Print a dense representation of the matrix, for debugging.
impl<F: Debug + Clone> Display for SparseMatrix<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let dense = self.to_dense();
        for row in dense.iter() {
            for value in row.iter() {
                write!(f, "{:?}\t", value)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

impl<F: PartialEq> SparseMatrix<F> {
    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), &F)> {
        self.entries.iter().filter_map(|(k, v)| {
            if v != &self.default {
                Some((*k, v))
            } else {
                None
            }
        })
    }

    // TODO wouldn't it be better to use the CSR format (not the COO format?) for
    // sparse matrices?  There should never be a row without a non-zero entry.
    /// Iterate over the non-default entries of the given row.
    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, &F)> {
        self.entries
            .range((row, 0)..(row + 1, 0))
            .filter_map(|((_, c), v)| {
                if v != &self.default {
                    Some((*c, v))
                } else {
                    None
                }
            })
    }

    /// Remove the default entries from the entries list.
    pub fn cleanup(&mut self) {
        self.entries.retain(|_, v| v != &self.default);
    }
}

impl<F> Index<(usize, usize)> for SparseMatrix<F> {
    type Output = F;

    fn index(&self, (i, j): (usize, usize)) -> &Self::Output {
        assert!(i < self.rows, "row index out of bounds");
        assert!(j < self.cols, "column index out of bounds");
        self.entries.get(&(i, j)).unwrap_or(&self.default)
    }
}

impl<F: Clone> IndexMut<(usize, usize)> for SparseMatrix<F> {
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut Self::Output {
        assert!(i < self.rows, "row index out of bounds");
        assert!(j < self.cols, "column index out of bounds");
        self.entries.entry((i, j)).or_insert(self.default.clone())
    }
}

impl<F> Mul<&[F]> for &SparseMatrix<F>
where
    F: Clone + AddAssign,
    for<'a> &'a F: Mul<Output = F>,
{
    type Output = Vec<F>;

    fn mul(self, rhs: &[F]) -> Self::Output {
        assert_eq!(
            self.cols,
            rhs.len(),
            "Vector length does not match number of columns."
        );
        let mut result = vec![self.default.clone(); self.rows];
        for ((i, j), value) in self.entries.iter() {
            result[*i] += value * &rhs[*j];
        }
        result
    }
}

pub fn mat_mul(a: &SparseMatrix<FieldElement>, b: &[FieldElement]) -> Vec<FieldElement> {
    let mut result = vec![FieldElement::zero(); a.rows];
    for ((i, j), &value) in a.iter() {
        result[i] += value * b[j];
    }
    result
}
