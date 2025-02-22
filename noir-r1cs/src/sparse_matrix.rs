use std::{
    collections::BTreeMap,
    ops::{Add, AddAssign, Index, IndexMut, Mul},
};

/// A sparse matrix with elements of type `F`.
#[derive(Debug, Clone, Default)]
pub struct SparseMatrix<F> {
    /// The number of rows in the matrix.
    rows: usize,

    /// The number of columns in the matrix.
    cols: usize,

    /// The default value of the matrix.
    default: F,

    /// The non-default entries of the matrix.
    entries: BTreeMap<(usize, usize), F>,
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

    /// Set the value at the given row and column.
    pub fn set(&mut self, row: usize, col: usize, value: F) {
        assert!(row < self.rows, "row index out of bounds");
        assert!(col < self.cols, "column index out of bounds");
        self.entries.insert((row, col), value);
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
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

impl<F> Mul<Vec<F>> for &SparseMatrix<F>
where
    F: Clone + AddAssign,
    for<'a> &'a F: Mul<Output = F>,
{
    type Output = Vec<F>;

    fn mul(self, rhs: Vec<F>) -> Self::Output {
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
