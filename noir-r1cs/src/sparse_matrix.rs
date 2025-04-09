use {
    crate::{utils::serde_ark, FieldElement},
    ark_std::Zero,
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
        fmt::{Debug, Display, Formatter},
        ops::{Index, IndexMut, Mul},
    },
};

/// A sparse matrix with elements of type `F`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SparseMatrix {
    /// The number of rows in the matrix.
    pub rows: usize,

    /// The number of columns in the matrix.
    pub cols: usize,

    /// The default value of the matrix.
    #[serde(with = "serde_ark")]
    default: FieldElement,

    /// The non-default entries of the matrix.
    #[serde(with = "serde_ark")]
    entries: BTreeMap<(usize, usize), FieldElement>,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize, default: FieldElement) -> Self {
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
    pub fn set(&mut self, row: usize, col: usize, value: FieldElement) {
        assert!(row < self.rows, "row index out of bounds");
        assert!(col < self.cols, "column index out of bounds");
        self.entries.insert((row, col), value);
    }

    /// Return a dense representation of the matrix.
    /// (This is a helper method for debugging.)
    fn to_dense(&self) -> Vec<Vec<FieldElement>> {
        let mut result = vec![vec![self.default.clone(); self.cols]; self.rows];
        for ((i, j), value) in self.entries.iter() {
            result[*i][*j] = value.clone();
        }
        result
    }
}

/// Print a dense representation of the matrix, for debugging.
impl Display for SparseMatrix {
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

impl SparseMatrix {
    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), &FieldElement)> {
        self.entries.iter().filter_map(|(k, v)| {
            if v != &self.default {
                Some((*k, v))
            } else {
                None
            }
        })
    }

    /// Iterate over the non-default entries of the given row.
    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, &FieldElement)> {
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

impl Index<(usize, usize)> for SparseMatrix {
    type Output = FieldElement;

    fn index(&self, (i, j): (usize, usize)) -> &Self::Output {
        assert!(i < self.rows, "row index out of bounds");
        assert!(j < self.cols, "column index out of bounds");
        self.entries.get(&(i, j)).unwrap_or(&self.default)
    }
}

impl IndexMut<(usize, usize)> for SparseMatrix {
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut Self::Output {
        assert!(i < self.rows, "row index out of bounds");
        assert!(j < self.cols, "column index out of bounds");
        self.entries.entry((i, j)).or_insert(self.default.clone())
    }
}

/// Right multiplication by vector
impl Mul<&[FieldElement]> for &SparseMatrix {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: &[FieldElement]) -> Self::Output {
        assert!(self.default.is_zero());
        assert_eq!(
            self.cols,
            rhs.len(),
            "Vector length does not match number of columns."
        );
        let mut result = vec![FieldElement::zero(); self.rows];
        for ((i, j), value) in self.entries.iter() {
            result[*i] += value * &rhs[*j];
        }
        result
    }
}

/// Left multiplication by vector
impl Mul<&SparseMatrix> for &[FieldElement] {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: &SparseMatrix) -> Self::Output {
        assert_eq!(
            self.len(),
            rhs.rows,
            "Vector length does not match number of rows."
        );
        let mut result = vec![FieldElement::zero(); rhs.cols];
        for ((i, j), value) in rhs.entries.iter() {
            result[*j] += value * &self[*i];
        }
        result
    }
}
