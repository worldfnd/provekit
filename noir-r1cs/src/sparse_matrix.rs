use {
    crate::{FieldElement, InternedFieldElement, Interner},
    ark_std::Zero,
    serde::{Deserialize, Serialize},
    std::{collections::BTreeMap, fmt::Debug, ops::Mul},
};

// TODO: Compressed Row Storage with Interning of field elements.

/// A sparse matrix with interned field elements
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SparseMatrix {
    /// The number of rows in the matrix.
    pub rows: usize,

    /// The number of columns in the matrix.
    pub cols: usize,

    /// The default value of the matrix.
    default: InternedFieldElement,

    /// The non-default entries of the matrix.
    #[serde(skip)]
    entries: BTreeMap<(usize, usize), InternedFieldElement>,
}

/// A hydrated sparse matrix with uninterned field elements
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HydratedSparseMatrix<'a> {
    default:  FieldElement,
    matrix:   &'a SparseMatrix,
    interner: &'a Interner,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize, default: InternedFieldElement) -> Self {
        Self {
            rows,
            cols,
            default,
            entries: BTreeMap::new(),
        }
    }

    pub fn hydrate<'a>(&'a self, interner: &'a Interner) -> HydratedSparseMatrix<'a> {
        let default = interner
            .get(self.default)
            .expect("Default value not in interner.");
        HydratedSparseMatrix {
            default,
            matrix: self,
            interner,
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
    pub fn set(&mut self, row: usize, col: usize, value: InternedFieldElement) {
        assert!(row < self.rows, "row index out of bounds");
        assert!(col < self.cols, "column index out of bounds");
        self.entries.insert((row, col), value);
    }

    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), InternedFieldElement)> + use<'_> {
        self.entries.iter().filter_map(|(&k, &v)| {
            if v != self.default {
                Some((k, v))
            } else {
                None
            }
        })
    }

    /// Iterate over the non-default entries of the given row.
    pub fn iter_row(
        &self,
        row: usize,
    ) -> impl Iterator<Item = (usize, InternedFieldElement)> + use<'_> {
        self.entries
            .range((row, 0)..(row + 1, 0))
            .filter_map(|(&(_, c), &v)| {
                if v != self.default {
                    Some((c, v))
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

impl<'a> HydratedSparseMatrix<'a> {
    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), FieldElement)> + use<'_> {
        self.matrix.entries.iter().filter_map(|(&k, &v)| {
            let v = self.interner.get(v).expect("Value not in interner.");
            if v != self.default {
                Some((k, v))
            } else {
                None
            }
        })
    }

    /// Iterate over the non-default entries of the given row.
    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, FieldElement)> + use<'_> {
        self.matrix
            .entries
            .range((row, 0)..(row + 1, 0))
            .filter_map(|(&(_, c), &v)| {
                let v = self.interner.get(v).expect("Value not in interner.");
                if v != self.default {
                    Some((c, v))
                } else {
                    None
                }
            })
    }
}

/// Right multiplication by vector
impl Mul<&[FieldElement]> for HydratedSparseMatrix<'_> {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: &[FieldElement]) -> Self::Output {
        assert!(self.default.is_zero());
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
