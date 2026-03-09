use {
    crate::{
        interner::InternedFieldElement, FieldElement, HydratedSparseMatrix, Interner, SparseMatrix,
    },
    ark_ff::Zero,
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
};

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1CS {
    pub num_public_inputs: usize,
    pub interner:          Interner,
    pub a:                 SparseMatrix,
    pub b:                 SparseMatrix,
    pub c:                 SparseMatrix,
}

impl Default for R1CS {
    fn default() -> Self {
        Self::new()
    }
}

impl R1CS {
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_public_inputs: 0,
            interner:          Interner::new(),
            a:                 SparseMatrix::new(0, 0),
            b:                 SparseMatrix::new(0, 0),
            c:                 SparseMatrix::new(0, 0),
        }
    }

    #[must_use]
    pub const fn a(&self) -> HydratedSparseMatrix<'_> {
        self.a.hydrate(&self.interner)
    }

    #[must_use]
    pub const fn b(&self) -> HydratedSparseMatrix<'_> {
        self.b.hydrate(&self.interner)
    }

    #[must_use]
    pub const fn c(&self) -> HydratedSparseMatrix<'_> {
        self.c.hydrate(&self.interner)
    }

    /// The number of constraints in the R1CS instance.
    pub const fn num_constraints(&self) -> usize {
        self.a.num_rows
    }

    /// The number of witnesses in the R1CS instance (including the constant one
    /// witness).
    pub const fn num_witnesses(&self) -> usize {
        self.a.num_cols
    }

    // Increase the size of the R1CS matrices to the specified dimensions.
    pub fn grow_matrices(&mut self, num_rows: usize, num_cols: usize) {
        self.a.grow(num_rows, num_cols);
        self.b.grow(num_rows, num_cols);
        self.c.grow(num_rows, num_cols);
    }

    /// Add a new witnesses to the R1CS instance.
    pub fn add_witnesses(&mut self, count: usize) {
        self.grow_matrices(self.num_constraints(), self.num_witnesses() + count);
    }

    /// Add an R1CS constraint.
    pub fn add_constraint(
        &mut self,
        a: &[(FieldElement, usize)],
        b: &[(FieldElement, usize)],
        c: &[(FieldElement, usize)],
    ) {
        let next_constraint_idx = self.num_constraints();
        self.grow_matrices(self.num_constraints() + 1, self.num_witnesses());

        for (coeff, witness_idx) in a.iter().copied() {
            self.a.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
        for (coeff, witness_idx) in b.iter().copied() {
            self.b.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
        for (coeff, witness_idx) in c.iter().copied() {
            self.c.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
    }

    pub fn reserve_constraints(&mut self, num_constraints: usize, total_entries: usize) {
        let entries_per_matrix = total_entries / 3 + 1;
        self.a.reserve(num_constraints, entries_per_matrix);
        self.b.reserve(num_constraints, entries_per_matrix);
        self.c.reserve(num_constraints, entries_per_matrix);
    }

    #[inline]
    pub fn push_constraint(
        &mut self,
        a: impl Iterator<Item = (u32, InternedFieldElement)>,
        b: impl Iterator<Item = (u32, InternedFieldElement)>,
        c: impl Iterator<Item = (u32, InternedFieldElement)>,
    ) {
        self.a.push_row(a);
        self.b.push_row(b);
        self.c.push_row(c);
    }

    #[inline]
    pub fn intern(&mut self, value: FieldElement) -> InternedFieldElement {
        self.interner.intern(value)
    }

    /// Check if constraint `row` is linear, meaning it can be reduced to
    /// a linear equation over witness variables.
    ///
    /// An R1CS constraint `A·w * B·w = C·w` is linear when at least one of
    /// A or B evaluates to a known constant (only references column 0, the
    /// constant-one witness). This covers:
    /// - Both A and B empty: `0 * 0 = C·w` → `C·w = 0`
    /// - B only references w0: `A·w * const = C·w` → `const*A·w - C·w = 0`
    /// - A only references w0: `const * B·w = C·w` → `const*B·w - C·w = 0`
    pub fn is_linear_constraint(&self, row: usize) -> bool {
        let a_is_const = self.row_is_constant(&self.a, row);
        let b_is_const = self.row_is_constant(&self.b, row);
        a_is_const || b_is_const
    }

    /// Check if a matrix row is "constant" — either empty or only references
    /// column 0 (the constant-one witness).
    fn row_is_constant(&self, matrix: &SparseMatrix, row: usize) -> bool {
        let entries: Vec<_> = matrix.iter_row(row).collect();
        if entries.is_empty() {
            return true;
        }
        entries.len() == 1 && entries[0].0 == 0
    }

    /// Get the constant value of a "constant" matrix row.
    /// Returns 0 if the row is empty, or the coefficient of w0 if present.
    fn row_constant_value(&self, matrix: &SparseMatrix, row: usize) -> FieldElement {
        match matrix.get(row, 0) {
            Some(interned) => self.interner.get(interned).expect("interned value missing"),
            None => FieldElement::zero(),
        }
    }

    /// Extract the linear expression from a linear constraint.
    ///
    /// Returns a list of (coefficient, witness_index) pairs such that
    /// sum(coeff_i * w_i) = 0.
    pub fn extract_linear_expression(&self, row: usize) -> Vec<(FieldElement, usize)> {
        let a_is_const = self.row_is_constant(&self.a, row);
        let b_is_const = self.row_is_constant(&self.b, row);

        let mut terms: HashMap<usize, FieldElement> = HashMap::new();

        if a_is_const && b_is_const {
            let const_a = self.row_constant_value(&self.a, row);
            let const_b = self.row_constant_value(&self.b, row);
            let product = const_a * const_b;
            if !product.is_zero() {
                *terms.entry(0).or_insert_with(FieldElement::zero) += product;
            }
            for (col, interned_val) in self.c.iter_row(row) {
                let val = self
                    .interner
                    .get(interned_val)
                    .expect("interned value missing");
                *terms.entry(col).or_insert_with(FieldElement::zero) -= val;
            }
        } else if a_is_const {
            let const_a = self.row_constant_value(&self.a, row);
            for (col, interned_val) in self.b.iter_row(row) {
                let val = self
                    .interner
                    .get(interned_val)
                    .expect("interned value missing");
                *terms.entry(col).or_insert_with(FieldElement::zero) += const_a * val;
            }
            for (col, interned_val) in self.c.iter_row(row) {
                let val = self
                    .interner
                    .get(interned_val)
                    .expect("interned value missing");
                *terms.entry(col).or_insert_with(FieldElement::zero) -= val;
            }
        } else {
            let const_b = self.row_constant_value(&self.b, row);
            for (col, interned_val) in self.a.iter_row(row) {
                let val = self
                    .interner
                    .get(interned_val)
                    .expect("interned value missing");
                *terms.entry(col).or_insert_with(FieldElement::zero) += const_b * val;
            }
            for (col, interned_val) in self.c.iter_row(row) {
                let val = self
                    .interner
                    .get(interned_val)
                    .expect("interned value missing");
                *terms.entry(col).or_insert_with(FieldElement::zero) -= val;
            }
        }

        let mut result: Vec<_> = terms
            .into_iter()
            .filter(|(_, v)| !v.is_zero())
            .map(|(col, val)| (val, col))
            .collect();
        result.sort_by_key(|(_, col)| *col);
        result
    }

    /// Remove constraints at the given row indices from all three matrices.
    pub fn remove_constraints(&mut self, rows_to_remove: &[usize]) {
        self.a = self.a.remove_rows(rows_to_remove);
        self.b = self.b.remove_rows(rows_to_remove);
        self.c = self.c.remove_rows(rows_to_remove);
    }
}
