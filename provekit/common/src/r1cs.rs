use {
    crate::{
        interner::InternedFieldElement, FieldElement, HydratedSparseMatrix, Interner, SparseMatrix,
    },
    ark_ff::Zero,
    serde::{Deserialize, Serialize},
    sha3::{Digest, Sha3_256},
    std::collections::HashMap,
};

fn has_duplicate_witnesses(terms: &[(FieldElement, usize)]) -> bool {
    for i in 0..terms.len() {
        for j in (i + 1)..terms.len() {
            if terms[i].1 == terms[j].1 {
                return true;
            }
        }
    }
    false
}

/// Merge duplicate witness indices and drop zero-coefficient entries.
fn canonicalize_terms(terms: &[(FieldElement, usize)]) -> Vec<(FieldElement, usize)> {
    if !has_duplicate_witnesses(terms) {
        return terms
            .iter()
            .filter(|(c, _)| !c.is_zero())
            .copied()
            .collect();
    }

    let mut sorted: Vec<(FieldElement, usize)> = terms.to_vec();
    sorted.sort_unstable_by_key(|&(_c, w)| w);

    let mut result: Vec<(FieldElement, usize)> = Vec::with_capacity(sorted.len());
    let mut acc_coeff = sorted[0].0;
    let mut acc_witness = sorted[0].1;

    for &(coeff, witness) in &sorted[1..] {
        if witness == acc_witness {
            acc_coeff += coeff;
        } else {
            if !acc_coeff.is_zero() {
                result.push((acc_coeff, acc_witness));
            }
            acc_coeff = coeff;
            acc_witness = witness;
        }
    }

    if !acc_coeff.is_zero() {
        result.push((acc_coeff, acc_witness));
    }

    result
}

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

    /// Compute a SHA3-256 hash of the serialized R1CS matrices.
    ///
    /// Panics if postcard serialization fails, which should not happen for a
    /// well-formed `R1CS` (all fields implement `Serialize`).
    #[must_use]
    pub fn hash(&self) -> crate::R1csHash {
        let bytes = postcard::to_stdvec(self).expect("R1CS serialization should not fail");
        crate::R1csHash::new(Sha3_256::digest(&bytes).into())
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

    /// Add an R1CS constraint. Duplicate witness indices within each linear
    /// combination are merged (coefficients summed) and zeros are dropped.
    pub fn add_constraint(
        &mut self,
        a: &[(FieldElement, usize)],
        b: &[(FieldElement, usize)],
        c: &[(FieldElement, usize)],
    ) {
        let a = canonicalize_terms(a);
        let b = canonicalize_terms(b);
        let c = canonicalize_terms(c);

        let next_constraint_idx = self.num_constraints();
        self.grow_matrices(self.num_constraints() + 1, self.num_witnesses());

        for (coeff, witness_idx) in &a {
            self.a.set(
                next_constraint_idx,
                *witness_idx,
                self.interner.intern(*coeff),
            );
        }
        for (coeff, witness_idx) in &b {
            self.b.set(
                next_constraint_idx,
                *witness_idx,
                self.interner.intern(*coeff),
            );
        }
        for (coeff, witness_idx) in &c {
            self.c.set(
                next_constraint_idx,
                *witness_idx,
                self.interner.intern(*coeff),
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

#[cfg(test)]
mod tests {
    use {super::*, ark_std::One};

    /// Duplicate witness coefficients are summed, not overwritten.
    #[test]
    fn duplicate_witnesses_are_merged() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3);

        let a = vec![(FieldElement::from(3u64), 1), (FieldElement::from(5u64), 1)];
        let b = vec![(FieldElement::one(), 0)];
        let c = vec![(FieldElement::from(8u64), 1)];

        r1cs.add_constraint(&a, &b, &c);

        let a_entries: Vec<_> = r1cs.a().iter_row(0).collect();
        assert_eq!(a_entries.len(), 1);
        assert_eq!(a_entries[0], (1, FieldElement::from(8u64)));
    }

    /// Opposite-sign duplicates cancel to zero and produce no entry.
    #[test]
    fn cancelling_duplicates_produce_no_entry() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3);

        let five = FieldElement::from(5u64);
        let neg_five = FieldElement::zero() - five;
        let a = vec![(five, 1), (neg_five, 1)];
        let b = vec![(FieldElement::one(), 0)];
        let c: Vec<(FieldElement, usize)> = vec![];

        r1cs.add_constraint(&a, &b, &c);

        let a_entries: Vec<_> = r1cs.a().iter_row(0).collect();
        assert!(a_entries.is_empty());
    }

    /// Only duplicate witnesses are merged; distinct witnesses are preserved.
    #[test]
    fn mixed_unique_and_duplicate_witnesses() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(4);

        let a = vec![
            (FieldElement::from(2u64), 1),
            (FieldElement::from(7u64), 2),
            (FieldElement::from(3u64), 1),
            (FieldElement::from(11u64), 3),
        ];
        let b = vec![(FieldElement::one(), 0)];
        let c = vec![];

        r1cs.add_constraint(&a, &b, &c);

        let mut a_entries: Vec<_> = r1cs.a().iter_row(0).collect();
        a_entries.sort_by_key(|(col, _)| *col);
        assert_eq!(a_entries.len(), 3);
        assert_eq!(a_entries[0], (1, FieldElement::from(5u64)));
        assert_eq!(a_entries[1], (2, FieldElement::from(7u64)));
        assert_eq!(a_entries[2], (3, FieldElement::from(11u64)));
    }

    /// Duplicates are merged independently in all three matrices.
    #[test]
    fn duplicates_in_all_matrices() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3);

        let a = vec![(FieldElement::from(1u64), 1), (FieldElement::from(2u64), 1)];
        let b = vec![(FieldElement::from(3u64), 2), (FieldElement::from(4u64), 2)];
        let c = vec![(FieldElement::from(5u64), 1), (FieldElement::from(6u64), 1)];

        r1cs.add_constraint(&a, &b, &c);

        let a_entries: Vec<_> = r1cs.a().iter_row(0).collect();
        assert_eq!(a_entries, vec![(1, FieldElement::from(3u64))]);

        let b_entries: Vec<_> = r1cs.b().iter_row(0).collect();
        assert_eq!(b_entries, vec![(2, FieldElement::from(7u64))]);

        let c_entries: Vec<_> = r1cs.c().iter_row(0).collect();
        assert_eq!(c_entries, vec![(1, FieldElement::from(11u64))]);
    }

    #[test]
    fn canonicalize_terms_basics() {
        assert!(canonicalize_terms(&[]).is_empty());
        assert!(canonicalize_terms(&[(FieldElement::zero(), 0)]).is_empty());

        let result = canonicalize_terms(&[(FieldElement::from(42u64), 5)]);
        assert_eq!(result, vec![(FieldElement::from(42u64), 5)]);

        // 1 + 2 + 3 = 6
        let result = canonicalize_terms(&[
            (FieldElement::from(1u64), 7),
            (FieldElement::from(2u64), 7),
            (FieldElement::from(3u64), 7),
        ]);
        assert_eq!(result, vec![(FieldElement::from(6u64), 7)]);
    }
}
