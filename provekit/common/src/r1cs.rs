use {
    crate::{FieldElement, HydratedSparseMatrix, Interner, SparseMatrix},
    ark_std::Zero,
    serde::{Deserialize, Serialize},
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
