use {
    crate::{FieldElement, HydratedSparseMatrix, Interner, SparseMatrix, interner::InternedFieldElement},
    serde::{Deserialize, Serialize},
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
}
