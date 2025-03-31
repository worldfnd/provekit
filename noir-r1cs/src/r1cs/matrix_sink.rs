/// Represents a R1CS constraint system as Sparse Matrices.
#[derive(Debug, Clone)]
pub struct MatrixSink {
    pub a: SparseMatrix<FieldElement>,
    pub b: SparseMatrix<FieldElement>,
    pub c: SparseMatrix<FieldElement>,
}

impl MatrixSink {
    pub fn new(witnesses: usize, constraints: usize) -> Self {
        Self {
            a: SparseMatrix::new(constraints, witnesses, FieldElement::zero()),
            b: SparseMatrix::new(constraints, witnesses, FieldElement::zero()),
            c: SparseMatrix::new(constraints, witnesses, FieldElement::zero()),
        }
    }
}

impl ConstraintSink for MatrixSink {
    fn add_constraint(
        &mut self,
        a: &[(FieldElement, usize)],
        b: &[(FieldElement, usize)],
        c: &[(FieldElement, usize)],
    ) {
        for (c, col) in a.iter().copied() {
            self.a.set(row, col, c)
        }
        for (c, col) in b.iter().copied() {
            self.b.set(row, col, c)
        }
        for (c, col) in c.iter().copied() {
            self.c.set(row, col, c)
        }
    }
}
