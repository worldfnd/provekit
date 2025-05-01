use {
    crate::{FieldElement, HydratedSparseMatrix, Interner, SparseMatrix},
    anyhow::{bail, ensure, Result},
    ark_ff::One,
    ark_std::Zero,
    serde::{Deserialize, Serialize},
    tracing::instrument,
};

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct R1CS {
    pub public_inputs: usize,
    pub witnesses:     usize,
    pub constraints:   usize,
    pub interner:      Interner,
    pub a:             SparseMatrix,
    pub b:             SparseMatrix,
    pub c:             SparseMatrix,
}

impl R1CS {
    pub fn new() -> Self {
        Self {
            public_inputs: 0,
            witnesses:     0,
            constraints:   0,
            interner:      Interner::new(),
            a:             SparseMatrix::new(0, 0),
            b:             SparseMatrix::new(0, 0),
            c:             SparseMatrix::new(0, 0),
        }
    }

    pub fn a(&self) -> HydratedSparseMatrix<'_> {
        self.a.hydrate(&self.interner)
    }

    pub fn b(&self) -> HydratedSparseMatrix<'_> {
        self.b.hydrate(&self.interner)
    }

    pub fn c(&self) -> HydratedSparseMatrix<'_> {
        self.c.hydrate(&self.interner)
    }

    /// Create a new witness variable
    pub fn new_witness(&mut self) -> usize {
        let value = self.witnesses;
        self.witnesses += 1;
        self.a.grow(self.constraints, self.witnesses);
        self.b.grow(self.constraints, self.witnesses);
        self.c.grow(self.constraints, self.witnesses);
        value
    }

    /// Add an R1CS constraint.
    pub fn add_constraint(
        &mut self,
        a: &[(FieldElement, usize)],
        b: &[(FieldElement, usize)],
        c: &[(FieldElement, usize)],
    ) {
        let row = self.constraints;
        self.constraints += 1;
        self.a.grow(self.constraints, self.witnesses);
        self.b.grow(self.constraints, self.witnesses);
        self.c.grow(self.constraints, self.witnesses);
        for (c, col) in a.iter().copied() {
            self.a.set(row, col, self.interner.intern(c))
        }
        for (c, col) in b.iter().copied() {
            self.b.set(row, col, self.interner.intern(c))
        }
        for (c, col) in c.iter().copied() {
            self.c.set(row, col, self.interner.intern(c))
        }
    }

    /// Take a partially solved witness and try to complete it using the R1CS
    /// relations.
    #[instrument(skip_all, fields(size = witness.len()))]
    pub fn solve_witness(&self, witness: &mut [Option<FieldElement>]) -> Result<()> {
        ensure!(
            witness.len() == self.witnesses,
            "Witness size does not match (got {} expected {})",
            witness.len(),
            self.witnesses
        );

        // Solve constraints in order
        // (this is how Noir expects it to be done, judging from ACVM)
        for row in 0..self.constraints {
            let a = sparse_dot(self.a().iter_row(row), &witness);
            let b = sparse_dot(self.b().iter_row(row), &witness);
            let c = sparse_dot(self.c().iter_row(row), &witness);
            let (val, mat) = match (a, b, c) {
                (Some(a), Some(b), Some(c)) => {
                    ensure!(a * b == c, "Constraint {row} failed");
                    continue;
                }
                (Some(a), Some(b), None) => (a * b, self.c()),
                (Some(a), None, Some(c)) => (c / a, self.b()),
                (None, Some(b), Some(c)) => (c / b, self.a()),
                _ => {
                    bail!("Can not solve constraint {row}.")
                }
            };
            let Some((col, val)) = solve_dot(mat.iter_row(row), &witness, val) else {
                bail!("Could not solve constraint {row}.")
            };
            witness[col] = Some(val);
        }
        Ok(())
    }

    #[instrument(skip_all, fields(size = witness.len()))]
    pub fn verify_witness(&self, witness: &[FieldElement]) -> Result<()> {
        ensure!(
            witness.len() == self.witnesses,
            "Witness size does not match"
        );

        // Verify
        let a = self.a() * witness;
        let b = self.b() * witness;
        let c = self.c() * witness;
        for (row, ((a, b), c)) in a
            .into_iter()
            .zip(b.into_iter())
            .zip(c.into_iter())
            .enumerate()
        {
            ensure!(a * b == c, "Constraint {row} failed");
        }
        Ok(())
    }
    pub fn pad_to_power_of_two(&mut self) {
        let new_constraints = self.constraints.next_power_of_two();
        let new_witnesses = self.witnesses.next_power_of_two();
    
        self.a.grow(new_constraints, new_witnesses);
        self.b.grow(new_constraints, new_witnesses);
        self.c.grow(new_constraints, new_witnesses);
    
        self.constraints = new_constraints;
        self.witnesses = new_witnesses;
    }
}

// Sparse dot product. `a` is assumed zero. `b` is assumed missing.
fn sparse_dot<'a>(
    a: impl Iterator<Item = (usize, FieldElement)>,
    b: &[Option<FieldElement>],
) -> Option<FieldElement> {
    let mut accumulator = FieldElement::zero();
    for (col, a) in a {
        accumulator += a * b[col]?;
    }
    Some(accumulator)
}

// Returns a pair (i, f) such that, setting `b[i] = f`,
// ensures `sparse_dot(a, b) = r`.
fn solve_dot<'a>(
    a: impl Iterator<Item = (usize, FieldElement)>,
    b: &[Option<FieldElement>],
    r: FieldElement,
) -> Option<(usize, FieldElement)> {
    let mut accumulator = -r;
    let mut missing = None;
    for (col, a) in a {
        if let Some(b) = b[col] {
            accumulator += a * b;
        } else if missing.is_none() {
            missing = Some((col, a));
        } else {
            return None;
        }
    }
    missing.map(|(col, coeff)| {
        if coeff.is_one() {
            // Very common case
            (col, -accumulator)
        } else {
            (col, -accumulator / coeff)
        }
    })
}

