use {
    crate::{FieldElement, SparseMatrix},
    anyhow::{ensure, Result},
    ark_std::Zero,
    serde::{Deserialize, Serialize},
    tracing::instrument,
};

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1CS {
    pub public_inputs: usize,
    pub witnesses:     usize,
    pub constraints:   usize,
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
            a:             SparseMatrix::new(0, 0, FieldElement::zero()),
            b:             SparseMatrix::new(0, 0, FieldElement::zero()),
            c:             SparseMatrix::new(0, 0, FieldElement::zero()),
        }
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
        // println!("add_constraint");
        let row = self.constraints;
        self.constraints += 1;
        self.a.grow(self.constraints, self.witnesses);
        self.b.grow(self.constraints, self.witnesses);
        self.c.grow(self.constraints, self.witnesses);
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
        // Solve constraints (this is how Noir expects it to be done, judging from ACVM)
        for row in 0..self.constraints {
            let [a, b, c] =
                [&self.a, &self.b, &self.c].map(|mat| sparse_dot(mat.iter_row(row), &witness));
            let (val, mat) = match (a, b, c) {
                (Some(a), Some(b), Some(c)) => {
                    assert_eq!(a * b, c, "Constraint {row} failed");
                    continue;
                }
                (Some(a), Some(b), None) => (a * b, &self.c),
                (Some(a), None, Some(c)) => (c / a, &self.b),
                (None, Some(b), Some(c)) => (c / b, &self.a),
                _ => {
                    panic!("Can not solve constraint {row}.")
                }
            };
            let Some((col, val)) = solve_dot(mat.iter_row(row), &witness, val) else {
                panic!("Could not solve constraint {row}.")
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
        let a = mat_mul(&self.a, &witness);
        let b = mat_mul(&self.b, &witness);
        let c = mat_mul(&self.c, &witness);
        for (row, ((&a, &b), &c)) in a.iter().zip(b.iter()).zip(c.iter()).enumerate() {
            ensure!(a * b == c, "Constraint {row} failed");
        }
        Ok(())
    }
}

// Sparse dot product. `a` is assumed zero. `b` is assumed missing.
fn sparse_dot<'a>(
    a: impl Iterator<Item = (usize, &'a FieldElement)>,
    b: &[Option<FieldElement>],
) -> Option<FieldElement> {
    let mut accumulator = FieldElement::zero();
    for (col, &a) in a {
        accumulator += a * b[col]?;
    }
    Some(accumulator)
}

// Returns a pair (i, f) such that, setting `b[i] = f`,
// ensures `sparse_dot(a, b) = r`.
fn solve_dot<'a>(
    a: impl Iterator<Item = (usize, &'a FieldElement)>,
    b: &[Option<FieldElement>],
    r: FieldElement,
) -> Option<(usize, FieldElement)> {
    let mut accumulator = -r;
    let mut missing = None;
    for (col, &a) in a {
        if let Some(b) = b[col] {
            accumulator += a * b;
        } else if missing.is_none() {
            missing = Some((col, a));
        } else {
            return None;
        }
    }
    missing.map(|(col, coeff)| (col, -accumulator / coeff))
}

fn mat_mul(a: &SparseMatrix, b: &[FieldElement]) -> Vec<FieldElement> {
    let mut result = vec![FieldElement::zero(); a.rows];
    for ((i, j), &value) in a.iter() {
        result[i] += value * b[j];
    }
    result
}
