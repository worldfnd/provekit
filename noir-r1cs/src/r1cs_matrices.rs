use {
    crate::sparse_matrix::{mat_mul, SparseMatrix},
    acir::{AcirField, FieldElement},
    serde::{Deserialize, Serialize},
    std::{fmt::Formatter, fs::File, io::Write},
};

#[derive(Serialize)]
struct JsonR1CS {
    num_public: usize,
    num_variables: usize,
    num_constraints: usize,
    a: Vec<MatrixEntry>,
    b: Vec<MatrixEntry>,
    c: Vec<MatrixEntry>,
    witnesses: Vec<Vec<String>>,
}

/// Represents a R1CS constraint system.
/// A witness z satisfies the R1CS iff:
/// Az * Bz = Cz
/// where Az, Bz, Cz are the vectors formed by multiplying the matrices A, B, C by the witness z.
#[derive(Debug, Clone)]
pub struct R1CSMatrices {
    pub a: SparseMatrix<FieldElement>,
    pub b: SparseMatrix<FieldElement>,
    pub c: SparseMatrix<FieldElement>,
}

#[derive(Serialize, Deserialize)]
struct MatrixEntry {
    constraint: usize,
    signal: usize,
    value: String,
}

impl R1CSMatrices {
    pub fn new() -> Self {
        Self {
            a: SparseMatrix::new(0, 1, FieldElement::zero()),
            b: SparseMatrix::new(0, 1, FieldElement::zero()),
            c: SparseMatrix::new(0, 1, FieldElement::zero()),
        }
    }

    pub fn to_json(
        &self,
        num_public: usize,
        witness: &[FieldElement],
    ) -> Result<String, serde_json::Error> {
        // Convert witness to string format
        let witnesses = vec![witness
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<String>>()];

        let json_r1cs = JsonR1CS {
            num_public,
            num_variables: self.num_witnesses(),
            num_constraints: self.num_constraints(),
            a: Self::matrix_to_entries(&self.a),
            b: Self::matrix_to_entries(&self.b),
            c: Self::matrix_to_entries(&self.c),
            witnesses,
        };

        serde_json::to_string_pretty(&json_r1cs)
    }

    fn matrix_to_entries(matrix: &SparseMatrix<FieldElement>) -> Vec<MatrixEntry> {
        matrix
            .entries
            .iter()
            .filter_map(|((row, col), value)| {
                if !value.is_zero() {
                    Some(MatrixEntry {
                        constraint: *row,
                        signal: *col,
                        value: value.to_string(),
                    });
                }
                None
            })
            .collect()
    }

    pub fn write_json_to_file(
        &self,
        num_public: usize,
        witness: &[FieldElement],
        path: &str,
    ) -> std::io::Result<()> {
        let json = self
            .to_json(num_public, witness)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    /// The number of constraints in the R1CS instance.
    pub fn num_constraints(&self) -> usize {
        self.a.rows
    }

    /// The number of witnesses in the R1CS instance (including the constant one witness).
    pub fn num_witnesses(&self) -> usize {
        self.a.cols
    }

    /// Add a new witness to the R1CS instance, returning its index.
    pub fn add_witness(&mut self) -> usize {
        let next_witness_idx = self.num_witnesses();
        self.grow_matrices(self.num_constraints(), self.num_witnesses() + 1);
        next_witness_idx
    }

    // Increase the size of the R1CS matrices to the specified dimensions.
    fn grow_matrices(&mut self, num_rows: usize, num_cols: usize) {
        self.a.grow(num_rows, num_cols);
        self.b.grow(num_rows, num_cols);
        self.c.grow(num_rows, num_cols);
    }

    /// Adds a new R1CS constraint.
    pub fn add_constraint(
        &mut self,
        az: &[(FieldElement, usize)],
        bz: &[(FieldElement, usize)],
        cz: &[(FieldElement, usize)],
    ) {
        let next_constraint_idx = self.num_constraints();
        let num_cols = self.num_witnesses();
        self.grow_matrices(self.num_constraints() + 1, num_cols);

        for (coeff, witness_idx) in az.iter().copied() {
            self.a.set(next_constraint_idx, witness_idx, coeff)
        }
        for (coeff, witness_idx) in bz.iter().copied() {
            self.b.set(next_constraint_idx, witness_idx, coeff)
        }
        for (coeff, witness_idx) in cz.iter().copied() {
            self.c.set(next_constraint_idx, witness_idx, coeff)
        }
    }

    /// Returns None if this R1CS instance is satisfied, otherwise returns the index of the first
    /// constraint that is not satisfied.
    pub fn test_satisfaction(&self, witness: &[FieldElement]) -> Option<usize> {
        let az = mat_mul(&self.a, witness);
        let bz = mat_mul(&self.b, witness);
        let cz = mat_mul(&self.c, witness);
        for (row, ((a_val, b_val), c_val)) in az
            .into_iter()
            .zip(bz.into_iter())
            .zip(cz.into_iter())
            .enumerate()
        {
            if a_val * b_val != c_val {
                return Some(row);
            }
        }
        None
    }
}

impl std::fmt::Display for R1CSMatrices {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if std::cmp::max(self.num_constraints(), self.num_witnesses()) > 25 {
            return writeln!(f, "R1CS matrices too large to print")
        }
        writeln!(f, "Matrix A:")?;
        write!(f, "{}", self.a)?;
        writeln!(f, "Matrix B:")?;
        write!(f, "{}", self.b)?;
        writeln!(f, "Matrix C:")?;
        write!(f, "{}", self.c)
    }
}
