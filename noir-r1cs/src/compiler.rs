use {
    crate::SparseMatrix,
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, Witness},
        AcirField, FieldElement,
    },
    serde::{Deserialize, Serialize},
    std::{collections::BTreeMap, fs::File, io::Write, ops::Neg},
};

#[derive(Serialize)]
struct JsonR1CS {
    num_public:      usize,
    num_variables:   usize,
    num_constraints: usize,
    a:               Vec<MatrixEntry>,
    b:               Vec<MatrixEntry>,
    c:               Vec<MatrixEntry>,
    witnesses:       Vec<Vec<String>>,
}

/// Represents a R1CS constraint system.
#[derive(Debug, Clone)]
pub struct R1CS {
    pub a: SparseMatrix<FieldElement>,
    pub b: SparseMatrix<FieldElement>,
    pub c: SparseMatrix<FieldElement>,

    // Remapping of witness indices to the r1cs_witness array
    pub witnesses: usize,
    pub remap:     BTreeMap<usize, usize>,

    pub constraints: usize,
}

#[derive(Serialize, Deserialize)]
struct MatrixEntry {
    constraint: usize,
    signal:     usize,
    value:      String,
}

impl R1CS {
    pub fn new() -> Self {
        Self {
            a:           SparseMatrix::new(0, 1, FieldElement::zero()),
            b:           SparseMatrix::new(0, 1, FieldElement::zero()),
            c:           SparseMatrix::new(0, 1, FieldElement::zero()),
            witnesses:   1,
            remap:       BTreeMap::new(),
            constraints: 0,
        }
    }

    pub fn to_json(
        &self,
        num_public: usize,
        witness: &[FieldElement],
    ) -> Result<String, serde_json::Error> {
        // Convert sparse matrices to vector format
        let a = self.matrix_to_entries(&self.a);
        let b = self.matrix_to_entries(&self.b);
        let c = self.matrix_to_entries(&self.c);

        // Convert witness to string format
        let witnesses = vec![witness
            .iter()
            .map(|w| w.to_string())
            .collect::<Vec<String>>()];

        let json_r1cs = JsonR1CS {
            num_public,
            num_variables: self.witnesses,
            num_constraints: self.constraints,
            a,
            b,
            c,
            witnesses,
        };

        serde_json::to_string_pretty(&json_r1cs)
    }

    fn matrix_to_entries(&self, matrix: &SparseMatrix<FieldElement>) -> Vec<MatrixEntry> {
        let mut entries = Vec::new();

        // Iterate through the sparse matrix
        for row in 0..self.constraints {
            for (col, value) in matrix.iter_row(row) {
                if !value.is_zero() {
                    entries.push(MatrixEntry {
                        constraint: row,
                        signal:     col,
                        value:      value.to_string(),
                    });
                }
            }
        }

        entries
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

    /// Pretty print the R1CS matrices and the ACIR -> R1CS witness map, useful for debugging.
    pub fn pretty_print(&self) {
        if std::cmp::max(self.constraints, self.witnesses) > 15 {
            println!("Matrices too large to print");
            return;
        }
        println!("ACIR witness <-> R1CS witness mapping:");
        for (k, v) in &self.remap {
            println!("{k} <-> {v}");
        }
        println!("Matrix A:");
        self.a.pretty_print();
        println!("Matrix B:");
        self.b.pretty_print();
        println!("Matrix C:");
        self.c.pretty_print();
    }

    pub fn add_circuit(&mut self, circuit: &Circuit<FieldElement>) {
        for opcode in circuit.opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => self.add_assert_zero(expr),

                // Brillig instructions are used by the ACVM to solve for ACIR witness values.
                // Corresponding ACIR constraints are by Noir as AssertZeros, and we map all ACIR
                // witness values to R1CS witness values, so we can safely ignore
                // Opcode::BrilligCall.
                Opcode::BrilligCall { .. } => {
                    println!("BrilligCall {:?}", opcode)
                }

                // // Directive is a modern version of Brillig.
                // Opcode::Directive(..) => unimplemented!("Directive"),

                // Calls to a function, this is to efficiently represent repeated structure in
                // circuits. TODO: We need to implement this so we can store
                // circuits concicely. It should not impact the R1CS constraints or
                // witness vector.
                Opcode::Call { .. } => unimplemented!("Call"),

                // These should be implemented using lookup arguments, or memory checking arguments.
                Opcode::MemoryOp {
                    block_id,
                    op,
                    predicate,
                } => {
                    println!("block id {:?} op {:?} pred {:?}", block_id, op, predicate);
                    println!("op {:?}", opcode);
                }
                Opcode::MemoryInit {
                    block_id,
                    init,
                    block_type,
                } => {
                    println!("MemoryInit {:?}", opcode);
                    println!("init {:?}", init)
                }

                // These are calls to built-in functions, for this we need to create.
                Opcode::BlackBoxFuncCall(_) => {
                    println!("BlackBoxFuncCall")
                }
            }
        }
    }

    /// Index of the constant one witness
    pub fn witness_one(&self) -> usize {
        0
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

    /// Map ACIR Witnesses to r1cs_witness indices
    pub fn map_witness(&mut self, witness: Witness) -> usize {
        self.remap
            .get(&witness.as_usize())
            .copied()
            .unwrap_or_else(|| {
                let value = self.new_witness();
                self.remap.insert(witness.as_usize(), value);
                value
            })
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

    /// Add an ACIR assert zero constraint.
    pub fn add_assert_zero(&mut self, expr: &Expression<FieldElement>) {
        // println!("expr {:?}", expr);
        // Create individual constraints for all the multiplication terms and collect
        // their outputs
        let mut linear = vec![];
        let mut a = vec![];
        let mut b = vec![];

        if expr.mul_terms.len() >= 1 {
            // Process all except the last multiplication term
            linear = expr
                .mul_terms
                .iter()
                .take(expr.mul_terms.len() - 1)
                .map(|term| {
                    let a = self.map_witness(term.1);
                    let b = self.map_witness(term.2);
                    let c = self.new_witness();
                    self.add_constraint(
                        &[(FieldElement::one(), a)],
                        &[(FieldElement::one(), b)],
                        &[(FieldElement::one(), c)],
                    );
                    (-term.0, c)
                })
                .collect::<Vec<_>>();

            // Handle the last multiplication term directly
            let last_term = &expr.mul_terms[expr.mul_terms.len() - 1];
            a = vec![(
                FieldElement::from(last_term.0),
                self.map_witness(last_term.1),
            )];
            b = vec![(FieldElement::one(), self.map_witness(last_term.2))];
        }

        // Extend with linear combinations
        linear.extend(
            expr.linear_combinations
                .iter()
                .map(|term| (term.0.neg(), self.map_witness(term.1))),
        );
        // println!("linear {:?}", linear);

        // Add constant by multipliying with constant value one.
        linear.push((expr.q_c.neg(), self.witness_one()));

        // Add a single linear constraint
        // We could avoid this by substituting back into the last multiplication
        // constraint.
        self.add_constraint(&a, &b, &linear);
    }
}
