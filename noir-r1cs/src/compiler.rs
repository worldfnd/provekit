use {
    crate::SparseMatrix,
    acir::{
        circuit::{Circuit, Opcode},
        native_types::{Expression, Witness as AcirWitness},
        AcirField, FieldElement,
    },
    serde::{Deserialize, Serialize},
    std::{collections::BTreeMap, fmt::{Debug, Formatter}, fs::File, io::Write, ops::Neg, vec},
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

#[derive(Debug, Clone)]
/// Indicates how to solve for an R1CS witness value
pub enum WitnessBuilder {
    /// Constant value, used for the constant one witness & e.g. static lookups
    Constant(FieldElement),
    /// A witness value carried over from the ACIR circuit
    Acir(usize),
    /// A Fiat-Shamir challenge value
    Challenge,
    /// The inverse of the value at a specified witness index
    Inverse(usize),
    /// Solvable is for values that can be solved for using the R1CS constraint with the specified index
    Solvable(usize),
    // TODO come back to this - it complicates Debug, Clone, etc.
    // /// Solve using a closure
    // Closure(Box<dyn Fn(&[FieldElement]) -> FieldElement>),
}

/// Represents a R1CS constraint system.
#[derive(Debug, Clone)]
pub struct R1CS {
    pub a: SparseMatrix<FieldElement>,
    pub b: SparseMatrix<FieldElement>,
    pub c: SparseMatrix<FieldElement>,

    /// Indicates how to solve for each R1CS witness
    pub witness_builders: Vec<WitnessBuilder>,
    
    /// Maps indices of ACIR witnesses to indices of R1CS witnesses
    acir_to_r1cs_witness_map: BTreeMap<usize, usize>,
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
            witness_builders:   vec![WitnessBuilder::Constant(FieldElement::one())],
            acir_to_r1cs_witness_map: BTreeMap::new(),
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
            num_variables: self.witness_builders.len(),
            num_constraints: self.num_constraints(),
            a: Self::matrix_to_entries(&self.a),
            b: Self::matrix_to_entries(&self.b),
            c: Self::matrix_to_entries(&self.c),
            witnesses,
        };

        serde_json::to_string_pretty(&json_r1cs)
    }

    fn matrix_to_entries(matrix: &SparseMatrix<FieldElement>) -> Vec<MatrixEntry> {
        matrix.entries.iter().filter_map(|((row, col), value)| {
            if !value.is_zero() {
                Some(MatrixEntry {
                    constraint: *row,
                    signal:     *col,
                    value:      value.to_string(),
                });
            }
            None
        }).collect()
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

    /// Index of the constant 1 witness
    pub fn witness_one(&self) -> usize {
        0
    }

    /// The number of witnesses in the R1CS instance.
    /// This includes the constant one witness.
    pub fn num_witnesses(&self) -> usize {
        self.witness_builders.len()
    }

    /// The number of constraints in the R1CS instance.
    pub fn num_constraints(&self) -> usize {
        self.a.rows
    }

    // Increase the size of the R1CS matrices to the specified dimensions.
    fn grow_matrices(&mut self, num_rows: usize, num_cols: usize) {
        self.a.grow(num_rows, num_cols);
        self.b.grow(num_rows, num_cols);
        self.c.grow(num_rows, num_cols);
    }

    // Grow the R1CS matrices to accomodate one new witness. Returns the index of the new witness.
    fn new_witness_index(&mut self) -> usize {
        let num_rows = self.num_constraints();
        let next_witness_idx = self.num_witnesses();
        self.grow_matrices(num_rows, self.num_witnesses() + 1);
        next_witness_idx
    }

    // Grow the R1CS matrices to accomodate one new constraint.  Returns the index of the new constraint.
    fn new_constraint_index(&mut self) -> usize {
        let next_constraint_idx = self.num_constraints();
        let num_cols = self.witness_builders.len();
        self.grow_matrices(self.num_constraints() + 1, num_cols);
        next_constraint_idx
    }

    // Add a new witness to the R1CS instance, returning its index.
    fn add_witness(&mut self, witness: WitnessBuilder) -> usize {
        let witness_idx = self.new_witness_index();
        // Add the witness to the mapping if it is an ACIR witness
        if let WitnessBuilder::Acir(acir_witness) = witness {
            self.acir_to_r1cs_witness_map.insert(acir_witness, witness_idx);
        }
        self.witness_builders.push(witness);
        debug_assert_eq!(self.witness_builders.len(), witness_idx + 1);
        witness_idx
    }

    // Return the R1CS witness index corresponding to the AcirWitness provided, creating a new R1CS
    // witness (and builder) if required.
    fn to_r1cs_witness(&mut self, acir_witness: AcirWitness) -> usize {
        self.acir_to_r1cs_witness_map
            .get(&acir_witness.as_usize())
            .copied()
            .unwrap_or_else(|| {
                self.add_witness(WitnessBuilder::Acir(acir_witness.as_usize()))
            })
    }

    // Set the values of an R1CS constraint at the specified constraint index.
    // Implementation note: does not create a new constraint index, since the constraint idx is
    // sometimes required earlier in the calling context, see e.g. Solvable.
    fn set_constraint(
        &mut self,
        constraint_idx: usize,
        az: &[(FieldElement, usize)],
        bz: &[(FieldElement, usize)],
        cz: &[(FieldElement, usize)],
    ) {
        for (coeff, witness_idx) in az.iter().copied() {
            self.a.set(constraint_idx, witness_idx, coeff)
        }
        for (coeff, witness_idx) in bz.iter().copied() {
            self.b.set(constraint_idx, witness_idx, coeff)
        }
        for (coeff, witness_idx) in cz.iter().copied() {
            self.c.set(constraint_idx, witness_idx, coeff)
        }
    }

    // Add R1CS constraints to the instance to enforce that the provided ACIR expression is zero.
    fn add_assert_zero(&mut self, expr: &Expression<FieldElement>) {
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
                .map(|(coeff, acir_witness0, acir_witness1)| {
                    let witness0 = self.to_r1cs_witness(*acir_witness0);
                    let witness1 = self.to_r1cs_witness(*acir_witness1);
                    let constraint_idx = self.new_constraint_index();
                    let multn_result = self.add_witness(WitnessBuilder::Solvable(constraint_idx));
                    self.set_constraint(
                        constraint_idx,
                        &[(FieldElement::one(), witness0)],
                        &[(FieldElement::one(), witness1)],
                        &[(FieldElement::one(), multn_result)],
                    );
                    (-*coeff, multn_result)
                })
                .collect::<Vec<_>>();

            // Handle the last multiplication term directly
            let (coeff, acir_witness0, acir_witness1) = &expr.mul_terms[expr.mul_terms.len() - 1];
            a = vec![(
                FieldElement::from(*coeff),
                self.to_r1cs_witness(*acir_witness0),
            )];
            b = vec![(FieldElement::one(), self.to_r1cs_witness(*acir_witness1))];
        }

        // Extend with linear combinations
        linear.extend(
            expr.linear_combinations
                .iter()
                .map(|(coeff, acir_witness)| (coeff.neg(), self.to_r1cs_witness(*acir_witness))),
        );

        // Add constant by multipliying with constant value one.
        linear.push((expr.q_c.neg(), self.witness_one()));

        // Add a single linear constraint
        // We could avoid this by substituting back into the last multiplication
        // constraint.
        let constraint_idx = self.new_constraint_index();
        self.set_constraint(constraint_idx, &a, &b, &linear);
    }
}

/// Print the R1CS matrices and the ACIR -> R1CS witness map, useful for debugging.
impl std::fmt::Display for R1CS {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f,
            "R1CS: {} witnesses, {} constraints",
            self.witness_builders.len(), self.num_constraints()
        )?;
        if std::cmp::max(self.num_constraints(), self.num_witnesses()) > 15 {
            println!("Matrices too large to print");
            return Ok(());
        }
        writeln!(f, "ACIR witness <-> R1CS witness mapping:")?;
        for (k, v) in &self.acir_to_r1cs_witness_map {
            writeln!(f, "{k} <-> {v}")?;
        }
        writeln!(f, "Matrix A:")?;
        write!(f, "{}", self.a)?;
        writeln!(f, "Matrix B:")?;
        write!(f, "{}", self.b)?;
        writeln!(f, "Matrix C:")?;
        write!(f, "{}", self.c)
    }
}