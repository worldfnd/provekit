use {
    crate::SparseMatrix, acir::{
        circuit::{opcodes::BlockType, Circuit, Opcode},
        native_types::{Expression, Witness as AcirWitness},
        AcirField, FieldElement,
    }, rand::seq::index, serde::{Deserialize, Serialize}, std::{collections::BTreeMap, fmt::{Debug, Formatter}, fs::File, io::Write, ops::Neg, vec}
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
/// Used for tracking reads of a read-only memory block
pub struct ReadOnlyMemoryBlock {
    /// The R1CS witnesses corresponding to the memory block values
    pub value_witnesses: Vec<usize>,
    /// (constant address, R1CS witness index of value read) tuples
    pub static_reads: Vec<(usize, usize)>,
    /// (R1CS witness index of address, R1CS witness index of value read) tuples
    pub dynamic_reads: Vec<(usize, usize)>,
}

#[derive(Debug, Clone)]
/// Indicates how to solve for an R1CS witness value in terms of earlier R1CS witness values and/or
/// ACIR witness values.
pub enum WitnessBuilder {
    /// Constant value, used for the constant one witness & e.g. static lookups
    Constant(FieldElement),
    /// A witness value carried over from the ACIR circuit
    Acir(usize),
    /// A Fiat-Shamir challenge value
    Challenge,
    /// The inverse of the value at a specified witness index
    Inverse(usize),
    /// The sum of many witness values
    Sum(Vec<usize>),
    /// The product of the values at two specified witness indices
    Product(usize, usize),
    /// Witness is the result of a memory read from the .0th block at the .1th static address, whose value is available as the .2th acir witness index
    StaticMemoryRead(usize, usize, usize),
    /// Witness is the result of a memory read from the .0th block at the address determined by the .1th R1CS witness, whose value is available as the .2th acir witness index
    DynamicMemoryRead(usize, usize, usize),
    /// The number of times that the .1th index of the .0th memory block is accessed
    MemoryAccessCount(usize, usize),
    /// Solvable is for values that can be solved for using the R1CS constraint with the specified index
    Solvable(usize),
}

/// Represents a R1CS constraint system.
#[derive(Debug, Clone)]
pub struct R1CS {
    pub a: SparseMatrix<FieldElement>,
    pub b: SparseMatrix<FieldElement>,
    pub c: SparseMatrix<FieldElement>,

    /// Indicates how to solve for each R1CS witness
    pub witness_builders: Vec<WitnessBuilder>,

    /// The length of each memory block
    pub memory_lengths: BTreeMap<usize, usize>,
    
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
            a: SparseMatrix::new(0, 1, FieldElement::zero()),
            b: SparseMatrix::new(0, 1, FieldElement::zero()),
            c: SparseMatrix::new(0, 1, FieldElement::zero()),
            witness_builders: vec![WitnessBuilder::Constant(FieldElement::one())],
            memory_lengths: BTreeMap::new(),
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

    // TODO should be a From method
    /// Create an R1CS instance from an ACIR circuit, introducing extra witnesses and constraints as
    /// needed.
    pub fn from_acir(circuit: &Circuit<FieldElement>) -> Self {
        let mut r1cs = R1CS::new();
        // Read-only memory blocks (used for building the memory lookup constraints at the end)
        let mut memory_blocks: BTreeMap<usize, ReadOnlyMemoryBlock> = BTreeMap::new();
        for opcode in circuit.opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => r1cs.add_acir_assert_zero(expr),

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

                Opcode::MemoryInit {
                    block_id,
                    init,
                    block_type,
                } => {
                    if *block_type != BlockType::Memory {
                        panic!("MemoryInit block type must be Memory")
                    }
                    let block_id = block_id.0 as usize;
                    assert!(
                        !memory_blocks.contains_key(&block_id),
                        "Memory block {} already initialized",
                        block_id
                    );
                    r1cs.memory_lengths.insert(block_id, init.len());
                    let mut block = ReadOnlyMemoryBlock {
                        value_witnesses: vec![],
                        static_reads: vec![],
                        dynamic_reads: vec![],
                    };
                    init.iter().for_each(|acir_witness| {
                        let r1cs_witness = r1cs.add_witness(WitnessBuilder::Acir(acir_witness.0 as usize));
                        // Add the witness index to the memory block
                        block.value_witnesses.push(r1cs_witness);
                    });
                    memory_blocks.insert(block_id, block);
                }

                Opcode::MemoryOp {
                    block_id,
                    op,
                    predicate,
                } => {
                    let is_read = op.operation.is_zero();
                    assert!(is_read, "MemoryOp write not yet supported");

                    // panic if the predicate is set (until we learn what it is!)
                    assert!(predicate.is_none());

                    let block_id = block_id.0 as usize;
                    assert!(
                        memory_blocks.contains_key(&block_id),
                        "Memory block {} not initialized before read",
                        block_id
                    );
                    let block = memory_blocks.get_mut(&block_id).unwrap();

                    // Create a new (as yet unconstrained) witness `result_of_read` for the result of the read; it will be constrained by the lookup for the memory block at the end.
                    // Use a memory witness builders so that the solver can later determine its value and also determine the memory access counts

                    // "In read operations, [op.value] corresponds to the witness index at which the value from memory will be written." (from the Noir codebase)
                    // At R1CS solving time, only need to map over the value of the corresponding ACIR witness, whose value is already determined by the ACIR solver.
                    let result_of_read_acir_witness = op.value.to_witness().unwrap().0 as usize;

                    if op.index.is_const() {
                        // Statically addressed memory read
                        let static_addr = op.index.to_const().unwrap().try_to_u64().unwrap() as usize;
                        let value_read = r1cs.add_witness(WitnessBuilder::StaticMemoryRead(block_id, static_addr, result_of_read_acir_witness));
                        block.static_reads.push((static_addr, value_read));
                    } else {
                        // Dynamically addressed memory read
                        // It isn't clear from the Noir codebase if index can ever be a not equal to just a single ACIR witness.
                        // If it isn't, we'll need to introduce constraints and use a solvable witness for the index, but let's leave this til later.
                        let addr_wb = match op.index.to_witness() {
                            Some(acir_witness) => WitnessBuilder::Acir(acir_witness.0 as usize),
                            None => unimplemented!("MemoryOp index must be a witness or a constant, not a more general Expression"),
                        };
                        let addr = r1cs.add_witness(addr_wb);
                        let value_read = r1cs.add_witness(WitnessBuilder::DynamicMemoryRead(block_id, addr, result_of_read_acir_witness));
                        block.dynamic_reads.push((addr, value_read));
                    }
                }

                // These are calls to built-in functions, for this we need to create.
                Opcode::BlackBoxFuncCall(_) => {
                    println!("BlackBoxFuncCall")
                }
            }
        }

        // For each memory block, use a lookup to enforce that the reads are correct.
        memory_blocks.iter().for_each(|(block_id, block)| {
            // Add witness values for memory access counts, using the WitnessBuilder::MemoryAccessCount
            let access_counts: Vec<_> = (0..block.value_witnesses.len()).into_iter().map(|index| {
                r1cs.add_witness(WitnessBuilder::MemoryAccessCount(*block_id, index))
            }).collect();

            // Add two verifier challenges for the lookup
            let rs_challenge = r1cs.add_witness(WitnessBuilder::Challenge);
            let sz_challenge = r1cs.add_witness(WitnessBuilder::Challenge);

            // Calculate the sum, over all reads, of 1/denominator
            let mut summands_for_reads = vec![];
            block.static_reads.iter().for_each(|(addr, value)| {
                summands_for_reads.push(r1cs.add_indexed_lookup_factor(rs_challenge, sz_challenge, (*addr).into(), r1cs.witness_one(), *value));
            });
            block.dynamic_reads.iter().for_each(|(addr_witness, value)| {
                summands_for_reads.push(r1cs.add_indexed_lookup_factor(rs_challenge, sz_challenge, FieldElement::one(), *addr_witness, *value));
            });
            let sum_for_reads = r1cs.add_sum(summands_for_reads);

            // Calculate the sum over all table elements of multiplicity/factor
            let summands_for_table = block.value_witnesses.iter().zip(access_counts.iter()).enumerate().map(|(addr, (value, access_count))| {
                let denominator = r1cs.add_indexed_lookup_factor(rs_challenge, sz_challenge, addr.into(), r1cs.witness_one(), *value);
                r1cs.add_product(*access_count, denominator)
            }).collect();
            let sum_for_table = r1cs.add_sum(summands_for_table);

            // Enforce that the two sums are equal
            let constraint_idx = r1cs.new_constraint_index();
            r1cs.set_constraint(
                constraint_idx,
                &[(FieldElement::one(), r1cs.witness_one())],
                &[(FieldElement::one(), sum_for_reads)],
                &[(FieldElement::one(), sum_for_table)],
            );
        });
        r1cs
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
    // If the witness builder implicitly maps an ACIR witness to an R1CS witness, then record this.
    fn add_witness(&mut self, witness: WitnessBuilder) -> usize {
        let witness_idx = self.new_witness_index();
        // Add the witness to the mapping if it is an ACIR witness
        match &witness {
            WitnessBuilder::Acir(acir_witness) => {
                self.acir_to_r1cs_witness_map.insert(*acir_witness, witness_idx);
            }
            WitnessBuilder::StaticMemoryRead(_, _, value_acir_witness) => {
                self.acir_to_r1cs_witness_map.insert(*value_acir_witness, witness_idx);
            }
            WitnessBuilder::DynamicMemoryRead(_, _, value_acir_witness) => {
                self.acir_to_r1cs_witness_map.insert(*value_acir_witness, witness_idx);
            }
            _ => {}
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

    // Helper function for adding a new lookup factor to the R1CS instance.
    // Adds a new witness `denominator` and constrains it to represent 
    //    `denominator - (sz_challenge - (index + rs_challenge * value)) == 0`
    // Then adds a new witness for its inverse, constrains it to be such, and returns its index.
    fn add_indexed_lookup_factor(&mut self, rs_challenge: usize, sz_challenge: usize, addr_coeff: FieldElement, addr_witness: usize, value: usize) -> usize {
        let constraint_idx = self.new_constraint_index();
        let denominator = self.add_witness(WitnessBuilder::Solvable(constraint_idx));
        self.set_constraint(
            constraint_idx,
            &[(FieldElement::one(), rs_challenge)],
            &[(FieldElement::one(), value)],
            &[(FieldElement::one(), denominator), (FieldElement::one().neg(), sz_challenge), (addr_coeff, addr_witness)],
        );
        let inverse = self.add_witness(WitnessBuilder::Inverse(denominator));
        let inverse_constraint_idx = self.new_constraint_index();
        self.set_constraint(
            inverse_constraint_idx,
            &[(FieldElement::one(), denominator)],
            &[(FieldElement::one(), inverse)],
            &[(FieldElement::one(), self.witness_one())],
        );
        inverse
    }

    // Add a new witness representing the product of two existing witnesses, and add an R1CS constraint enforcing this.
    fn add_product(&mut self, operand_a: usize, operand_b: usize) -> usize {
        let product = self.add_witness(WitnessBuilder::Product(operand_a, operand_b));
        let constraint_idx = self.new_constraint_index();
        self.set_constraint(
            constraint_idx,
            &[(FieldElement::one(), operand_a)],
            &[(FieldElement::one(), operand_b)],
            &[(FieldElement::one(), product)],
        );
        product
    }

    // Add a new witness representing the sum of existing witnesses, and add an R1CS constraint enforcing this.
    fn add_sum(&mut self, summands: Vec<usize>) -> usize {
        let sum = self.add_witness(WitnessBuilder::Sum(summands.clone()));
        let constraint_idx = self.new_constraint_index();
        let az = summands.iter().map(|&s| (FieldElement::one(), s)).collect::<Vec<_>>();
        self.set_constraint(
            constraint_idx,
            &az,
            &[(FieldElement::one(), self.witness_one())],
            &[(FieldElement::one(), sum)],
        );
        sum
    }

    // Add R1CS constraints to the instance to enforce that the provided ACIR expression is zero.
    fn add_acir_assert_zero(&mut self, expr: &Expression<FieldElement>) {
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
                    (-*coeff, self.add_product(witness0, witness1))
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
            "R1CS: {} witnesses, {} constraints, {} memory blocks",
            self.witness_builders.len(), self.num_constraints(), self.memory_lengths.len()
        )?;
        if self.memory_lengths.len() > 0 {
            writeln!(f, "Memory blocks:")?;
            for (block_id, block) in &self.memory_lengths {
                write!(f, "  {}: {} elements; ", block_id, block)?;
            }
            writeln!(f, "")?;
        }
        if std::cmp::max(self.num_constraints(), self.num_witnesses()) > 15 {
            println!("R1CS matrices too large to print");
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