use {
    crate::{
        r1cs_matrices::R1CSMatrices,
        solver::{R1CSSolver, WitnessBuilder},
    },
    acir::{
        circuit::{opcodes::BlockType, Circuit, Opcode},
        native_types::{Expression, Witness as AcirWitness},
        AcirField, FieldElement,
    },
    std::{
        collections::BTreeMap,
        fmt::{Debug, Formatter},
        ops::Neg,
        vec,
    },
};

/// Compiles an ACIR circuit into an [R1CS] instance, comprising the
/// [R1CSMatrices] and [R1CSSolver].
pub struct R1CS {
    pub matrices: R1CSMatrices,

    pub solver: R1CSSolver,

    // Maps indices of ACIR witnesses to indices of R1CS witnesses
    acir_to_r1cs_witness_map: BTreeMap<usize, usize>,
}

impl R1CS {
    /// The number of constraints in the R1CS instance.
    pub fn num_constraints(&self) -> usize {
        self.matrices.num_constraints()
    }

    /// The number of witnesses in the R1CS instance.
    /// This includes the constant one witness.
    pub fn num_witnesses(&self) -> usize {
        self.solver.num_witnesses()
    }

    /// Create an R1CS instance from an ACIR circuit, introducing R1CS witnesses
    /// and constraints as needed.
    pub fn from_acir(circuit: &Circuit<FieldElement>) -> Self {
        // Create a new R1CS instance
        let mut r1cs = Self {
            matrices:                 R1CSMatrices::new(),
            solver:                   R1CSSolver::new(),
            acir_to_r1cs_witness_map: BTreeMap::new(),
        };

        // Read-only memory blocks (used for building the memory lookup constraints at
        // the end)
        let mut memory_blocks: BTreeMap<usize, ReadOnlyMemoryBlock> = BTreeMap::new();
        for opcode in circuit.opcodes.iter() {
            match opcode {
                Opcode::AssertZero(expr) => {
                    r1cs.add_acir_assert_zero(expr);
                }

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
                    r1cs.solver.memory_lengths.insert(block_id, init.len());
                    let mut block = ReadOnlyMemoryBlock {
                        value_witnesses: vec![],
                        read_operations: vec![],
                    };
                    init.iter().for_each(|acir_witness| {
                        let r1cs_witness =
                            r1cs.add_witness(WitnessBuilder::Acir(acir_witness.0 as usize));
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

                    // Panic if the predicate is set (according to Noir developers, predicate is
                    // always None and will soon be removed).
                    assert!(predicate.is_none());

                    let block_id = block_id.0 as usize;
                    assert!(
                        memory_blocks.contains_key(&block_id),
                        "Memory block {} not initialized before read",
                        block_id
                    );
                    let block = memory_blocks.get_mut(&block_id).unwrap();

                    // Create a new (as yet unconstrained) witness `result_of_read` for the result
                    // of the read; it will be constrained by the lookup for the memory block at the
                    // end. Use a memory witness builders so that the solver can
                    // later determine its value and also determine the memory access counts

                    // "In read operations, [op.value] corresponds to the witness index at which the
                    // value from memory will be written." (from the Noir codebase)
                    // At R1CS solving time, only need to map over the value of the corresponding
                    // ACIR witness, whose value is already determined by the ACIR solver.
                    let result_of_read_acir_witness = op.value.to_witness().unwrap().0 as usize;

                    // It isn't clear from the Noir codebase if index can ever be a not equal to
                    // just a single ACIR witness. If it isn't, we'll need to
                    // introduce constraints and use a witness for the index, but let's leave this
                    // til later. (According to experiments, the index is always
                    // a witness, not a constant: static reads are hard-wired
                    // into the circuit, or instead rendered as a dynamic read
                    // by introducing a new witness constrained to have the value of
                    // the static address.)
                    let addr_wb = op.index.to_witness().map_or_else(
                        || {
                            unimplemented!(
                                "MemoryOp index must be a single witness, not a more general \
                                 Expression"
                            )
                        },
                        |acir_witness| WitnessBuilder::Acir(acir_witness.0 as usize),
                    );
                    let addr = r1cs.add_witness(addr_wb);
                    let value_read = r1cs.add_witness(WitnessBuilder::MemoryRead(
                        block_id,
                        addr,
                        result_of_read_acir_witness,
                    ));
                    block.read_operations.push((addr, value_read));
                }

                // These are calls to built-in functions, for this we need to create.
                Opcode::BlackBoxFuncCall(_) => {
                    println!("BlackBoxFuncCall")
                }
            }
        }

        // For each memory block, use a lookup to enforce that the reads are correct.
        memory_blocks.iter().for_each(|(block_id, block)| {
            // Add witness values for memory access counts, using the
            // WitnessBuilder::MemoryAccessCount
            let access_counts: Vec<_> = (0..block.value_witnesses.len())
                .map(|index| r1cs.add_witness(WitnessBuilder::MemoryAccessCount(*block_id, index)))
                .collect();

            // Add two verifier challenges for the lookup
            let rs_challenge = r1cs.add_witness(WitnessBuilder::Challenge);
            let sz_challenge = r1cs.add_witness(WitnessBuilder::Challenge);

            // Calculate the sum, over all reads, of 1/denominator
            let summands_for_reads = block
                .read_operations
                .iter()
                .map(|(addr_witness, value)| {
                    r1cs.add_indexed_lookup_factor(
                        rs_challenge,
                        sz_challenge,
                        FieldElement::one(),
                        *addr_witness,
                        *value,
                    )
                })
                .collect();
            let sum_for_reads = r1cs.add_sum(summands_for_reads);

            // Calculate the sum over all table elements of multiplicity/factor
            let summands_for_table = block
                .value_witnesses
                .iter()
                .zip(access_counts.iter())
                .enumerate()
                .map(|(addr, (value, access_count))| {
                    let denominator = r1cs.add_indexed_lookup_factor(
                        rs_challenge,
                        sz_challenge,
                        addr.into(),
                        r1cs.solver.witness_one(),
                        *value,
                    );
                    r1cs.add_product(*access_count, denominator)
                })
                .collect();
            let sum_for_table = r1cs.add_sum(summands_for_table);

            // Enforce that the two sums are equal
            r1cs.matrices.add_constraint(
                &[(FieldElement::one(), r1cs.solver.witness_one())],
                &[(FieldElement::one(), sum_for_reads)],
                &[(FieldElement::one(), sum_for_table)],
            );
        });
        r1cs
    }

    // Return the R1CS witness index corresponding to the AcirWitness provided,
    // creating a new R1CS witness (and builder) if required.
    fn fetch_r1cs_witness_index(&mut self, acir_witness_index: AcirWitness) -> usize {
        self.acir_to_r1cs_witness_map
            .get(&acir_witness_index.as_usize())
            .copied()
            .unwrap_or_else(|| {
                self.add_witness(WitnessBuilder::Acir(acir_witness_index.as_usize()))
            })
    }

    // Add a new witness to the R1CS instance, returning its index.
    // If the witness builder implicitly maps an ACIR witness to an R1CS witness,
    // then record this.
    fn add_witness(&mut self, witness_builder: WitnessBuilder) -> usize {
        let next_witness_idx = self.matrices.add_witness();
        // Add the witness to the mapping if it is an ACIR witness
        match &witness_builder {
            WitnessBuilder::Acir(acir_witness) => {
                self.acir_to_r1cs_witness_map
                    .insert(*acir_witness, next_witness_idx);
            }
            WitnessBuilder::MemoryRead(_, _, value_acir_witness) => {
                self.acir_to_r1cs_witness_map
                    .insert(*value_acir_witness, next_witness_idx);
            }
            _ => {}
        }
        self.solver.add_witness_builder(witness_builder);
        next_witness_idx
    }

    // Add a new witness representing the product of two existing witnesses, and add
    // an R1CS constraint enforcing this.
    fn add_product(&mut self, operand_a: usize, operand_b: usize) -> usize {
        let product = self.add_witness(WitnessBuilder::Product(operand_a, operand_b));
        self.matrices.add_constraint(
            &[(FieldElement::one(), operand_a)],
            &[(FieldElement::one(), operand_b)],
            &[(FieldElement::one(), product)],
        );
        product
    }

    // Add a new witness representing the sum of existing witnesses, and add an R1CS
    // constraint enforcing this.
    fn add_sum(&mut self, summands: Vec<usize>) -> usize {
        let sum = self.add_witness(WitnessBuilder::Sum(summands.clone()));
        let az = summands
            .iter()
            .map(|&s| (FieldElement::one(), s))
            .collect::<Vec<_>>();
        self.matrices
            .add_constraint(&az, &[(FieldElement::one(), self.solver.witness_one())], &[
                (FieldElement::one(), sum),
            ]);
        sum
    }

    // Add R1CS constraints to the instance to enforce that the provided ACIR
    // expression is zero.
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
                    let witness0 = self.fetch_r1cs_witness_index(*acir_witness0);
                    let witness1 = self.fetch_r1cs_witness_index(*acir_witness1);
                    (-*coeff, self.add_product(witness0, witness1))
                })
                .collect::<Vec<_>>();

            // Handle the last multiplication term directly
            let (coeff, acir_witness0, acir_witness1) = &expr.mul_terms[expr.mul_terms.len() - 1];
            a = vec![(
                FieldElement::from(*coeff),
                self.fetch_r1cs_witness_index(*acir_witness0),
            )];
            b = vec![(
                FieldElement::one(),
                self.fetch_r1cs_witness_index(*acir_witness1),
            )];
        }

        // Extend with linear combinations
        linear.extend(
            expr.linear_combinations
                .iter()
                .map(|(coeff, acir_witness)| {
                    (coeff.neg(), self.fetch_r1cs_witness_index(*acir_witness))
                }),
        );

        // Add constant by multipliying with constant value one.
        linear.push((expr.q_c.neg(), self.solver.witness_one()));

        // Add a single linear constraint
        // We could avoid this by substituting back into the last multiplication
        // constraint.
        self.matrices.add_constraint(&a, &b, &linear);
    }

    // Helper function for adding a new lookup factor to the R1CS instance.
    // Adds a new witness `denominator` and constrains it to represent
    //    `denominator - (sz_challenge - (index_coeff * index + rs_challenge *
    // value)) == 0`, where `sz_challenge`, `index`, `rs_challenge` and `value`
    // are the provided R1CS witness indices. Finally, adds a new witness for
    // its inverse, constrains it to be such, and returns its index.
    fn add_indexed_lookup_factor(
        &mut self,
        rs_challenge: usize,
        sz_challenge: usize,
        index: FieldElement,
        index_witness: usize,
        value: usize,
    ) -> usize {
        let wb = WitnessBuilder::LogUpDenominator(
            sz_challenge,
            (index, index_witness),
            rs_challenge,
            value,
        );
        let denominator = self.add_witness(wb);
        self.matrices.add_constraint(
            &[(FieldElement::one(), rs_challenge)],
            &[(FieldElement::one(), value)],
            &[
                (FieldElement::one().neg(), denominator),
                (FieldElement::one(), sz_challenge),
                (index.neg(), index_witness),
            ],
        );
        let inverse = self.add_witness(WitnessBuilder::Inverse(denominator));
        self.matrices.add_constraint(
            &[(FieldElement::one(), denominator)],
            &[(FieldElement::one(), inverse)],
            &[(FieldElement::one(), self.solver.witness_one())],
        );
        inverse
    }
}

impl std::fmt::Display for R1CS {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "R1CS: {} witnesses, {} constraints, {} memory blocks",
            self.num_witnesses(),
            self.num_constraints(),
            self.solver.memory_lengths.len()
        )?;
        if !self.solver.memory_lengths.is_empty() {
            writeln!(f, "Memory blocks:")?;
            for (block_id, block) in &self.solver.memory_lengths {
                write!(f, "  {}: {} elements; ", block_id, block)?;
            }
            writeln!(f)?;
        }
        writeln!(f, "{}", self.matrices)
    }
}

#[derive(Debug, Clone)]
/// Used for tracking reads of a read-only memory block
pub struct ReadOnlyMemoryBlock {
    /// The R1CS witnesses corresponding to the memory block values
    pub value_witnesses: Vec<usize>,
    /// (R1CS witness index of address, R1CS witness index of value read) tuples
    pub read_operations: Vec<(usize, usize)>,
}
