use {
    crate::{
        r1cs_matrices::R1CSMatrices,
        solver::{R1CSSolver, WitnessBuilder},
    }, acir::{
        circuit::{opcodes::BlockType, Circuit, Opcode},
        native_types::{Expression, Witness as AcirWitness},
        AcirField, FieldElement,
    }, acvm::brillig_vm::Memory, core::hash, std::{
        collections::BTreeMap,
        fmt::{Debug, Formatter},
        ops::Neg,
        vec,
    }, tracing::field::Field
};

/// Compiles an ACIR circuit into an [R1CS] instance, comprising the [R1CSMatrices] and
/// [R1CSSolver].
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

    /// Create an R1CS instance from an ACIR circuit, introducing R1CS witnesses and constraints as
    /// needed.
    pub fn from_acir(circuit: &Circuit<FieldElement>) -> Self {
        // Create a new R1CS instance
        let mut r1cs = Self {
            matrices: R1CSMatrices::new(),
            solver: R1CSSolver::new(),
            acir_to_r1cs_witness_map: BTreeMap::new(),
        };

        // Read-only memory blocks (used for building the memory lookup constraints at the end)
        let mut memory_blocks: BTreeMap<usize, MemoryBlock> = BTreeMap::new();
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
                    r1cs.solver.initial_memories.insert(block_id, init.iter().map(|w| w.0 as usize).collect());
                    let mut block = MemoryBlock::new();
                    init.iter().for_each(|acir_witness| {
                        let r1cs_witness =
                            r1cs.add_witness(WitnessBuilder::Acir(acir_witness.0 as usize));
                        // Add the witness index to the memory block
                        block.initial_value_witnesses.push(r1cs_witness);
                    });
                    memory_blocks.insert(block_id, block);
                }

                Opcode::MemoryOp {
                    block_id,
                    op,
                    predicate,
                } => {
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

                    // `op.index` is _always_ just a single ACIR witness, not a more complicated expression, and not a constant.
                    // See [here](https://discord.com/channels/1113924620781883405/1356865341065531446)
                    // Static reads are hard-wired into the circuit, or instead rendered as a
                    // dummy dynamic read by introducing a new witness constrained to have the value of
                    // the static address.
                    let addr_wb = op.index.to_witness().map_or_else(
                        || {
                            unimplemented!("MemoryOp index must be a single witness, not a more general Expression")
                        },
                        |acir_witness| WitnessBuilder::Acir(acir_witness.0 as usize),
                    );
                    let addr = r1cs.add_witness(addr_wb);

                    let op = if op.operation.is_zero() {
                        // Create a new (as yet unconstrained) witness `result_of_read` for the result of the read; it will be constrained by the lookup for the memory block at the end.
                        // Use a MemoryRead witness builder so that the solver can determine its value and also count memory accesses to each address.

                        // "In read operations, [op.value] corresponds to the witness index at which the value from memory will be written." (from the Noir codebase)
                        // At R1CS solving time, only need to map over the value of the corresponding ACIR witness, whose value is already determined by the ACIR solver.
                        let result_of_read_acir_witness = op.value.to_witness().unwrap().0 as usize;

                        let result_of_read = r1cs.add_witness(WitnessBuilder::ValueReadFromMemory(
                            block_id,
                            addr,
                            result_of_read_acir_witness,
                        ));
                        MemoryOperation::Read(addr, result_of_read)
                    } else {
                        let value_written = r1cs.add_witness(WitnessBuilder::ValueWrittenToMemory(
                            block_id,
                            addr,
                            // TODO check that op.value is indeed the value written
                            op.value.to_witness().unwrap().0 as usize,
                        ));
                        MemoryOperation::Write(addr, value_written)
                    };
                    block.operations.push(op);
                }

                // These are calls to built-in functions, for this we need to create.
                Opcode::BlackBoxFuncCall(_) => {
                    println!("BlackBoxFuncCall")
                }
            }
        }

        // For each memory block, add appropriate constraints (depending on whether it is read-only or not)
        memory_blocks.iter().for_each(|(block_id, block)| {
            if block.is_read_only() {
                // Use a lookup to enforce that the reads are correct.
                // Add witness entries for memory access counts, using the WitnessBuilder::MemoryAccessCount
                let access_counts: Vec<_> = (0..block.initial_value_witnesses.len())
                    .map(|index| r1cs.add_witness(WitnessBuilder::MemoryReadCount(*block_id, index)))
                    .collect();

                // Add two verifier challenges for the lookup
                let rs_challenge = r1cs.add_witness(WitnessBuilder::Challenge);
                let sz_challenge = r1cs.add_witness(WitnessBuilder::Challenge);

                // Calculate the sum, over all reads, of 1/denominator
                let summands_for_reads = block
                    .operations
                    .iter()
                    .map(|op| {
                        match op {
                            MemoryOperation::Read(addr_witness, value) => {
                                r1cs.add_indexed_lookup_factor(
                                    rs_challenge,
                                    sz_challenge,
                                    FieldElement::one(),
                                    *addr_witness,
                                    *value,
                                )
                            }
                            MemoryOperation::Write(_, _) => {
                                unreachable!();
                            }
                        }
                    }).collect();
                let sum_for_reads = r1cs.add_sum(summands_for_reads);

                // Calculate the sum over all table elements of multiplicity/factor
                let summands_for_table = block
                    .initial_value_witnesses
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
            } else {
                // Read/write memory block - use Spice offline memory checking
                let rs_challenge = r1cs.add_witness(WitnessBuilder::Challenge);
                let rs_challenge_sqrd = r1cs.add_product(rs_challenge, rs_challenge);

                let mut read_hash = r1cs.solver.witness_one();
                let mut write_hash = r1cs.solver.witness_one();

                // For each of the writes in the inititialization, add a factor to the write hash
                block.initial_value_witnesses.iter().enumerate().for_each(|(addr, mem_value)| {
                    // Initial PUTs. These all use timestamp zero.
                    let hash_value = r1cs.add_memory_op_hash(
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::from(addr), r1cs.solver.witness_one()),
                        *mem_value,
                        (FieldElement::zero(), r1cs.solver.witness_one()),
                    );
                    write_hash = r1cs.add_product(write_hash, hash_value);
                });

                // TODO double check that it makes sense that the same constraints are added in both the read and the write case
                block.operations.iter().enumerate().for_each(|(mem_op_index, op)| {
                    match op {
                        MemoryOperation::Read(addr_witness, value) => {
                            // GET
                            let retrieved_timer = r1cs.add_witness(WitnessBuilder::MemoryReadTimestamp(
                                *block_id,
                                (1, *addr_witness),
                            ));
                            let hash_value = r1cs.add_memory_op_hash(
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *value,
                                (FieldElement::one(), retrieved_timer),
                            );
                            read_hash = r1cs.add_product(read_hash, hash_value);

                            // PUT
                            let hash_value = r1cs.add_memory_op_hash(
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *value,
                                (FieldElement::from(mem_op_index + 1), r1cs.solver.witness_one()),
                            );
                            write_hash = r1cs.add_product(write_hash, hash_value);
                        }
                        MemoryOperation::Write(addr_witness, value) => {
                            // GET
                            let retrieved_timer = r1cs.add_witness(WitnessBuilder::MemoryReadTimestamp(
                                *block_id,
                                (1, *addr_witness),
                            ));
                            let hash_value = r1cs.add_memory_op_hash(
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *value,
                                (FieldElement::one(), retrieved_timer),
                            );
                            read_hash = r1cs.add_product(read_hash, hash_value);

                            // PUT
                            let hash_value = r1cs.add_memory_op_hash(
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *value,
                                (FieldElement::from(mem_op_index + 1), r1cs.solver.witness_one()),
                            );
                            write_hash = r1cs.add_product(write_hash, hash_value);
                        }
                    }
                });

                // For each of the cells of the memory block, add a factor to the read hash
                (0..block.initial_value_witnesses.len()).for_each(|addr| {
                    // Implementation note: the values read via all of the memory operations above
                    // are provided by ACIR.  By constrast, here, for the "audit" reads at the end
                    // of offline memory checking, we need to add witnesses for these values
                    // ourselves.
                    let value = r1cs.add_witness(WitnessBuilder::FinalMemoryValue(
                        *block_id,
                        addr,
                    ));
                    // GET
                    let retrieved_timer = r1cs.add_witness(WitnessBuilder::MemoryReadTimestamp(
                        *block_id,
                        (addr, r1cs.solver.witness_one()),
                    ));
                    let hash_value = r1cs.add_memory_op_hash(
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::from(addr), r1cs.solver.witness_one()),
                        value,
                        (FieldElement::one(), retrieved_timer),
                    );
                    read_hash = r1cs.add_product(read_hash, hash_value);
                });

                // Add the final constraint to enforce that the hashes are equal
                r1cs.matrices.add_constraint(
                    &[(FieldElement::one(), r1cs.solver.witness_one())],
                    &[(FieldElement::one(), read_hash)],
                    &[(FieldElement::one(), write_hash)],
                );

                // TODO add the range checks!
            }
        });
        r1cs
    }

    // FIXME can we generalize this to work for any RS signature?  Wouldn't it then be useful for logup and permutation arguments in general?
    // add_rs_fingerprint/add_permutation_factor([rs challenges; N], [things to be combined; N+1])
    fn add_memory_op_hash(
        &mut self,
        rs_challenge: usize,
        rs_challenge_sqrd: usize,
        (addr, addr_witness): (FieldElement, usize),
        value_witness: usize,
        (timer, timer_witness): (FieldElement, usize),
    ) -> usize {
        let hash_value = self.add_witness(WitnessBuilder::HashValue(
            rs_challenge,
            (addr, addr_witness),
            value_witness,
            (timer, timer_witness),
        ));
        let intermediate = self.add_product(rs_challenge_sqrd, timer_witness);
        self.matrices.add_constraint(
            &[(FieldElement::one(), rs_challenge)],
            &[(FieldElement::one(), value_witness)],
            &[
                (FieldElement::one(), hash_value),
                (timer.neg(), intermediate),
                (addr.neg(), addr_witness),
            ],
        );
        0
    }

    // Return the R1CS witness index corresponding to the AcirWitness provided, creating a new R1CS
    // witness (and builder) if required.
    fn fetch_r1cs_witness_index(&mut self, acir_witness_index: AcirWitness) -> usize {
        self.acir_to_r1cs_witness_map
            .get(&acir_witness_index.as_usize())
            .copied()
            .unwrap_or_else(|| {
                self.add_witness(WitnessBuilder::Acir(acir_witness_index.as_usize()))
            })
    }

    // Add a new witness to the R1CS instance, returning its index.
    // If the witness builder implicitly maps an ACIR witness to an R1CS witness, then record this.
    fn add_witness(&mut self, witness_builder: WitnessBuilder) -> usize {
        let next_witness_idx = self.matrices.add_witness();
        // Add the witness to the mapping if it is an ACIR witness
        match &witness_builder {
            WitnessBuilder::Acir(acir_witness) => {
                self.acir_to_r1cs_witness_map
                    .insert(*acir_witness, next_witness_idx);
            }
            WitnessBuilder::ValueReadFromMemory(_, _, value_acir_witness) => {
                self.acir_to_r1cs_witness_map
                    .insert(*value_acir_witness, next_witness_idx);
            }
            _ => {}
        }
        self.solver.add_witness_builder(witness_builder);
        next_witness_idx
    }

    // Add a new witness representing the product of two existing witnesses, and add an R1CS constraint enforcing this.
    fn add_product(&mut self, operand_a: usize, operand_b: usize) -> usize {
        let product = self.add_witness(WitnessBuilder::Product(operand_a, operand_b));
        self.matrices.add_constraint(
            &[(FieldElement::one(), operand_a)],
            &[(FieldElement::one(), operand_b)],
            &[(FieldElement::one(), product)],
        );
        product
    }

    // Add a new witness representing the sum of existing witnesses, and add an R1CS constraint enforcing this.
    fn add_sum(&mut self, summands: Vec<usize>) -> usize {
        let sum = self.add_witness(WitnessBuilder::Sum(summands.clone()));
        let az = summands
            .iter()
            .map(|&s| (FieldElement::one(), s))
            .collect::<Vec<_>>();
        self.matrices.add_constraint(
            &az,
            &[(FieldElement::one(), self.solver.witness_one())],
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
    //    `denominator - (sz_challenge - (index_coeff * index + rs_challenge * value)) == 0`,
    // where `sz_challenge`, `index`, `rs_challenge` and `value` are the provided R1CS witness indices.
    // Finally, adds a new witness for its inverse, constrains it to be such, and returns its index.
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

// FIXME should display if memory read-only or read/write
impl std::fmt::Display for R1CS {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "R1CS: {} witnesses, {} constraints, {} memory blocks",
            self.num_witnesses(),
            self.num_constraints(),
            self.solver.initial_memories.len()
        )?;
        if !self.solver.initial_memories.is_empty() {
            writeln!(f, "Memory blocks:")?;
            for (block_id, block) in &self.solver.initial_memories {
                write!(f, "  {}: {} elements; ", block_id, block.len())?;
            }
            writeln!(f)?;
        }
        writeln!(f, "{}", self.matrices)
    }
}

#[derive(Debug, Clone)]
/// Used for tracking reads of a read-only memory block
pub struct MemoryBlock {
    /// The R1CS witnesses corresponding to the memory block values
    pub initial_value_witnesses: Vec<usize>,
    /// The memory operations, in the order that they occur
    pub operations: Vec<MemoryOperation>,
}

impl MemoryBlock {
    pub fn new() -> Self {
        Self {
            initial_value_witnesses: vec![],
            operations: vec![],
        }
    }

    pub fn is_read_only(&self) -> bool {
        self.operations.iter().all(|op| match op {
            MemoryOperation::Read(_, _) => true,
            MemoryOperation::Write(_, _) => false,
        })
    }
}

#[derive(Debug, Clone)]
pub enum MemoryOperation {
    /// (R1CS witness index of address, R1CS witness index of value read) tuples
    Read(usize, usize),
    /// (R1CS witness index of address, R1CS witness index of value to write) tuples
    Write(usize, usize),
}