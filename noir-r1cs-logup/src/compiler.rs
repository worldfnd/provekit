use {
    crate::{
        memory::{MemoryBlock, MemoryOperation},
        r1cs_matrices::R1CSMatrices,
        ram::add_ram_checking,
        range_check::add_range_checks,
        rom::add_rom_checking,
        solver::{MockTranscript, WitnessBuilder},
    },
    acir::{
        circuit::{
            opcodes::{BlackBoxFuncCall, BlockType, ConstantOrWitnessEnum},
            Circuit, Opcode,
        },
        native_types::{Expression, Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    },
    std::{collections::BTreeMap, fmt::Formatter, ops::Neg, vec},
};

/// Compiles an ACIR circuit into an [R1CS] instance, comprising the
/// [R1CSMatrices] and a vector of [WitnessBuilder]s.
pub struct R1CS {
    pub matrices: R1CSMatrices,

    // Maps indices of ACIR witnesses to indices of R1CS witnesses
    acir_to_r1cs_witness_map: BTreeMap<usize, usize>,

    /// Indicates how to solve for each R1CS witness
    pub witness_builders: Vec<WitnessBuilder>,

    /// The ACIR witness indices of the initial values of the memory blocks
    pub initial_memories: BTreeMap<usize, Vec<usize>>,
}

impl R1CS {
    /// The number of constraints in the R1CS instance.
    pub fn num_constraints(&self) -> usize {
        self.matrices.num_constraints()
    }

    // Add a new witness to the R1CS instance, returning its index.
    // If the witness builder implicitly maps an ACIR witness to an R1CS witness,
    // then record this.
    pub fn add_witness_builder(&mut self, witness_builder: WitnessBuilder) -> usize {
        let start_idx = self.num_witnesses();
        self.matrices.add_witnesses(witness_builder.num_witnesses());
        // Add the witness to the mapping if it is an ACIR witness
        match &witness_builder {
            WitnessBuilder::Acir(r1cs_witness_idx, acir_witness) => {
                self.acir_to_r1cs_witness_map
                    .insert(*acir_witness, *r1cs_witness_idx);
            }
            _ => {}
        }
        self.witness_builders.push(witness_builder);
        start_idx
    }

    /// Given the ACIR witness values, solve for the R1CS witness values.
    pub fn solve(
        &self,
        transcript: &mut MockTranscript,
        acir_witnesses: &WitnessMap<FieldElement>,
    ) -> Vec<FieldElement> {
        let mut witness = vec![FieldElement::zero(); self.num_witnesses()];
        self.witness_builders.iter().for_each(|witness_builder| {
            witness_builder.solve_and_append_to_transcript(
                &mut witness,
                acir_witnesses,
                transcript,
            );
        });
        witness
    }

    /// The number of witnesses in the R1CS instance.
    /// This includes the constant one witness.
    pub fn num_witnesses(&self) -> usize {
        self.matrices.num_witnesses()
    }

    /// Index of the constant 1 witness
    pub const fn witness_one(&self) -> usize {
        0
    }

    /// Create an R1CS instance from an ACIR circuit, introducing R1CS witnesses
    /// and constraints as needed.
    pub fn from_acir(circuit: &Circuit<FieldElement>) -> Self {
        // Create a new R1CS instance
        let mut r1cs = Self {
            matrices:                 R1CSMatrices::new(),
            acir_to_r1cs_witness_map: BTreeMap::new(),
            witness_builders:         vec![WitnessBuilder::Constant(0, FieldElement::one())], /* FIXME magic */
            initial_memories:         BTreeMap::new(),
        };

        // Read-only memory blocks (used for building the memory lookup constraints at
        // the end)
        let mut memory_blocks: BTreeMap<usize, MemoryBlock> = BTreeMap::new();
        // Mapping the log of the range size k to the vector of witness indices that
        // are to be constrained within the range [0..2^k].
        // These will be digitally decomposed into smaller ranges, if necessary.
        let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
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
                    r1cs.initial_memories
                        .insert(block_id, init.iter().map(|w| w.0 as usize).collect());
                    let mut block = MemoryBlock::new();
                    init.iter().for_each(|acir_witness| {
                        let r1cs_witness = r1cs.fetch_r1cs_witness_index(*acir_witness);
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

                    // `op.index` is _always_ just a single ACIR witness, not a more complicated
                    // expression, and not a constant. See [here](https://discord.com/channels/1113924620781883405/1356865341065531446)
                    // Static reads are hard-wired into the circuit, or instead rendered as a
                    // dummy dynamic read by introducing a new witness constrained to have the value
                    // of the static address.
                    let addr = op.index.to_witness().map_or_else(
                        || {
                            unimplemented!(
                                "MemoryOp index must be a single witness, not a more general \
                                 Expression"
                            )
                        },
                        |acir_witness| r1cs.fetch_r1cs_witness_index(acir_witness),
                    );

                    let op = if op.operation.is_zero() {
                        // Create a new (as yet unconstrained) witness `result_of_read` for the
                        // result of the read; it will be constrained by later memory block
                        // processing.
                        // "In read operations, [op.value] corresponds to the witness index at which
                        // the value from memory will be written." (from the Noir codebase)
                        // At R1CS solving time, only need to map over the value of the
                        // corresponding ACIR witness, whose value is already determined by the ACIR
                        // solver.
                        let result_of_read =
                            r1cs.fetch_r1cs_witness_index(op.value.to_witness().unwrap());
                        MemoryOperation::Load(addr, result_of_read)
                    } else {
                        let new_value =
                            r1cs.fetch_r1cs_witness_index(op.value.to_witness().unwrap());
                        MemoryOperation::Store(addr, new_value)
                    };
                    block.operations.push(op);
                }

                Opcode::BlackBoxFuncCall(black_box_func_call) => match black_box_func_call {
                    BlackBoxFuncCall::RANGE {
                        input: function_input,
                    } => {
                        let input = function_input.input();
                        let num_bits = function_input.num_bits();
                        let input_witness = match input {
                            ConstantOrWitnessEnum::Constant(_) => {
                                panic!(
                                    "We should never be range-checking a constant value, as this \
                                     should already be done by the noir-ACIR compiler"
                                );
                            }
                            ConstantOrWitnessEnum::Witness(witness) => {
                                r1cs.fetch_r1cs_witness_index(witness)
                            }
                        };
                        println!(
                            "RANGE CHECK of witness {} to {} bits",
                            input_witness, num_bits
                        );
                        // Add the entry into the range blocks.
                        range_checks
                            .entry(num_bits)
                            .or_default()
                            .push(input_witness);
                    }
                    _ => println!("BlackBoxFuncCall"),
                },
            }
        }

        // For each memory block, add appropriate constraints (depending on whether it
        // is read-only or not)
        memory_blocks.iter().for_each(|(_, block)| {
            if block.is_read_only() {
                // Use a lookup to enforce that the reads are correct.
                add_rom_checking(&mut r1cs, block);
            } else {
                // Read/write memory block - use Spice offline memory checking.
                // Returns witnesses that need to be range checked.
                let (num_bits, witnesses_to_range_check) = add_ram_checking(&mut r1cs, block);
                let range_check = range_checks.entry(num_bits).or_default();
                witnesses_to_range_check
                    .iter()
                    .for_each(|value| range_check.push(*value));
            }
        });

        // Perform all range checks
        add_range_checks(&mut r1cs, range_checks);

        r1cs
    }

    // Return the R1CS witness index corresponding to the AcirWitness provided,
    // creating a new R1CS witness (and builder) if required.
    fn fetch_r1cs_witness_index(&mut self, acir_witness_index: AcirWitness) -> usize {
        self.acir_to_r1cs_witness_map
            .get(&acir_witness_index.as_usize())
            .copied()
            .unwrap_or_else(|| {
                self.add_witness_builder(WitnessBuilder::Acir(
                    self.num_witnesses(),
                    acir_witness_index.as_usize(),
                ))
            })
    }

    /// Add a new witness representing the product of two existing witnesses,
    /// and add an R1CS constraint enforcing this.
    pub(crate) fn add_product(&mut self, operand_a: usize, operand_b: usize) -> usize {
        let product = self.add_witness_builder(WitnessBuilder::Product(
            self.num_witnesses(),
            operand_a,
            operand_b,
        ));
        self.matrices.add_constraint(
            &[(FieldElement::one(), operand_a)],
            &[(FieldElement::one(), operand_b)],
            &[(FieldElement::one(), product)],
        );
        product
    }

    /// Add a new witness representing the sum of existing witnesses, and add an
    /// R1CS constraint enforcing this. Vector consists of (optional
    /// coefficient, witness index) tuples, one for each summand.
    /// The coefficient is optional, and if it is None, the coefficient is 1.
    pub(crate) fn add_sum(&mut self, summands: Vec<(Option<FieldElement>, usize)>) -> usize {
        let sum =
            self.add_witness_builder(WitnessBuilder::Sum(self.num_witnesses(), summands.clone()));
        let az = summands
            .iter()
            .map(|(coeff, witness_idx)| (coeff.unwrap_or(FieldElement::one()), *witness_idx))
            .collect::<Vec<_>>();
        self.matrices
            .add_constraint(&az, &[(FieldElement::one(), self.witness_one())], &[(
                FieldElement::one(),
                sum,
            )]);
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
        linear.push((expr.q_c.neg(), self.witness_one()));

        // Add a single linear constraint
        // We could avoid this by substituting back into the last multiplication
        // constraint.
        self.matrices.add_constraint(&a, &b, &linear);
    }
}

impl std::fmt::Display for R1CS {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "R1CS: {} witnesses, {} constraints, {} memory blocks",
            self.num_witnesses(),
            self.num_constraints(),
            self.initial_memories.len()
        )?;
        if !self.initial_memories.is_empty() {
            writeln!(f, "Memory blocks:")?;
            for (block_id, block) in &self.initial_memories {
                write!(f, "  {}: {} elements; ", block_id, block.len())?;
            }
            writeln!(f)?;
        }
        writeln!(f, "{}", self.matrices)
    }
}
