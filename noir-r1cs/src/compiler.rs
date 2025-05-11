use {
    crate::{
        r1cs_matrices::R1CSMatrices,
        solver::{MockTranscript, WitnessBuilder},
    }, acir::{
        circuit::{opcodes::{BlackBoxFuncCall, BlockType, ConstantOrWitnessEnum}, Circuit, Opcode},
        native_types::{Expression, Witness as AcirWitness, WitnessMap},
        AcirField, FieldElement,
    }, std::{
        collections::BTreeMap, fmt::{Debug, Formatter}, ops::Neg, vec
    }
};

const NUM_WITNESS_THRESHOLD_FOR_LOOKUP_TABLE: usize = 5;
pub const NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP: u32 = 8;

/// Compiles an ACIR circuit into an [R1CS] instance, comprising the [R1CSMatrices] and
/// a vector of [WitnessBuilder]s.
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
    // If the witness builder implicitly maps an ACIR witness to an R1CS witness, then record this.
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
        self.witness_builders
            .iter()
            .for_each(|witness_builder| {
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

    /// Create an R1CS instance from an ACIR circuit, introducing R1CS witnesses and constraints as
    /// needed.
    pub fn from_acir(circuit: &Circuit<FieldElement>) -> Self {
        // Create a new R1CS instance
        let mut r1cs = Self {
            matrices: R1CSMatrices::new(),
            acir_to_r1cs_witness_map: BTreeMap::new(),
            witness_builders: vec![WitnessBuilder::Constant(0, FieldElement::one())], // FIXME magic
            initial_memories: BTreeMap::new(),
        };

        // Read-only memory blocks (used for building the memory lookup constraints at the end)
        let mut memory_blocks: BTreeMap<usize, MemoryBlock> = BTreeMap::new();
        // Mapping the log of the range size k to the vector of witness indices that
        // are to be constrained within the range [0..2^k].
        // These will be digitally decomposed into smaller ranges, if necessary.
        let mut range_blocks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
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
                    r1cs.initial_memories.insert(block_id, init.iter().map(|w| w.0 as usize).collect());
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

                    // `op.index` is _always_ just a single ACIR witness, not a more complicated expression, and not a constant.
                    // See [here](https://discord.com/channels/1113924620781883405/1356865341065531446)
                    // Static reads are hard-wired into the circuit, or instead rendered as a
                    // dummy dynamic read by introducing a new witness constrained to have the value of
                    // the static address.
                    let addr = op.index.to_witness().map_or_else(
                        || {
                            unimplemented!("MemoryOp index must be a single witness, not a more general Expression")
                        },
                        |acir_witness| r1cs.fetch_r1cs_witness_index(acir_witness)
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
                        let result_of_read = r1cs.fetch_r1cs_witness_index(op.value.to_witness().unwrap());
                        MemoryOperation::Load(addr, result_of_read)
                    } else {
                        let new_value = r1cs.fetch_r1cs_witness_index(op.value.to_witness().unwrap());
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
                        let input_witness = match input 
                        {
                            ConstantOrWitnessEnum::Constant(_) => {
                                panic!("We should never be range-checking a constant value, as this should already be done by the noir-ACIR compiler");
                            }
                            ConstantOrWitnessEnum::Witness(witness) => {
                                r1cs.fetch_r1cs_witness_index(witness)
                            }
                        };
                        // Add the entry into the range blocks.
                        range_blocks
                            .entry(num_bits)
                            .or_default()
                            .push(input_witness);
                    }
                    _ => println!("BlackBoxFuncCall")
                }
            }
        }

        // For each memory block, add appropriate constraints (depending on whether it is read-only or not)
        memory_blocks.iter().for_each(|(_, block)| {
            if block.is_read_only() {
                // Use a lookup to enforce that the reads are correct.
                let addr_witnesses = block
                    .operations
                    .iter()
                    .map(|op| {
                        match op {
                            MemoryOperation::Load(addr_witness, _) => *addr_witness,
                            MemoryOperation::Store(_, _) => unreachable!(),
                        }
                    })
                    .collect::<Vec<_>>();
                let memory_length = block.initial_value_witnesses.len();
                let wb = WitnessBuilder::MemoryAccessCounts(r1cs.num_witnesses(), memory_length, addr_witnesses);
                let access_counts_first_witness = r1cs.add_witness_builder(wb);

                // Add two verifier challenges for the lookup
                let rs_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));
                let sz_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));

                // Calculate the sum, over all reads, of 1/denominator
                let summands_for_reads = block
                    .operations
                    .iter()
                    .map(|op| {
                        match op {
                            MemoryOperation::Load(addr_witness, value) => {
                                r1cs.add_indexed_lookup_factor(
                                    rs_challenge,
                                    sz_challenge,
                                    FieldElement::one(),
                                    *addr_witness,
                                    *value,
                                )
                            }
                            MemoryOperation::Store(_, _) => {
                                unreachable!();
                            }
                        }
                    }).collect();
                let sum_for_reads = r1cs.add_sum(summands_for_reads);

                // Calculate the sum over all table elements of multiplicity/factor
                let summands_for_table = block
                    .initial_value_witnesses
                    .iter()
                    .zip(0..memory_length)
                    .enumerate()
                    .map(|(addr, (value, access_count_idx_offset))| {
                        let denominator = r1cs.add_indexed_lookup_factor(
                            rs_challenge,
                            sz_challenge,
                            addr.into(),
                            r1cs.witness_one(),
                            *value,
                        );
                        r1cs.add_product(access_counts_first_witness + access_count_idx_offset, denominator)
                    })
                    .collect();
                let sum_for_table = r1cs.add_sum(summands_for_table);

                // Enforce that the two sums are equal
                r1cs.matrices.add_constraint(
                    &[(FieldElement::one(), r1cs.witness_one())],
                    &[(FieldElement::one(), sum_for_reads)],
                    &[(FieldElement::one(), sum_for_table)],
                );
            } else {
                // Read/write memory block - use Spice offline memory checking
                // Add two verifier challenges for the multiset check
                let rs_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));
                let rs_challenge_sqrd = r1cs.add_product(rs_challenge, rs_challenge);
                let sz_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));

                // The current witnesses indices for the partial products of the read set (RS) hash
                // and the write set (WS) hash
                let mut rs_hash = r1cs.witness_one();
                let mut ws_hash = r1cs.witness_one();

                let memory_length = block.initial_value_witnesses.len();

                // Track all the (mem_op_index, read timestamp) pairs so we can perform the two
                // required range checks later.
                let mut all_mem_op_index_and_rt = vec![];

                println!("INIT");
                // For each of the writes in the inititialization, add a factor to the write hash
                block.initial_value_witnesses.iter().enumerate().for_each(|(addr, mem_value)| {
                    // Initial PUTs. These all use timestamp zero.
                    let factor = r1cs.add_mem_op_multiset_factor(
                        sz_challenge,
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::from(addr), r1cs.witness_one()),
                        *mem_value,
                        (FieldElement::zero(), r1cs.witness_one()),
                    );
                    println!("WS factor [{}]: ({}, [{}], 0)", factor, addr, mem_value);
                    ws_hash = r1cs.add_product(ws_hash, factor);
                });

                let spice_witnesses = SpiceWitnesses::new(
                        r1cs.num_witnesses(),
                        memory_length,
                        block.initial_value_witnesses[0],
                        block.operations.clone());
                r1cs.add_witness_builder(WitnessBuilder::SpiceWitnesses(spice_witnesses.clone()));

                spice_witnesses.memory_operations.iter().enumerate().for_each(|(mem_op_index, op)| {
                    match op {
                        SpiceMemoryOperation::Load(addr_witness, value_witness, rt_witness) => {
                            println!("LOAD (mem op {})", mem_op_index);
                            // GET
                            all_mem_op_index_and_rt.push((mem_op_index, *rt_witness));
                            let factor = r1cs.add_mem_op_multiset_factor(
                                sz_challenge,
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *value_witness,
                                (FieldElement::one(), *rt_witness),
                            );
                            println!("RS factor [{}]: ([{}], [{}], [{}])", factor, addr_witness, value_witness, rt_witness);
                            rs_hash = r1cs.add_product(rs_hash, factor);

                            // PUT
                            let factor = r1cs.add_mem_op_multiset_factor(
                                sz_challenge,
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *value_witness,
                                (FieldElement::from(mem_op_index + 1), r1cs.witness_one()),
                            );
                            println!("WS factor [{}]: ([{}], [{}], {})", factor, addr_witness, value_witness, mem_op_index + 1);
                            ws_hash = r1cs.add_product(ws_hash, factor);
                        }
                        SpiceMemoryOperation::Store(addr_witness, old_value_witness, new_value_witness, rt_witness) => {
                            println!("STORE (mem op {})", mem_op_index);
                            // GET
                            all_mem_op_index_and_rt.push((mem_op_index, *rt_witness));
                            let factor = r1cs.add_mem_op_multiset_factor(
                                sz_challenge,
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *old_value_witness,
                                (FieldElement::one(), *rt_witness),
                            );
                            println!("RS factor [{}]: ([{}], [{}], [{}])", factor, addr_witness, old_value_witness, rt_witness);
                            rs_hash = r1cs.add_product(rs_hash, factor);

                            // PUT
                            let factor = r1cs.add_mem_op_multiset_factor(
                                sz_challenge,
                                rs_challenge,
                                rs_challenge_sqrd,
                                (FieldElement::one(), *addr_witness),
                                *new_value_witness,
                                (FieldElement::from(mem_op_index + 1), r1cs.witness_one()),
                            );
                            println!("WS factor [{}]: ([{}], [{}], {})", factor, addr_witness, new_value_witness, mem_op_index + 1);
                            ws_hash = r1cs.add_product(ws_hash, factor);
                        }
                    }
                });

                println!("AUDIT");
                // audit(): for each of the cells of the memory block, add a factor to the read hash
                (0..memory_length).for_each(|addr| {
                    // GET
                    let value_witness = spice_witnesses.rv_final_start + addr;
                    let rt_witness = spice_witnesses.rt_final_start + addr;
                    all_mem_op_index_and_rt.push((block.operations.len(), rt_witness));
                    let factor = r1cs.add_mem_op_multiset_factor(
                        sz_challenge,
                        rs_challenge,
                        rs_challenge_sqrd,
                        (FieldElement::from(addr), r1cs.witness_one()),
                        value_witness,
                        (FieldElement::one(), rt_witness),
                    );
                    println!("RS factor [{}]: ({}, [{}], [{}])", factor, addr, value_witness, rt_witness);
                    rs_hash = r1cs.add_product(rs_hash, factor);
                });

                // Add the final constraint to enforce that the hashes are equal
                r1cs.matrices.add_constraint(
                    &[(FieldElement::one(), r1cs.witness_one())],
                    &[(FieldElement::one(), rs_hash)],
                    &[(FieldElement::one(), ws_hash)],
                );

                // TODO add the two range checks using all_mem_op_index_and_rt

                // Question: do we need to include the final timestamps?
                let read_timestamps = spice_witnesses.memory_operations.iter().map(|op| {
                    match op {
                        SpiceMemoryOperation::Load(_, _, rt_witness) => *rt_witness,
                        SpiceMemoryOperation::Store(_, _, _, rt_witness) => *rt_witness,
                    }
                }).collect::<Vec<_>>();

                // We want to establish that mem_op_index = max(mem_op_index, retrieved_timer)
                // We do this via two separate range checks:
                //  1. retrieved_timer in 0..2^K
                //  2. (mem_op_index - retrieved_time) in 0..2^K
                // where K is minimal such that 2^K >= block.operations.len().
                // TODO triple check the following:
                // This is sound so long as 2^K is less than the characteristic of the field.
                // (Note that range checks are being implemented only for powers of two).
                
                // When merging in Vishruti's code:
                // (in order for this to work, the compilation of the range checks must come after the compilation of the memory checking).
            }
        });

        // ------------------------ Range checks ------------------------

        // Do a pass through everything that needs to be range checked,
        // decomposing each value into digits that are at most [NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP]
        // and creating a map `atomic_range_blocks` of each `num_bits` from 1 to the
        // NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP (inclusive) to the vec of witness indices that are
        // constrained to that range.

        // Mapping the log of the range size k to the vector of witness indices that
        // are to be constrained within the range [0..2^k].
        // The witnesses of all small range op codes are added to this map, along with witnesses of
        // digits for digital decompositions of larger range checks.
        let mut atomic_range_blocks: Vec<Vec<Vec<usize>>> = vec![vec![vec![]]; NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP as usize + 1];

        range_blocks
            .into_iter()
            .for_each(|(num_bits, values_to_lookup)| {
                if num_bits > NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP {
                    let num_big_digits = num_bits / NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP;
                    let logbase_of_remainder_digit = num_bits % NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP;
                    let mut log_bases = vec![NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP as usize; num_big_digits as usize];
                    log_bases.push(logbase_of_remainder_digit as usize);
                    let num_values = values_to_lookup.len();
                    let dd_struct = DigitalDecompositionWitnesses::new(
                            r1cs.num_witnesses(),
                            log_bases.clone(),
                            values_to_lookup,
                    );
                    r1cs.add_witness_builder(WitnessBuilder::DigitalDecomposition(dd_struct.clone()));
                    // Add the constraints for the digital recomposition (TODO consider putting this in the witness builder)
                    let digit_multipliers = DigitalDecompositionWitnesses::get_digit_multipliers(&log_bases);
                    dd_struct.values.iter().enumerate().for_each(|(i, value)| {
                        let mut recomp_summands = vec![];
                        dd_struct.digit_start_indices.iter().zip(digit_multipliers.iter()).for_each(|(digit_start_index, digit_multiplier)| {
                            let digit_witness = *digit_start_index + i;
                            recomp_summands.push((FieldElement::from(*digit_multiplier), digit_witness));
                        });
                        r1cs.matrices.add_constraint(
                            &[(FieldElement::one(), r1cs.witness_one())],
                            &[(FieldElement::one(), *value)],
                            &recomp_summands,
                        );
                    });

                    // Add the digit witness indices to the atomic range blocks
                    dd_struct.log_bases.iter().zip(dd_struct.digit_start_indices.iter()).for_each(|(log_base, digit_start_index)| {
                        atomic_range_blocks[*log_base].push((0..num_values).map(|i| *digit_start_index + i).collect());
                    });
                } else {
                    atomic_range_blocks[num_bits as usize].push(values_to_lookup);
                }
            });

        // TODO implement the range checks for each of the atomic ranges

        r1cs
    }

    // Add and return a new witness representing `sz_challenge - hash`, where `hash` is the hash value of a memory operation, adding an R1CS constraint enforcing this.
    // (This is a helper method for the offline memory checking.)
    // TODO combine this with Vishruti's add_indexed_lookup_factor (generic over the length of the combination).
    fn add_mem_op_multiset_factor(
        &mut self,
        sz_challenge: usize,
        rs_challenge: usize,
        rs_challenge_sqrd: usize,
        (addr, addr_witness): (FieldElement, usize),
        value_witness: usize,
        (timer, timer_witness): (FieldElement, usize),
    ) -> usize {
        let factor = self.add_witness_builder(WitnessBuilder::MemOpMultisetFactor(
            self.num_witnesses(),
            sz_challenge,
            rs_challenge,
            (addr, addr_witness),
            value_witness,
            (timer, timer_witness),
        ));
        let intermediate = self.add_product(rs_challenge_sqrd, timer_witness);
        self.matrices.add_constraint(
            &[(FieldElement::one(), rs_challenge)],
            &[(FieldElement::one().neg(), value_witness)],
            &[
                (FieldElement::one(), factor),
                (FieldElement::one().neg(), sz_challenge),
                (timer, intermediate),
                (addr, addr_witness),
            ],
        );
        factor
    }

    // Return the R1CS witness index corresponding to the AcirWitness provided, creating a new R1CS
    // witness (and builder) if required.
    fn fetch_r1cs_witness_index(&mut self, acir_witness_index: AcirWitness) -> usize {
        self.acir_to_r1cs_witness_map
            .get(&acir_witness_index.as_usize())
            .copied()
            .unwrap_or_else(|| {
                self.add_witness_builder(WitnessBuilder::Acir(self.num_witnesses(), acir_witness_index.as_usize()))
            })
    }

    // Add a new witness representing the product of two existing witnesses, and add an R1CS constraint enforcing this.
    fn add_product(&mut self, operand_a: usize, operand_b: usize) -> usize {
        let product = self.add_witness_builder(WitnessBuilder::Product(self.num_witnesses(), operand_a, operand_b));
        self.matrices.add_constraint(
            &[(FieldElement::one(), operand_a)],
            &[(FieldElement::one(), operand_b)],
            &[(FieldElement::one(), product)],
        );
        product
    }

    // Add a new witness representing the sum of existing witnesses, and add an R1CS constraint enforcing this.
    fn add_sum(&mut self, summands: Vec<usize>) -> usize {
        let sum = self.add_witness_builder(WitnessBuilder::Sum(self.num_witnesses(), summands.clone()));
        let az = summands
            .iter()
            .map(|&s| (FieldElement::one(), s))
            .collect::<Vec<_>>();
        self.matrices.add_constraint(
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
            self.num_witnesses(),
            sz_challenge,
            (index, index_witness),
            rs_challenge,
            value,
        );
        let denominator = self.add_witness_builder(wb);
        self.matrices.add_constraint(
            &[(FieldElement::one(), rs_challenge)],
            &[(FieldElement::one(), value)],
            &[
                (FieldElement::one().neg(), denominator),
                (FieldElement::one(), sz_challenge),
                (index.neg(), index_witness),
            ],
        );
        let inverse = self.add_witness_builder(WitnessBuilder::Inverse(self.num_witnesses(), denominator));
        self.matrices.add_constraint(
            &[(FieldElement::one(), denominator)],
            &[(FieldElement::one(), inverse)],
            &[(FieldElement::one(), self.witness_one())],
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

#[derive(Debug, Clone)]
/// Used for tracking operations on a memory block.
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
            MemoryOperation::Load(_, _) => true,
            MemoryOperation::Store(_, _) => false,
        })
    }
}

#[derive(Debug, Clone)]
pub enum MemoryOperation {
    /// (R1CS witness index of address, R1CS witness index of value read)
    Load(usize, usize),
    /// (R1CS witness index of address, R1CS witness index of value to write)
    Store(usize, usize),
}

// FIXME where does this belong?
#[derive(Debug, Clone)]
pub(crate) struct SpiceWitnesses {
    pub memory_length: usize,
    pub initial_values_start: usize,
    pub memory_operations: Vec<SpiceMemoryOperation>,
    pub rv_final_start: usize,
    pub rt_final_start: usize,
    /// The index of the first witness written to by the SpiceWitnesses struct
    pub first_witness_idx: usize,
    /// The number of witnesses written to by the SpiceWitnesses struct
    pub num_witnesses: usize
}

impl SpiceWitnesses {
    fn new(
        next_witness_idx: usize,
        memory_length: usize,
        initial_values_start: usize, // already allocated
        memory_operations: Vec<MemoryOperation>,
    ) -> Self {
        let start_witness_idx = next_witness_idx;
        let mut next_witness_idx = start_witness_idx;
        let spice_memory_operations = memory_operations
            .into_iter()
            .map(|op| match op {
                MemoryOperation::Load(addr, value) => {
                    let op = SpiceMemoryOperation::Load(addr, value, next_witness_idx);
                    next_witness_idx += 1;
                    op
                },
                MemoryOperation::Store(addr, new_value) => {
                    let old_value = next_witness_idx;
                    next_witness_idx += 1;
                    let read_timestamp = next_witness_idx;
                    next_witness_idx += 1;
                    SpiceMemoryOperation::Store(addr, old_value, new_value, read_timestamp)
                }
            })
            .collect();
        let rv_final_start = next_witness_idx;
        next_witness_idx += memory_length;
        let rt_final_start = next_witness_idx;
        next_witness_idx += memory_length;
        let num_witnesses = next_witness_idx - start_witness_idx;

        Self {
            memory_length,
            initial_values_start,
            memory_operations: spice_memory_operations,
            rv_final_start,
            rt_final_start,
            first_witness_idx: start_witness_idx,
            num_witnesses
        }
    }
}

/// Like MemoryOperation, but with the indices of the additional witnesses needed by Spice.
#[derive(Debug, Clone)]
pub(crate) enum SpiceMemoryOperation {
    /// (R1CS witness index of address, R1CS witness index of value read)
    Load(usize, usize, usize),
    /// (R1CS witness index of address, R1CS index of old value, R1CS witness index of value to write, R1CS witness index of the read timestamp)
    Store(usize, usize, usize, usize),
}

#[derive(Debug, Clone)]
pub(crate) struct DigitalDecompositionWitnesses {
    /// The log base of each digit (in big-endian order)
    pub log_bases: Vec<usize>,
    /// Witness indices of the values to be decomposed
    pub values: Vec<usize>,
    /// Witness indices for the digits of the decomposition of each value (indexed by digital place).
    pub digit_start_indices: Vec<usize>,
    /// The index of the first witness written to
    pub first_witness_idx: usize,
    /// The number of witnesses written to
    pub num_witnesses: usize,
}

impl DigitalDecompositionWitnesses {
    pub fn new(next_witness_idx: usize, log_bases: Vec<usize>, values: Vec<usize>) -> Self {
        let num_values = values.len();
        let digital_decomp_length = log_bases.len();
        let digit_start_indices = (0..digital_decomp_length)
            .map(|i| next_witness_idx + i * num_values).collect::<Vec<_>>();
        Self {
            log_bases,
            values,
            digit_start_indices,
            first_witness_idx: next_witness_idx,
            num_witnesses: digital_decomp_length * num_values,
        }
    }

    /// Returns the digit multipliers for the digital recomposition, in the same order as self.log_bases.
    pub fn get_digit_multipliers(log_bases: &Vec<usize>) -> Vec<FieldElement> {
        // Calculate the partial sums of log bases (in reverse)
        let log_base_partial_sums_le = log_bases.iter().rev().scan(0, |acc, &x| {
            let return_value = *acc;
            *acc += x;
            Some(return_value)
        }).collect::<Vec<_>>();
        // TODO careful with the u128 here!  what is the maximum range check size?
        log_base_partial_sums_le.iter().rev().map(|x| FieldElement::from(1u128 << *x)).collect::<Vec<_>>()
    }
}

