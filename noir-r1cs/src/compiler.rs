use {
    crate::{
        r1cs_matrices::R1CSMatrices,
        solver::{R1CSSolver, WitnessBuilder},
        utils::field_utils::pow_field,
        utils::helpers::compute_compact_and_logup_repr,
    },
    acir::{
        circuit::{
            opcodes::{BlackBoxFuncCall, BlockType, ConstantOrWitnessEnum},
            Circuit, Opcode,
        },
        native_types::{Expression, Witness as AcirWitness},
        AcirField, FieldElement,
    },
    std::{
        collections::{hash_map::Entry, BTreeMap, HashMap},
        fmt::{Debug, Formatter},
        ops::{AddAssign, Neg},
        vec,
    },
};

const NUM_WITNESS_THRESHOLD_FOR_LOOKUP_TABLE: usize = 5;
pub const NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP: u32 = 8;

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
        let mut memory_blocks: BTreeMap<usize, ReadOnlyMemoryBlock> = BTreeMap::new();
        // Range blocks to map the number of bits threshold to the vector of values that
        // are meant to be constrained within that range.
        let mut range_blocks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        // Same as above, but for number of bits that are above the [NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP].
        // Separated so that we can separate the witness values into digits to do smaller range checks.
        let mut range_blocks_decomp_sorted: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        // Keeps track of a mapping between R1CS witness indices to the list of
        // R1CS witness indices corresponding to their decomp, where the tuple
        // can be seen as (num_bits, digit_idx) such that `digit_idx` is the R1CS
        // index of the digit witness which should be multiplied by 2^{num_bits}
        // in the final recomp.
        let mut value_to_decomp_map: BTreeMap<usize, Vec<(u32, usize)>> = BTreeMap::new();
        // We assume for now that all (lhs, rhs, output, combined_table_val) tuples are `u32`s and
        // store their R1CS witness indices. We keep track of just the `combined_table_val` indices here
        // to understand which witnesses to add lookup constraints to later in order to enforce the AND and XOR opcodes.
        // Note that `combined_table_val` refers to the "packed" version of (lhs, rhs, output)
        // which is to be looked up in the LogUp table.
        let mut and_opcode_packed_elems_r1cs_indices: Vec<usize> = Vec::new();
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

                    // Create a new (as yet unconstrained) witness `result_of_read` for the result of the read; it will be constrained by the lookup for the memory block at the end.
                    // Use a MemoryRead witness builder so that the solver can determine its value and also count memory accesses to each address.

                    // "In read operations, [op.value] corresponds to the witness index at which the value from memory will be written." (from the Noir codebase)
                    // At R1CS solving time, only need to map over the value of the corresponding ACIR witness, whose value is already determined by the ACIR solver.
                    let result_of_read_acir_witness = op.value.to_witness().unwrap().0 as usize;

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
                    let result_of_read = r1cs.add_witness(WitnessBuilder::MemoryRead(
                        block_id,
                        addr,
                        result_of_read_acir_witness,
                    ));
                    block.read_operations.push((addr, result_of_read));
                }

                // These are calls to built-in functions, for this we need to create.
                Opcode::BlackBoxFuncCall(black_box_func_call) => match black_box_func_call {
                    BlackBoxFuncCall::RANGE {
                        input: function_input,
                    } => {
                        let input = function_input.input();
                        let num_bits = function_input.num_bits();
                        let input_wb = match input {
                            ConstantOrWitnessEnum::Constant(_) => {
                                panic!("We should never be range-checking a constant value, as this should already be done by the noir-ACIR compiler");
                            }
                            ConstantOrWitnessEnum::Witness(witness) => {
                                WitnessBuilder::Acir(witness.as_usize())
                            }
                        };
                        let input_witness = r1cs.add_witness(input_wb);
                        // Add the entry into the range blocks.
                        range_blocks
                            .entry(num_bits)
                            .or_default()
                            .push(input_witness);
                    }
                    BlackBoxFuncCall::AND { lhs, rhs, output } => {
                        let lhs_input = lhs.input();
                        let rhs_input = rhs.input();
                        let (lhs_input_wb, rhs_input_wb) = match (lhs_input, rhs_input) {
                            (
                                ConstantOrWitnessEnum::Witness(lhs_input_witness),
                                ConstantOrWitnessEnum::Witness(rhs_input_witness),
                            ) => (
                                WitnessBuilder::Acir(lhs_input_witness.as_usize()),
                                WitnessBuilder::Acir(rhs_input_witness.as_usize()),
                            ),
                            _ => panic!(
                                "Currently we do not support calling `AND` on non-witness values, although this can be easily remedied."
                            ),
                        };

                        // --- Add all the needed witnesses to the R1CS instance... ---
                        let lhs_r1cs_witness_idx = r1cs.add_witness(lhs_input_wb);
                        let rhs_r1cs_witness_idx = r1cs.add_witness(rhs_input_wb);
                        let output_r1cs_witness_idx =
                            r1cs.add_witness(WitnessBuilder::Acir(output.as_usize()));

                        // --- ...including digits and the "packed" version of digits to be looked up ---
                        // Four u8s in a u32. digit_0 + digit_1 * 2^8 + digit_2 * 2^{16} + digit_3 * 2^{24} is the recomp.
                        let lhs_u8_digit_decomp_r1cs_indices: Vec<usize> = (0..3)
                            .map(|digit_idx| {
                                r1cs.add_witness(WitnessBuilder::DigitDecomp(
                                    8,
                                    lhs_r1cs_witness_idx,
                                    digit_idx * 8,
                                ))
                            })
                            .collect();
                        let rhs_u8_digit_decomp_r1cs_indices: Vec<usize> = (0..3)
                            .map(|digit_idx| {
                                r1cs.add_witness(WitnessBuilder::DigitDecomp(
                                    8,
                                    rhs_r1cs_witness_idx,
                                    digit_idx * 8,
                                ))
                            })
                            .collect();
                        let output_u8_digit_decomp_r1cs_indices: Vec<usize> = (0..3)
                            .map(|digit_idx| {
                                r1cs.add_witness(WitnessBuilder::DigitDecomp(
                                    8,
                                    output_r1cs_witness_idx,
                                    digit_idx * 8,
                                ))
                            })
                            .collect();
                        // --- We need to add recomp constraints for LHS, RHS, and output ---
                        value_to_decomp_map.insert(
                            lhs_r1cs_witness_idx,
                            lhs_u8_digit_decomp_r1cs_indices
                                .iter()
                                .map(|x| (8, *x))
                                .collect(),
                        );
                        value_to_decomp_map.insert(
                            rhs_r1cs_witness_idx,
                            rhs_u8_digit_decomp_r1cs_indices
                                .iter()
                                .map(|x| (8, *x))
                                .collect(),
                        );
                        value_to_decomp_map.insert(
                            output_r1cs_witness_idx,
                            output_u8_digit_decomp_r1cs_indices
                                .iter()
                                .map(|x| (8, *x))
                                .collect(),
                        );

                        // --- These are the actual things which need to be looked up ---
                        let mut packed_table_val_r1cs_indices = (0..3)
                            .map(|digit_idx| {
                                r1cs.add_witness(WitnessBuilder::LookupTablePacking(
                                    lhs_u8_digit_decomp_r1cs_indices[digit_idx],
                                    rhs_u8_digit_decomp_r1cs_indices[digit_idx],
                                    output_u8_digit_decomp_r1cs_indices[digit_idx],
                                ))
                            })
                            .collect();
                        and_opcode_packed_elems_r1cs_indices
                            .append(&mut packed_table_val_r1cs_indices);
                    }
                    _ => {
                        println!("Other black box function: {:?}", black_box_func_call);
                    }
                },
            }
        }

        // ------------------------ AND opcode ------------------------
        // Note: We assume that all inputs are `u32`s, and that we have a single
        // table of size 2^{16} which is (u8 & u8 -> u8), represented by a
        // "packed" u32 which is (lhs + rhs << 8 + output << 16).

        // --- Okay so let's add the table which contains all (u8 & u8 -> u8) values ---
        // TODO: Can we combine all of these SZ challenges?
        let add_opcode_sz_challenge_r1cs_index = r1cs.add_witness(WitnessBuilder::Challenge);

        // Canonically, we will say that the LHS for logup is the "thing to be
        // looked up" side and the RHS for logup is the "lookup table" side.
        // This first bit of code computes the "lookup table" side.
        let all_compact_and_reprs: Vec<u32> = (0..255)
            .flat_map(|lhs| (0..255).map(move |rhs| compute_compact_and_logup_repr(lhs, rhs)))
            .collect();
        let and_logup_frac_rhs_r1cs_indices = all_compact_and_reprs
            .iter()
            .map(|compact_and_repr| {
                let logup_table_frac_inv_idx = r1cs.add_lookup_factor(
                    add_opcode_sz_challenge_r1cs_index,
                    FieldElement::from(*compact_and_repr),
                    r1cs.solver.witness_one(),
                );
                let multiplicity_witness_r1cs_idx = r1cs.add_witness(
                    WitnessBuilder::AndOpcodeTupleMultiplicity(*compact_and_repr),
                );
                r1cs.add_product(logup_table_frac_inv_idx, multiplicity_witness_r1cs_idx)
            })
            .collect();

        // Next, we compute all of the (1 / (1 - x_i)) values, i.e. the "things
        // to be looked up" side.
        let and_logup_frac_lhs_r1cs_indices = and_opcode_packed_elems_r1cs_indices
            .iter()
            .map(|packed_val_idx| {
                r1cs.add_lookup_factor(
                    add_opcode_sz_challenge_r1cs_index,
                    FieldElement::one(),
                    *packed_val_idx,
                )
            })
            .collect();

        // Compute the sums over the LHS and RHS and check that they are equal.
        let sum_for_table = r1cs.add_sum(and_logup_frac_rhs_r1cs_indices);
        let sum_for_witness = r1cs.add_sum(and_logup_frac_lhs_r1cs_indices);
        r1cs.matrices.add_constraint(
            &[
                (FieldElement::one(), sum_for_table),
                (FieldElement::one().neg(), sum_for_witness),
            ],
            &[(FieldElement::one(), r1cs.solver.witness_one())],
            &[(FieldElement::zero(), r1cs.solver.witness_one())],
        );

        // ------------------------ Memory checking ------------------------

        // For each memory block, use a lookup to enforce that the reads are correct.
        memory_blocks.iter().for_each(|(block_id, block)| {
            // Add witness entries for memory access counts, using the WitnessBuilder::MemoryAccessCount
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

        // Keeps track of the witness_index: Vec<(digit_num_bits, witness_index_of_digit)> of the
        // mixed-digit decomposition of the value stored at witness_index.
        // ------------------------ Range checks ------------------------

        // Do a forward pass through everything that needs to be range checked,
        // decomposing each value into digits that are at most [NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP]
        // and creating a map `range_blocks_decomp_sorted` of each `num_bits` from 1 to the
        // NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP (inclusive) to the vec of values that are
        // to be looked up in that range.
        range_blocks
            .iter()
            .for_each(|(num_bits, values_to_lookup)| {
                if *num_bits > NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP {
                    for value in values_to_lookup {
                        let mut smaller_num_bits = num_bits.clone();
                        let mut sum_of_bits_so_far = 0;
                        // Keep creating digits of the maximum size until we are left
                        // with the remainder.
                        while smaller_num_bits > NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP {
                            let digit_wb = WitnessBuilder::DigitDecomp(
                                NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP,
                                *value,
                                sum_of_bits_so_far,
                            );
                            let digit_wb_idx = r1cs.add_witness(digit_wb);
                            value_to_decomp_map
                                .entry(*value)
                                .or_default()
                                .push((NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP, digit_wb_idx));
                            range_blocks_decomp_sorted
                                .entry(NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP)
                                .or_default()
                                .push(digit_wb_idx);
                            sum_of_bits_so_far += NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP;
                            smaller_num_bits -= NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP;
                        }
                        let digit_wb = WitnessBuilder::DigitDecomp(
                            smaller_num_bits,
                            *value,
                            sum_of_bits_so_far,
                        );
                        let digit_wb_idx = r1cs.add_witness(digit_wb);
                        range_blocks_decomp_sorted
                            .entry(smaller_num_bits)
                            .or_default()
                            .push(digit_wb_idx);
                        value_to_decomp_map
                            .entry(*value)
                            .or_default()
                            .push((smaller_num_bits, digit_wb_idx));
                    }
                } else {
                    range_blocks_decomp_sorted.insert(*num_bits, values_to_lookup.clone());
                }
            });

        // Do a pass through all the values to its digital decompositions to add
        // a constraint to check for the correct recomposition.
        value_to_decomp_map
            .iter()
            .for_each(|(value, le_decomposition)| {
                let digits_constraint_a: Vec<(FieldElement, usize)> = le_decomposition
                    .iter()
                    .enumerate()
                    .map(|(index, (recomp_coeff, digit))| {
                        let recomp_coeff_scaled = pow_field(
                            FieldElement::from((1 << *recomp_coeff) as u64),
                            index as u32,
                        );
                        (recomp_coeff_scaled, *digit)
                    })
                    .collect();
                r1cs.matrices.add_constraint(
                    &digits_constraint_a,
                    &[(FieldElement::one(), r1cs.solver.witness_one())],
                    &[(FieldElement::one(), *value)],
                );
            });

        // Do a pass through all of the range checks necessary, and if it meets
        // the threshold to do a lookup, count the multiplicity for it. We need
        // all of these to be counted before actually doing the lookup.
        range_blocks_decomp_sorted
            .iter()
            .for_each(|(num_bits, values_to_lookup)| {
                if values_to_lookup.len() > NUM_WITNESS_THRESHOLD_FOR_LOOKUP_TABLE {
                    values_to_lookup.iter().for_each(|value| {
                        r1cs.add_witness(WitnessBuilder::AddMultiplicityCount(*num_bits, *value));
                    })
                }
            });

        // Do another pass through all the range checks necessary, creating
        // a logup check for those that meet the threshold (ie we are looking up
        // more than NUM_WITNESS_THRESHOLD_FOR_LOOKUP_TABLE) values, and
        // doing the naive range check otherwise.
        range_blocks_decomp_sorted
            .iter()
            .for_each(|(num_bits, values_to_lookup)| {
                if values_to_lookup.len() > NUM_WITNESS_THRESHOLD_FOR_LOOKUP_TABLE {
                    r1cs.add_logup_summations(*num_bits, &values_to_lookup);
                } else {
                    values_to_lookup.iter().for_each(|value| {
                        r1cs.add_naive_range_check(*num_bits, *value);
                    })
                }
            });
        r1cs
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

    /// Add a new witness to the R1CS instance, returning its index.
    /// If the witness builder implicitly maps an ACIR witness to an R1CS witness, then record this.
    fn add_witness(&mut self, witness_builder: WitnessBuilder) -> usize {
        if let WitnessBuilder::AddMultiplicityCount(_, _) = witness_builder {
            self.solver.add_witness_builder(witness_builder);
            self.matrices.num_witnesses()
        } else {
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

    /// Add R1CS constraints to the instance to enforce that the provided ACIR expression is zero.
    fn add_acir_assert_zero(&mut self, expr: &Expression<FieldElement>) {
        // Create individual constraints for all the multiplication terms and collect
        // their outputs
        let mut linear = vec![];
        let mut a = vec![];
        let mut b = vec![];

        if expr.mul_terms.len() >= 1 {
            // Process all except the last multiplication term
            // --- Okay so `linear` is a vector consisting of all the (coeff, product witness R1CS index)s ---
            // --- And the idea is that all (linearized) mul terms except the very last one are negative because they're on the C side ---
            // --- as well as all linear terms, as well as the constant ---
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
        let wb = WitnessBuilder::IndexedLogUpDenominator(
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

    /// Helper function which computes all the terms of the summation for
    /// each side (LHS and RHS) of the log-derivative multiset check.
    ///
    /// Checks that both sums (LHS and RHS) are equal at the end.
    fn add_logup_summations(&mut self, num_bits: u32, values_to_lookup: &[usize]) {
        // Sample the Schwartz-Zippel challenge for the log derivative
        // multiset check.
        let sz_challenge = self.add_witness(WitnessBuilder::Challenge);
        // Compute all the terms in the summation for multiplicity/(X - table_value)
        // for each table value.
        let table_summands: Vec<usize> = (0..(1 << num_bits))
            .map(|table_value| {
                let table_denom = self.add_lookup_factor(
                    sz_challenge,
                    FieldElement::from(table_value),
                    self.solver.witness_one(),
                );
                let multiplicity_witness =
                    self.add_witness(WitnessBuilder::DigitMultiplicity(table_value, num_bits));
                let denom_times_multiplicity =
                    self.add_witness(WitnessBuilder::Product(multiplicity_witness, table_denom));
                self.add_product(table_denom, multiplicity_witness);
                denom_times_multiplicity
            })
            .collect();
        let sum_for_table = self.add_sum(table_summands);
        // Compute all the terms in the summation for 1/(X - witness_value) for each
        // witness value.
        let witness_summands: Vec<usize> = values_to_lookup
            .iter()
            .map(|value| self.add_lookup_factor(sz_challenge, FieldElement::one(), *value))
            .collect();
        let sum_for_witness = self.add_sum(witness_summands);

        // Check that these two sums are equal.
        self.matrices.add_constraint(
            &[
                (FieldElement::one(), sum_for_table),
                (FieldElement::one().neg(), sum_for_witness),
            ],
            &[(FieldElement::one(), self.solver.witness_one())],
            &[(FieldElement::zero(), self.solver.witness_one())],
        );
    }

    /// Helper function that computes the LogUp denominator either for
    /// the table values: (X - t_j), or for the witness values:
    /// (X - w_i). Computes the inverse and also checks that this is
    /// the appropriate inverse.
    fn add_lookup_factor(
        &mut self,
        sz_challenge: usize,
        value_coeff: FieldElement,
        value_witness: usize,
    ) -> usize {
        let denom_wb = WitnessBuilder::LogUpDenominator(sz_challenge, (value_coeff, value_witness));
        let denominator = self.add_witness(denom_wb);
        self.matrices.add_constraint(
            &[
                (FieldElement::one(), sz_challenge),
                (FieldElement::one().neg() * value_coeff, value_witness),
            ],
            &[(FieldElement::one(), self.solver.witness_one())],
            &[(FieldElement::one(), denominator)],
        );
        let inverse = self.add_witness(WitnessBuilder::Inverse(denominator));
        self.matrices.add_constraint(
            &[(FieldElement::one(), denominator)],
            &[(FieldElement::one(), inverse)],
            &[(FieldElement::one(), self.solver.witness_one())],
        );
        inverse
    }

    /// A naive range check helper function, computing the
    /// $\prod_{i = 0}^{range}(a - i) = 0$ to check whether a witness found at
    /// `index_witness`, which is $a$, is in the $range$, which is `num_bits`.
    fn add_naive_range_check(&mut self, num_bits: u32, index_witness: usize) {
        let mut current_product_witness = index_witness;
        (1..num_bits).for_each(|index| {
            let next_product_witness = self.add_witness(WitnessBuilder::ProductLinearOperation(
                (
                    current_product_witness,
                    FieldElement::one(),
                    FieldElement::zero(),
                ),
                (
                    current_product_witness,
                    FieldElement::one(),
                    FieldElement::from(index).neg(),
                ),
            ));
            self.matrices.add_constraint(
                &[(FieldElement::one(), current_product_witness)],
                &[
                    (FieldElement::one(), current_product_witness),
                    (FieldElement::from(index).neg(), self.solver.witness_one()),
                ],
                &[(FieldElement::one(), next_product_witness)],
            );
            current_product_witness = next_product_witness;
        });

        self.matrices.add_constraint(
            &[(FieldElement::one(), current_product_witness)],
            &[
                (FieldElement::one(), current_product_witness),
                (
                    FieldElement::from(num_bits).neg(),
                    self.solver.witness_one(),
                ),
            ],
            &[(FieldElement::zero(), self.solver.witness_one())],
        );
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
