use {
    crate::{
        binops::{add_binop, BinOp},
        memory::{MemoryBlock, MemoryOperation},
        r1cs_solver::{ConstantTerm, SumTerm, WitnessBuilder},
        ram::add_ram_checking,
        range_check::add_range_checks,
        rom::add_rom_checking,
        serde_ark,
        utils::noir_to_native,
        FieldElement, NoirElement, R1CS,
    },
    acir::{
        circuit::{
            opcodes::{
                BlackBoxFuncCall, BlockType, ConstantOrWitnessEnum as ConstantOrACIRWitness,
            },
            Circuit, Opcode,
        },
        native_types::{Expression, Witness as NoirWitness},
    },
    anyhow::{bail, Result},
    ark_std::One,
    serde::{Deserialize, Serialize},
    std::{collections::BTreeMap, num::NonZeroU32, ops::Neg},
};
/// The index of the constant 1 witness in the R1CS instance
pub const WITNESS_ONE_IDX: usize = 0;

/// Compiles an ACIR circuit into an [R1CS] instance, comprising of the A, B,
/// and C R1CS matrices, along with the witness vector.
pub(crate) struct NoirToR1CSCompiler {
    pub(crate) r1cs: R1CS,

    /// Indicates how to solve for each R1CS witness
    pub witness_builders: Vec<WitnessBuilder>,

    /// Maps indices of ACIR witnesses to indices of R1CS witnesses
    acir_to_r1cs_witness_map: BTreeMap<usize, usize>,

    /// The ACIR witness indices of the initial values of the memory blocks
    pub initial_memories: BTreeMap<usize, Vec<usize>>,
}

/// Compile a Noir circuit to a R1CS relation, returning the R1CS and a map from
/// Noir witness indices to R1CS witness indices.
pub fn noir_to_r1cs(
    circuit: &Circuit<NoirElement>,
) -> Result<(R1CS, Vec<Option<NonZeroU32>>, Vec<WitnessBuilder>)> {
    let mut compiler = NoirToR1CSCompiler::new();
    compiler.add_circuit(circuit)?;
    Ok(compiler.finalize())
}

impl NoirToR1CSCompiler {
    fn new() -> Self {
        let mut r1cs = R1CS::new();
        // Grow the matrices to account for the constant one witness.
        r1cs.add_witnesses(1);
        // We want to get the index of the witness_one index, which should be
        // the current number of witnesses minus one, meaning it is the only
        // witness that has been added so far.
        let witness_one_idx = r1cs.num_witnesses() - 1;
        assert_eq!(witness_one_idx, 0, "R1CS requires first witness to be 1");
        Self {
            r1cs,
            witness_builders: vec![WitnessBuilder::Constant(ConstantTerm(
                witness_one_idx,
                FieldElement::one(),
            ))],
            acir_to_r1cs_witness_map: BTreeMap::new(),
            initial_memories: BTreeMap::new(),
        }
    }

    /// Returns the R1CS and the witness map
    pub fn finalize(self) -> (R1CS, Vec<Option<NonZeroU32>>, Vec<WitnessBuilder>) {
        // Convert witness map to vector
        let len = self
            .acir_to_r1cs_witness_map
            .keys()
            .copied()
            .max()
            .map_or_else(|| 0, |i| i + 1);
        let mut map = vec![None; len];
        for (acir_witness_idx, r1cs_witness_idx) in self.acir_to_r1cs_witness_map {
            map[acir_witness_idx] =
                Some(NonZeroU32::new(r1cs_witness_idx as u32).expect("Index zero is reserved"));
        }
        (self.r1cs, map, self.witness_builders)
    }

    /// Index of the constant one witness
    pub const fn witness_one(&self) -> usize {
        0
    }

    /// The number of witnesses in the R1CS instance. This includes the constant
    /// one witness.
    pub fn num_witnesses(&self) -> usize {
        self.r1cs.num_witnesses()
    }

    // Add a new witness to the R1CS instance, returning its index. If the
    // witness builder implicitly maps an ACIR witness to an R1CS witness, then
    // record this.
    pub fn add_witness_builder(&mut self, witness_builder: WitnessBuilder) -> usize {
        let start_idx = self.num_witnesses();
        self.r1cs.add_witnesses(witness_builder.num_witnesses());
        // Add the witness to the mapping if it is an ACIR witness
        if let WitnessBuilder::Acir(r1cs_witness_idx, acir_witness) = &witness_builder {
            self.acir_to_r1cs_witness_map
                .insert(*acir_witness, *r1cs_witness_idx);
        }
        self.witness_builders.push(witness_builder);
        start_idx
    }

    // Return the R1CS witness index corresponding to the AcirWitness provided,
    // creating a new R1CS witness (and builder) if required.
    pub fn fetch_r1cs_witness_index(&mut self, acir_witness_index: NoirWitness) -> usize {
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

    // Convert a ConstantOrACIRWitness into a ConstantOrR1CSWitness, creating a new
    // R1CS witness (and builder) if required.
    fn fetch_constant_or_r1cs_witness(
        &mut self,
        constant_or_witness: ConstantOrACIRWitness<NoirElement>,
    ) -> ConstantOrR1CSWitness {
        match constant_or_witness {
            ConstantOrACIRWitness::Constant(c) => {
                ConstantOrR1CSWitness::Constant(noir_to_native(c))
            }
            ConstantOrACIRWitness::Witness(w) => {
                let r1cs_witness = self.fetch_r1cs_witness_index(w);
                ConstantOrR1CSWitness::Witness(r1cs_witness)
            }
        }
    }

    /// Add a new witness representing the product of two existing witnesses,
    /// and add an R1CS constraint enforcing this.
    pub(crate) fn add_product(&mut self, operand_a: usize, operand_b: usize) -> usize {
        let product = self.add_witness_builder(WitnessBuilder::Product(
            self.num_witnesses(),
            operand_a,
            operand_b,
        ));
        self.r1cs.add_constraint(
            &[(FieldElement::one(), operand_a)],
            &[(FieldElement::one(), operand_b)],
            &[(FieldElement::one(), product)],
        );
        product
    }

    /// Add a new witness representing the sum of existing witnesses, and add an
    /// R1CS constraint enforcing this. Vector consists of (optional
    /// coefficient, witness index) tuples, one for each summand. The
    /// coefficient is optional, and if it is None, the coefficient is 1.
    pub(crate) fn add_sum(&mut self, summands: Vec<SumTerm>) -> usize {
        let sum =
            self.add_witness_builder(WitnessBuilder::Sum(self.num_witnesses(), summands.clone()));
        let az = summands
            .iter()
            .map(|SumTerm(coeff, witness_idx)| (coeff.unwrap_or(FieldElement::one()), *witness_idx))
            .collect::<Vec<_>>();
        self.r1cs
            .add_constraint(&az, &[(FieldElement::one(), self.witness_one())], &[(
                FieldElement::one(),
                sum,
            )]);
        sum
    }

    /// Add an ACIR assert zero constraint.
    pub fn add_acir_assert_zero(&mut self, expr: &Expression<NoirElement>) {
        // Create individual constraints for all the multiplication terms and collect
        // their outputs
        let mut linear: Vec<(FieldElement, usize)> = vec![];
        let mut a: Vec<(FieldElement, usize)> = vec![];
        let mut b: Vec<(FieldElement, usize)> = vec![];

        if !expr.mul_terms.is_empty() {
            // Process all except the last multiplication term
            linear = expr
                .mul_terms
                .iter()
                .take(expr.mul_terms.len() - 1)
                .map(|(coeff, acir_witness_a, acir_witness_b)| {
                    let a = self.fetch_r1cs_witness_index(*acir_witness_a);
                    let b = self.fetch_r1cs_witness_index(*acir_witness_b);
                    (-noir_to_native(*coeff), self.add_product(a, b))
                })
                .collect::<Vec<_>>();

            // Handle the last multiplication term directly
            let (final_coeff, final_acir_witness_a, final_acir_witness_b) =
                &expr.mul_terms[expr.mul_terms.len() - 1];
            a = vec![(
                noir_to_native(*final_coeff),
                self.fetch_r1cs_witness_index(*final_acir_witness_a),
            )];
            b = vec![(
                FieldElement::one(),
                self.fetch_r1cs_witness_index(*final_acir_witness_b),
            )];
        }

        // Extend with linear combinations
        linear.extend(expr.linear_combinations.iter().map(|term| {
            (
                noir_to_native(term.0).neg(),
                self.fetch_r1cs_witness_index(term.1),
            )
        }));

        // Add constant by multipliying with constant value one.
        linear.push((noir_to_native(expr.q_c).neg(), self.witness_one()));

        // Add a single linear constraint. We could avoid this by substituting
        // back into the last multiplication constraint.
        self.r1cs.add_constraint(&a, &b, &linear);
    }

    pub fn add_circuit(&mut self, circuit: &Circuit<NoirElement>) -> Result<()> {
        // Read-only memory blocks (used for building the memory lookup constraints at
        // the end)
        let mut memory_blocks: BTreeMap<usize, MemoryBlock> = BTreeMap::new();
        // Mapping the log of the range size k to the vector of witness indices that
        // are to be constrained within the range [0..2^k].
        // These will be digitally decomposed into smaller ranges, if necessary.
        let mut range_checks: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        // (input, input, output) tuples for AND and XOR operations.
        // Inputs may be either constants or R1CS witnesses.
        // Outputs are always R1CS witnesses.
        let mut and_ops = vec![];
        let mut xor_ops = vec![];

        for opcode in &circuit.opcodes {
            match opcode {
                Opcode::AssertZero(expr) => self.add_acir_assert_zero(expr),

                // Brillig is only for witness generation and does not produce constraints.
                Opcode::BrilligCall { .. } => {}

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
                    self.initial_memories
                        .insert(block_id, init.iter().map(|w| w.0 as usize).collect());
                    let mut block = MemoryBlock::new();
                    init.iter().for_each(|acir_witness| {
                        let r1cs_witness = self.fetch_r1cs_witness_index(*acir_witness);
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
                        |acir_witness| self.fetch_r1cs_witness_index(acir_witness),
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
                            self.fetch_r1cs_witness_index(op.value.to_witness().unwrap());
                        MemoryOperation::Load(addr, result_of_read)
                    } else {
                        let new_value =
                            self.fetch_r1cs_witness_index(op.value.to_witness().unwrap());
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
                            ConstantOrACIRWitness::Constant(_) => {
                                panic!(
                                    "We should never be range-checking a constant value, as this \
                                     should already be done by the noir-ACIR compiler"
                                );
                            }
                            ConstantOrACIRWitness::Witness(witness) => {
                                self.fetch_r1cs_witness_index(witness)
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

                    // Binary operations:
                    // The inputs and outputs will have already been solved for by the ACIR solver.
                    // Collect the R1CS witnesses indices so that we can later constrain them
                    // appropriately.
                    BlackBoxFuncCall::AND { lhs, rhs, output } => {
                        and_ops.push((
                            self.fetch_constant_or_r1cs_witness(lhs.input()),
                            self.fetch_constant_or_r1cs_witness(rhs.input()),
                            self.fetch_r1cs_witness_index(*output),
                        ));
                    }
                    BlackBoxFuncCall::XOR { lhs, rhs, output } => {
                        xor_ops.push((
                            self.fetch_constant_or_r1cs_witness(lhs.input()),
                            self.fetch_constant_or_r1cs_witness(rhs.input()),
                            self.fetch_r1cs_witness_index(*output),
                        ));
                    }

                    _ => {
                        unimplemented!("Other black box function: {:?}", black_box_func_call);
                    }
                },

                op => bail!("Unsupported Opcode {op}"),
            }
        }

        // For each memory block, add appropriate constraints (depending on whether it
        // is read-only or not)
        memory_blocks.iter().for_each(|(_, block)| {
            if block.is_read_only() {
                // Use a lookup to enforce that the reads are correct.
                add_rom_checking(self, block);
            } else {
                // Read/write memory block - use Spice offline memory checking.
                // Returns witnesses that need to be range checked.
                let (num_bits, witnesses_to_range_check) = add_ram_checking(self, block);
                let range_check = range_checks.entry(num_bits).or_default();
                witnesses_to_range_check
                    .iter()
                    .for_each(|value| range_check.push(*value));
            }
        });

        // For the AND and XOR operations, add the appropriate constraints.
        add_binop(self, BinOp::AND, and_ops);
        add_binop(self, BinOp::XOR, xor_ops);

        // Perform all range checks
        add_range_checks(self, range_checks);

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConstantOrR1CSWitness {
    Constant(#[serde(with = "serde_ark")] FieldElement),
    Witness(usize),
}

impl ConstantOrR1CSWitness {
    pub fn to_tuple(&self) -> (FieldElement, usize) {
        match self {
            ConstantOrR1CSWitness::Constant(c) => (*c, WITNESS_ONE_IDX),
            ConstantOrR1CSWitness::Witness(w) => (FieldElement::one(), *w),
        }
    }
}
