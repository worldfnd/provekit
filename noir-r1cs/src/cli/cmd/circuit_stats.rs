//! This binary analyzes ACIR circuit statistics and provides insights into
//! constraints, witness size, and various operations used in the circuit.

use {
    super::Command,
    acir::{
        circuit::{
            opcodes::{BlackBoxFuncCall, ConstantOrWitnessEnum},
            Opcode, Program,
        },
        native_types::Expression,
        FieldElement,
    },
    anyhow::Result,
    argh::FromArgs,
    base64::Engine,
    std::{
        collections::{hash_map::Entry, HashMap, HashSet},
        fs,
        ops::AddAssign,
        path::PathBuf,
    },
    tracing::instrument,
};

/// Simple program to show circuit statistics
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "circuit_stats")]
pub struct Args {
    /// path to circuit file
    #[argh(positional)]
    circuit_path: PathBuf,

    /// path to witness file
    #[argh(positional)]
    witness_path: PathBuf,
}

fn program_at_path(acir_path: String) -> Program<FieldElement> {
    let json_string =
        fs::read_to_string(acir_path).expect("There was a problem reading the file content");
    let json_str: &str = &json_string;
    let json: serde_json::Value =
        serde_json::from_str(json_str).expect("There was a problem parsing the json program");
    let Some(bytecode_str) = json["bytecode"].as_str() else {
        panic!("Expected a different circuit format")
    };
    let bytecode: &[u8] = &base64::prelude::BASE64_STANDARD
        .decode(bytecode_str)
        .expect("There was a problem decoding the program from base 64");
    let program = Program::deserialize_program(bytecode);
    program.unwrap()
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        main(self);
        Ok(())
    }
}

fn main(arg: &Args) {
    let program = program_at_path(arg.circuit_path.to_string_lossy().to_string());

    assert!(
        program.functions.len() == 1,
        "only one function supported at the moment",
    );

    let Program {
        mut functions,
        unconstrained_functions: _,
    } = program;
    let circuit = functions.pop().unwrap();

    println!("Private inputs len: {:?}", circuit.private_parameters.len());
    println!(
        "Public inputs len:  {:?}",
        circuit.public_parameters.0.len()
    );
    println!("Return values len:  {:?}", circuit.return_values.0.len());

    let mut total_num_mul_terms = 0;
    let mut total_num_assert_zero_opcodes = 0;

    // --- These are all the blackbox functions ---
    // --- Manual because the variants don't equal each other when they have
    // arguments ---
    let mut blackbox_func_call_variants: HashMap<&str, usize> = vec![
        ("AES128Encrypt", 0),
        ("AND", 0),
        ("XOR", 0),
        ("RANGE", 0),
        ("Blake2s", 0),
        ("Blake3", 0),
        ("EcdsaSecp256k1", 0),
        ("EcdsaSecp256r1", 0),
        ("MultiScalarMul", 0),
        ("EmbeddedCurveAdd", 0),
        ("Keccakf1600", 0),
        ("RecursiveAggregation", 0),
        ("BigIntAdd", 0),
        ("BigIntSub", 0),
        ("BigIntMul", 0),
        ("BigIntDiv", 0),
        ("BigIntFromLeBytes", 0),
        ("BigIntToLeBytes", 0),
        ("Poseidon2Permutation", 0),
        ("Sha256Compression", 0),
    ]
    .into_iter()
    .collect();

    // --- Data tracking for AND/XOR opcodes ---
    // Tuples are going to be the bit lengths of each binary input
    // Values are going to be the number instances for that specific tuple input
    let mut and_opcode_bit_counts: HashMap<(u32, u32), usize> = HashMap::new();
    let mut xor_opcode_bit_counts: HashMap<(u32, u32), usize> = HashMap::new();
    let and_with_non_witness_value: bool = false;
    let mut xor_with_non_witness_value: bool = false;

    // --- For counting types of instances of each input combination ---
    let mut heterogeneous_and_inputs_count = 0;
    let mut homogeneous_witness_and_inputs_count = 0;
    let mut homogeneous_constant_and_inputs_count = 0;
    let mut heterogeneous_xor_inputs_count = 0;
    let mut homogeneous_witness_xor_inputs_count = 0;
    let mut homogeneous_constant_xor_inputs_count = 0;

    // --- Data tracking for range checks ---
    let mut range_check_bit_counts: HashMap<u32, usize> = HashMap::new();

    // --- Data tracking for memory operations ---
    let mut mem_read_counter = 0;
    let mut mem_write_counter = 0;
    let mut mem_alloc_counter = 0;
    let mut mem_alloc_total_size = 0;
    // We want to know if any writes happen AFTER reads to a specific location
    let mut mem_read_locs = HashSet::new();
    let mut all_reads_after_writes = true;

    // --- Tracking for `BrilligCall` and `Call` ---
    let mut num_brillig_call_opcodes = 0;
    let mut unique_brillig_call_opcodes = HashSet::new();
    let mut num_call_opcodes = 0;
    let mut unique_call_opcodes = HashSet::new();

    // --- I'm guessing Noir does it so that you just "execute" the opcodes in a
    // linear manner --- --- Or at least that they correspond to constraints
    // which should be satisfied in that "order" ---
    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expr) => {
                // println!("AssertZero: {:?}", opcode);
                total_num_mul_terms += expr.num_mul_terms();
                total_num_assert_zero_opcodes += 1;
            }
            Opcode::BlackBoxFuncCall(variant) => {
                // println!("BlackBoxFuncCall: {:?}", variant);
                match variant {
                    BlackBoxFuncCall::AES128Encrypt {
                        inputs: _,
                        iv: _,
                        key: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("AES128Encrypt")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::AND {
                        lhs,
                        rhs,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("AND")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                        // --- Keep track of the various bit counts we are dealing with ---
                        if let Entry::Occupied(mut x) =
                            and_opcode_bit_counts.entry((lhs.num_bits(), rhs.num_bits()))
                        {
                            x.get_mut().add_assign(1);
                        } else {
                            and_opcode_bit_counts.insert((lhs.num_bits(), rhs.num_bits()), 1);
                        }
                        match (lhs.input(), rhs.input()) {
                            (
                                ConstantOrWitnessEnum::Constant(_),
                                ConstantOrWitnessEnum::Constant(_),
                            ) => {
                                homogeneous_constant_and_inputs_count += 1;
                            }
                            (
                                ConstantOrWitnessEnum::Constant(_),
                                ConstantOrWitnessEnum::Witness(_),
                            ) => {
                                heterogeneous_and_inputs_count += 1;
                            }
                            (
                                ConstantOrWitnessEnum::Witness(_),
                                ConstantOrWitnessEnum::Constant(_),
                            ) => {
                                heterogeneous_and_inputs_count += 1;
                            }
                            (
                                ConstantOrWitnessEnum::Witness(_),
                                ConstantOrWitnessEnum::Witness(_),
                            ) => {
                                homogeneous_witness_and_inputs_count += 1;
                            }
                        }
                    }
                    BlackBoxFuncCall::XOR {
                        lhs,
                        rhs,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("XOR")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                        // --- Keep track of the various bit counts we are dealing with ---
                        if let Entry::Occupied(mut x) =
                            xor_opcode_bit_counts.entry((lhs.num_bits(), rhs.num_bits()))
                        {
                            x.get_mut().add_assign(1);
                        } else {
                            xor_opcode_bit_counts.insert((lhs.num_bits(), rhs.num_bits()), 1);
                        }
                        if let ConstantOrWitnessEnum::Constant(_) = lhs.input() {
                            xor_with_non_witness_value = true;
                        }
                        if let ConstantOrWitnessEnum::Constant(_) = rhs.input() {
                            xor_with_non_witness_value = true;
                        }
                        match (lhs.input(), rhs.input()) {
                            (
                                ConstantOrWitnessEnum::Constant(_),
                                ConstantOrWitnessEnum::Constant(_),
                            ) => {
                                homogeneous_constant_xor_inputs_count += 1;
                            }
                            (
                                ConstantOrWitnessEnum::Constant(_),
                                ConstantOrWitnessEnum::Witness(_),
                            ) => {
                                heterogeneous_xor_inputs_count += 1;
                            }
                            (
                                ConstantOrWitnessEnum::Witness(_),
                                ConstantOrWitnessEnum::Constant(_),
                            ) => {
                                heterogeneous_xor_inputs_count += 1;
                            }
                            (
                                ConstantOrWitnessEnum::Witness(_),
                                ConstantOrWitnessEnum::Witness(_),
                            ) => {
                                homogeneous_witness_xor_inputs_count += 1;
                            }
                        }
                    }
                    BlackBoxFuncCall::RANGE { input } => {
                        // --- We keep track of the total number of RANGE calls ---
                        dbg!(&input.input());
                        blackbox_func_call_variants
                            .entry("RANGE")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                        // --- We also keep track of the RANGE calls, broken down by num bits ---
                        if let Entry::Occupied(mut x) =
                            range_check_bit_counts.entry(input.num_bits())
                        {
                            x.get_mut().add_assign(1);
                        } else {
                            range_check_bit_counts.insert(input.num_bits(), 1);
                        }
                    }

                    BlackBoxFuncCall::Blake2s {
                        inputs: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("Blake2s")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::Blake3 {
                        inputs: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("Blake3")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::EcdsaSecp256k1 {
                        public_key_x: _,
                        public_key_y: _,
                        signature: _,
                        hashed_message: _,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("EcdsaSecp256k1")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::EcdsaSecp256r1 {
                        public_key_x: _,
                        public_key_y: _,
                        signature: _,
                        hashed_message: _,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("EcdsaSecp256r1")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::MultiScalarMul {
                        points: _,
                        scalars: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("MultiScalarMul")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::EmbeddedCurveAdd {
                        input1: _,
                        input2: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("EmbeddedCurveAdd")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::Keccakf1600 {
                        inputs: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("Keccakf1600")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::RecursiveAggregation {
                        verification_key: _,
                        proof: _,
                        public_inputs: _,
                        key_hash: _,
                        proof_type: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("RecursiveAggregation")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::BigIntAdd {
                        lhs: _,
                        rhs: _,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("BigIntAdd")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::BigIntSub {
                        lhs: _,
                        rhs: _,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("BigIntSub")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::BigIntMul {
                        lhs: _,
                        rhs: _,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("BigIntMul")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::BigIntDiv {
                        lhs: _,
                        rhs: _,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("BigIntDiv")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::BigIntFromLeBytes {
                        inputs: _,
                        modulus: _,
                        output: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("BigIntFromLeBytes")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::BigIntToLeBytes {
                        input: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("BigIntToLeBytes")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::Poseidon2Permutation {
                        inputs: _,
                        outputs: _,
                        len: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("Poseidon2Permutation")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                    BlackBoxFuncCall::Sha256Compression {
                        inputs: _,
                        hash_values: _,
                        outputs: _,
                    } => {
                        blackbox_func_call_variants
                            .entry("Sha256Compression")
                            .and_modify(|count| {
                                count.add_assign(1);
                            });
                    }
                }
            }
            Opcode::MemoryOp {
                block_id,
                op,
                predicate: _,
            } => {
                // --- For MemoryOp there are only two variants: read and write ---
                // --- Additionally, each MemoryOp tells you how to read/write a *single* index
                // --- --- Therefore we will simply count the total number of
                // reads and writes --- (Additionally, check whether each write
                // happens before all reads to that address)

                // `Expression::zero()` means read, and `Expression::one()` means write
                if op.operation == Expression::zero() {
                    mem_read_counter += 1;
                    mem_read_locs.insert((block_id, op.index.clone()));
                } else {
                    mem_write_counter += 1;
                    // --- If we've read from this location before and *then* wrote to it ---
                    if mem_read_locs.contains(&(block_id, op.index.clone())) {
                        println!("Write after read at {:?}, {:?}", block_id, op.index.clone());
                        all_reads_after_writes = false;
                    }
                }

                // println!("MemoryOp: {:?}", opcode);
            }
            Opcode::MemoryInit {
                block_id: _,
                init,
                block_type: _,
            } => {
                mem_alloc_counter += 1;
                mem_alloc_total_size += init.len();
                // println!("MemoryInit: {:?}", opcode);

                // TODO(ryancao): handle block type?
                // pub enum BlockType {
                //     Memory,
                //     CallData(u32),
                //     ReturnData,
                // }
            }
            Opcode::BrilligCall {
                id,
                inputs: _,
                outputs: _,
                predicate: _,
            } => {
                // println!("BrilligCall: {:?}", opcode);
                // --- Brillig calls aren't really translated into constraints ---
                // --- Therefore we can profile them but won't worry about them ---
                num_brillig_call_opcodes += 1;
                unique_brillig_call_opcodes.insert(id);
            }
            Opcode::Call {
                id,
                inputs: _,
                outputs: _,
                predicate: _,
            } => {
                // println!("Call: {:?}", opcode);
                // --- So these are calls to separate circuits... Not sure where to get those
                // circuits, but oh well ---
                num_call_opcodes += 1;
                unique_call_opcodes.insert(id);
            }
        }
    }

    // --- AssertZero ---
    println!("Num AssertZero: {total_num_assert_zero_opcodes:}",);
    println!("Num `mul_term`s: {total_num_mul_terms:}");

    // --- Blackbox functions ---
    for (k, v) in &blackbox_func_call_variants {
        if *v > 0 {
            println!("Blackbox fn {k:?}: {v:?}");
        }
    }
    let mut key_value_pairs: Vec<(u32, usize)> = range_check_bit_counts.into_iter().collect();
    key_value_pairs.sort_by(|x, y| y.1.cmp(&x.1));
    for (k, v) in &key_value_pairs {
        println!("RANGE check: {k:?} bits had {v:?} lookups");
    }

    // --- Blackbox AND and XOR functions ---
    and_opcode_bit_counts.iter().for_each(|(k, v)| {
        println!(
            "AND blackbox call with input dims {:?} accessed {:?} times",
            k, v
        );
    });
    println!(
        "Did we see any AND with non-witness values: {:?}",
        and_with_non_witness_value
    );
    println!(
        "heterogeneous_and_inputs_count: {:?}",
        heterogeneous_and_inputs_count
    );
    println!(
        "homogeneous_witness_and_inputs_count: {:?}",
        homogeneous_witness_and_inputs_count
    );
    println!(
        "homogeneous_constant_and_inputs_count: {:?}",
        homogeneous_constant_and_inputs_count
    );
    xor_opcode_bit_counts.iter().for_each(|(k, v)| {
        println!(
            "XOR blackbox call with input dims {:?} accessed {:?} times",
            k, v
        );
    });
    println!(
        "Did we see any XOR with non-witness values: {:?}",
        xor_with_non_witness_value
    );
    println!(
        "heterogeneous_xor_inputs_count: {:?}",
        heterogeneous_xor_inputs_count
    );
    println!(
        "homogeneous_witness_xor_inputs_count: {:?}",
        homogeneous_witness_xor_inputs_count
    );
    println!(
        "homogeneous_constant_xor_inputs_count: {:?}",
        homogeneous_constant_xor_inputs_count
    );

    // --- Memory operations ---
    println!("Num Memory inits: {mem_alloc_counter:?}");
    println!("Total memory alloc size: {mem_alloc_total_size:?}");
    println!("Num Memory writes: {mem_write_counter:?}");
    println!("Num Memory reads: {mem_read_counter:?}");
    println!("Read-only: {all_reads_after_writes:?}");

    // --- Brillig + Call operations ---
    println!("Num Brillig calls: {num_brillig_call_opcodes:?}");
    println!(
        "Num Unique Brillig opcodes: {:?}",
        unique_brillig_call_opcodes.len()
    );
    println!("Num Calls: {num_call_opcodes:?}");
    println!("Num Unique calls: {:?}", unique_call_opcodes.len());

    println!("----------------------------------------------------------------");

    // --- Finally, we analyze the total number of constraints + witness size ---
    let mut total_num_r1cs_rows = 0;
    let mut total_num_witness_size = 0;
    total_num_r1cs_rows += total_num_assert_zero_opcodes + total_num_mul_terms;
    println!(
        "{:?} constraints from AssertZero",
        total_num_assert_zero_opcodes + total_num_mul_terms
    );
    // SHA adds 31264 R1CS constraints and 30959 witnesses
    if let Entry::Occupied(x) = blackbox_func_call_variants.entry("Sha256Compression") {
        println!("{:?} constraints from SHA", 31264 * x.get());
        println!("{:?} witnesses from SHA", 30959 * x.get());
        total_num_r1cs_rows += 31264 * x.get();
        total_num_witness_size += 30959 * x.get();
    }
    // Poseidon adds 415 R1CS constraints and 417 wires
    if let Entry::Occupied(x) = blackbox_func_call_variants.entry("Poseidon2Permutation") {
        println!("{:?} constraints from Poseidon2", 415 * x.get());
        println!("{:?} witnesses from Poseidon2", 417 * x.get());
        total_num_r1cs_rows += 415 * x.get();
        total_num_witness_size += 417 * x.get();
    }
    // We do a simple (i.e. non-LogUp) approach for computing range checks
    let mut total_num_range_check_constraints = 0;
    let mut total_num_range_check_witnesses = 0;
    for (k, v) in &key_value_pairs {
        total_num_range_check_constraints += 2 * v; // Let's assume for now that we can do the decomp in a single R1CS row
        total_num_range_check_witnesses += (*k as usize) * v; // Total # of
                                                              // extra witnesses
    }
    println!("{total_num_range_check_constraints:?} constraints from range checks");
    println!("{total_num_range_check_witnesses:?} witnesses from range checks");
    total_num_r1cs_rows += total_num_range_check_constraints;
    total_num_witness_size += total_num_range_check_witnesses;

    // TODO(ryancao): COMPUTE THE MEMORY CHECKER CONSTRAINTS
    println!("TODO(ryancao): MISSING MEMORY CHECKER CONSTRAINTS");
    println!(
        "{:?} total R1CS constraints ({:?} num vars)",
        total_num_r1cs_rows,
        (total_num_r1cs_rows as f64).log2()
    );
    println!(
        "{:?} total R1CS witness size, ({:?} num vars)",
        total_num_witness_size,
        (total_num_witness_size as f64).log2()
    );
}
