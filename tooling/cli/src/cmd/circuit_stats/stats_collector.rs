//! Circuit statistics collection.
//!
//! Collects comprehensive statistics from ACIR circuits by traversing opcodes
//! and tracking all relevant operations.

use {
    super::memory::MemoryStats,
    acir::{
        circuit::{
            opcodes::{AcirFunctionId, BlackBoxFuncCall, ConstantOrWitnessEnum},
            Circuit, Opcode,
        },
        native_types::Expression,
        FieldElement,
    },
    std::collections::{HashMap, HashSet},
};

/// R1CS complexity constants for black box functions (measured empirically).
pub(super) const SHA256_COMPRESSION_CONSTRAINTS: usize = 31_264;
pub(super) const SHA256_COMPRESSION_WITNESSES: usize = 30_959;
pub(super) const POSEIDON2_PERMUTATION_CONSTRAINTS: usize = 415;
pub(super) const POSEIDON2_PERMUTATION_WITNESSES: usize = 417;

/// Comprehensive circuit statistics collector.
pub(super) struct CircuitStats {
    // AssertZero statistics
    pub num_mul_terms:           usize,
    pub num_assert_zero_opcodes: usize,

    // Black box function counts
    pub blackbox_func_counts: HashMap<String, usize>,

    // AND/XOR operation details
    pub and_bit_counts:                  HashMap<(u32, u32), usize>,
    pub xor_bit_counts:                  HashMap<(u32, u32), usize>,
    pub heterogeneous_and_inputs:        usize,
    pub homogeneous_witness_and_inputs:  usize,
    pub homogeneous_constant_and_inputs: usize,
    pub heterogeneous_xor_inputs:        usize,
    pub homogeneous_witness_xor_inputs:  usize,
    pub homogeneous_constant_xor_inputs: usize,
    pub xor_with_non_witness_value:      bool,

    // Range check statistics
    pub range_check_bit_counts: HashMap<u32, usize>,

    // Memory operation statistics
    pub memory: MemoryStats,

    // Function call statistics
    pub num_brillig_calls:    usize,
    pub unique_brillig_calls: HashSet<String>,
    pub num_calls:            usize,
    pub unique_calls:         HashSet<AcirFunctionId>,
}

impl CircuitStats {
    /// Creates a new statistics collector from an ACIR circuit.
    pub fn from_circuit(circuit: &Circuit<FieldElement>) -> Self {
        let mut stats = Self::new();
        stats.collect_from_circuit(circuit);
        stats
    }

    /// Initializes a new statistics collector with empty counts.
    fn new() -> Self {
        let mut blackbox_func_counts = HashMap::new();

        // Initialize all known black box functions
        for func in BLACKBOX_FUNCTIONS {
            blackbox_func_counts.insert(func.to_string(), 0);
        }

        Self {
            num_mul_terms: 0,
            num_assert_zero_opcodes: 0,
            blackbox_func_counts,
            and_bit_counts: HashMap::new(),
            xor_bit_counts: HashMap::new(),
            heterogeneous_and_inputs: 0,
            homogeneous_witness_and_inputs: 0,
            homogeneous_constant_and_inputs: 0,
            heterogeneous_xor_inputs: 0,
            homogeneous_witness_xor_inputs: 0,
            homogeneous_constant_xor_inputs: 0,
            xor_with_non_witness_value: false,
            range_check_bit_counts: HashMap::new(),
            memory: MemoryStats::default(),
            num_brillig_calls: 0,
            unique_brillig_calls: HashSet::new(),
            num_calls: 0,
            unique_calls: HashSet::new(),
        }
    }

    /// Collects statistics by traversing all opcodes in the circuit.
    fn collect_from_circuit(&mut self, circuit: &Circuit<FieldElement>) {
        for opcode in &circuit.opcodes {
            self.process_opcode(opcode);
        }
    }

    /// Processes a single ACIR opcode.
    fn process_opcode(&mut self, opcode: &Opcode<FieldElement>) {
        match opcode {
            Opcode::AssertZero(expr) => {
                self.num_mul_terms += expr.num_mul_terms();
                self.num_assert_zero_opcodes += 1;
            }

            Opcode::BlackBoxFuncCall(call) => self.process_blackbox_call(call),

            Opcode::MemoryOp {
                block_id,
                op,
                predicate: _,
            } => {
                // Expression::zero() indicates read, Expression::one() indicates write
                if op.operation == Expression::zero() {
                    self.memory.record_read(block_id.0, &op.index);
                } else {
                    self.memory.record_write(block_id.0, &op.index);
                }
            }

            Opcode::MemoryInit {
                block_id,
                init,
                block_type,
            } => {
                self.memory.record_init(block_id.0, block_type, init.len());
            }

            Opcode::BrilligCall { id, .. } => {
                self.num_brillig_calls += 1;
                self.unique_brillig_calls.insert(format!("{:?}", id));
            }

            Opcode::Call { id, .. } => {
                self.num_calls += 1;
                self.unique_calls.insert(*id);
            }
        }
    }

    /// Processes a black box function call.
    fn process_blackbox_call(&mut self, call: &BlackBoxFuncCall<FieldElement>) {
        match call {
            BlackBoxFuncCall::AES128Encrypt { .. } => self.increment_blackbox("AES128Encrypt"),
            BlackBoxFuncCall::AND { lhs, rhs, .. } => self.process_and_operation(lhs, rhs),
            BlackBoxFuncCall::XOR { lhs, rhs, .. } => self.process_xor_operation(lhs, rhs),
            BlackBoxFuncCall::RANGE { input } => self.process_range_check(input),
            BlackBoxFuncCall::Blake2s { .. } => self.increment_blackbox("Blake2s"),
            BlackBoxFuncCall::Blake3 { .. } => self.increment_blackbox("Blake3"),
            BlackBoxFuncCall::EcdsaSecp256k1 { .. } => self.increment_blackbox("EcdsaSecp256k1"),
            BlackBoxFuncCall::EcdsaSecp256r1 { .. } => self.increment_blackbox("EcdsaSecp256r1"),
            BlackBoxFuncCall::MultiScalarMul { .. } => self.increment_blackbox("MultiScalarMul"),
            BlackBoxFuncCall::EmbeddedCurveAdd { .. } => {
                self.increment_blackbox("EmbeddedCurveAdd")
            }
            BlackBoxFuncCall::Keccakf1600 { .. } => self.increment_blackbox("Keccakf1600"),
            BlackBoxFuncCall::RecursiveAggregation { .. } => {
                self.increment_blackbox("RecursiveAggregation")
            }
            BlackBoxFuncCall::BigIntAdd { .. } => self.increment_blackbox("BigIntAdd"),
            BlackBoxFuncCall::BigIntSub { .. } => self.increment_blackbox("BigIntSub"),
            BlackBoxFuncCall::BigIntMul { .. } => self.increment_blackbox("BigIntMul"),
            BlackBoxFuncCall::BigIntDiv { .. } => self.increment_blackbox("BigIntDiv"),
            BlackBoxFuncCall::BigIntFromLeBytes { .. } => {
                self.increment_blackbox("BigIntFromLeBytes")
            }
            BlackBoxFuncCall::BigIntToLeBytes { .. } => self.increment_blackbox("BigIntToLeBytes"),
            BlackBoxFuncCall::Poseidon2Permutation { .. } => {
                self.increment_blackbox("Poseidon2Permutation")
            }
            BlackBoxFuncCall::Sha256Compression { .. } => {
                self.increment_blackbox("Sha256Compression")
            }
        }
    }

    fn increment_blackbox(&mut self, func_name: &str) {
        *self
            .blackbox_func_counts
            .entry(func_name.to_string())
            .or_insert(0) += 1;
    }

    fn process_and_operation(
        &mut self,
        lhs: &acir::circuit::opcodes::FunctionInput<FieldElement>,
        rhs: &acir::circuit::opcodes::FunctionInput<FieldElement>,
    ) {
        self.increment_blackbox("AND");
        *self
            .and_bit_counts
            .entry((lhs.num_bits(), rhs.num_bits()))
            .or_insert(0) += 1;

        match (lhs.input(), rhs.input()) {
            (ConstantOrWitnessEnum::Constant(_), ConstantOrWitnessEnum::Constant(_)) => {
                self.homogeneous_constant_and_inputs += 1;
            }
            (ConstantOrWitnessEnum::Constant(_), ConstantOrWitnessEnum::Witness(_))
            | (ConstantOrWitnessEnum::Witness(_), ConstantOrWitnessEnum::Constant(_)) => {
                self.heterogeneous_and_inputs += 1;
            }
            (ConstantOrWitnessEnum::Witness(_), ConstantOrWitnessEnum::Witness(_)) => {
                self.homogeneous_witness_and_inputs += 1;
            }
        }
    }

    fn process_xor_operation(
        &mut self,
        lhs: &acir::circuit::opcodes::FunctionInput<FieldElement>,
        rhs: &acir::circuit::opcodes::FunctionInput<FieldElement>,
    ) {
        self.increment_blackbox("XOR");
        *self
            .xor_bit_counts
            .entry((lhs.num_bits(), rhs.num_bits()))
            .or_insert(0) += 1;

        if matches!(lhs.input(), ConstantOrWitnessEnum::Constant(_))
            || matches!(rhs.input(), ConstantOrWitnessEnum::Constant(_))
        {
            self.xor_with_non_witness_value = true;
        }

        match (lhs.input(), rhs.input()) {
            (ConstantOrWitnessEnum::Constant(_), ConstantOrWitnessEnum::Constant(_)) => {
                self.homogeneous_constant_xor_inputs += 1;
            }
            (ConstantOrWitnessEnum::Constant(_), ConstantOrWitnessEnum::Witness(_))
            | (ConstantOrWitnessEnum::Witness(_), ConstantOrWitnessEnum::Constant(_)) => {
                self.heterogeneous_xor_inputs += 1;
            }
            (ConstantOrWitnessEnum::Witness(_), ConstantOrWitnessEnum::Witness(_)) => {
                self.homogeneous_witness_xor_inputs += 1;
            }
        }
    }

    fn process_range_check(&mut self, input: &acir::circuit::opcodes::FunctionInput<FieldElement>) {
        self.increment_blackbox("RANGE");
        *self
            .range_check_bit_counts
            .entry(input.num_bits())
            .or_insert(0) += 1;
    }
}

/// All supported ACIR black box functions.
const BLACKBOX_FUNCTIONS: &[&str] = &[
    "AES128Encrypt",
    "AND",
    "XOR",
    "RANGE",
    "Blake2s",
    "Blake3",
    "EcdsaSecp256k1",
    "EcdsaSecp256r1",
    "MultiScalarMul",
    "EmbeddedCurveAdd",
    "Keccakf1600",
    "RecursiveAggregation",
    "BigIntAdd",
    "BigIntSub",
    "BigIntMul",
    "BigIntDiv",
    "BigIntFromLeBytes",
    "BigIntToLeBytes",
    "Poseidon2Permutation",
    "Sha256Compression",
];
