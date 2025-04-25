use acir::{
    circuit::opcodes::{ConstantOrWitnessEnum, FunctionInput},
    native_types::Witness,
    AcirField, FieldElement,
};
use std::{collections::BTreeMap, ops::Neg};

use crate::{
    compiler::R1CS,
    solver::WitnessBuilder,
    utils::helpers::{compute_compact_bin_op_logup_repr, BinOp},
};

/// This is the function which should get called by the compiler whenever
/// a OpCode::{AND, XOR, OR, etc.} is called.
///
/// NOTE: We currently assume that all the binary logical operators are called
/// with `u32`s ONLY and perform a `(u8, u8, u8, u8)` decomposition.
/// Additionally, we do *not* range check the inputs or outputs since they are
/// assumed to have OpCode::RANGE over them already given their `u32` data
/// types.
pub fn add_bin_opcode_initial_witnesses(
    r1cs: &mut R1CS,
    op: BinOp,
    value_to_decomp_map: &mut BTreeMap<usize, Vec<(u32, usize)>>,
    binop_opcode_packed_elems_r1cs_indices: &mut Vec<usize>,
    lhs: &FunctionInput<FieldElement>,
    rhs: &FunctionInput<FieldElement>,
    output: &Witness,
) {
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
        (
            ConstantOrWitnessEnum::Witness(lhs_input_witness),
            ConstantOrWitnessEnum::Constant(rhs_constant),
        ) => (
            WitnessBuilder::Acir(lhs_input_witness.as_usize()),
            WitnessBuilder::Constant(rhs_constant),
        ),
        (
            ConstantOrWitnessEnum::Constant(lhs_constant),
            ConstantOrWitnessEnum::Witness(rhs_input_witness),
        ) => (
            WitnessBuilder::Constant(lhs_constant),
            WitnessBuilder::Acir(rhs_input_witness.as_usize()),
        ),
        _ => panic!("We should not be calling an AND/XOR opcode on two constant values."),
    };

    // --- Add all the needed witnesses to the R1CS instance... ---
    let lhs_r1cs_witness_idx = r1cs.add_witness(lhs_input_wb);
    let rhs_r1cs_witness_idx = r1cs.add_witness(rhs_input_wb);
    let output_r1cs_witness_idx = r1cs.add_witness(WitnessBuilder::Acir(output.as_usize()));

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
                op,
            ))
        })
        .collect();
    binop_opcode_packed_elems_r1cs_indices.append(&mut packed_table_val_r1cs_indices);
}

/// For AND and XOR opcodes.
pub fn add_bin_opcode_logup_constraints_witnesses(
    r1cs: &mut R1CS,
    op: BinOp,
    binop_opcode_packed_elems_r1cs_indices: &Vec<usize>,
) {
    // --- Okay so let's add the table which contains all (u8 & u8 -> u8) values ---
    // TODO: Can we combine all of these SZ challenges?
    // TODO: We need to be careful with the ordering within the witness vector here
    let binop_opcode_sz_challenge_r1cs_index = r1cs.add_witness(WitnessBuilder::Challenge);

    // Canonically, we will say that the LHS for logup is the "thing to be
    // looked up" side and the RHS for logup is the "lookup table" side.
    // This first bit of code computes the "lookup table" side.
    let all_compact_binop_reprs: Vec<u32> = (0..255)
        .flat_map(|lhs| (0..255).map(move |rhs| compute_compact_bin_op_logup_repr(lhs, rhs, op)))
        .collect();
    let binop_logup_frac_rhs_r1cs_indices = all_compact_binop_reprs
        .iter()
        .map(|compact_binop_repr| {
            let logup_table_frac_inv_idx = r1cs.add_lookup_factor(
                binop_opcode_sz_challenge_r1cs_index,
                FieldElement::from(*compact_binop_repr),
                r1cs.solver.witness_one(),
            );
            let multiplicity_witness_r1cs_idx = r1cs.add_witness(match op {
                BinOp::AND => WitnessBuilder::AndOpcodeTupleMultiplicity(*compact_binop_repr),
                BinOp::XOR => WitnessBuilder::XorOpcodeTupleMultiplicity(*compact_binop_repr),
            });
            r1cs.add_product(logup_table_frac_inv_idx, multiplicity_witness_r1cs_idx)
        })
        .collect();

    // Next, we compute all of the (1 / (1 - x_i)) values, i.e. the "things
    // to be looked up" side.
    let binop_logup_frac_lhs_r1cs_indices = binop_opcode_packed_elems_r1cs_indices
        .iter()
        .map(|packed_val_idx| {
            r1cs.add_lookup_factor(
                binop_opcode_sz_challenge_r1cs_index,
                FieldElement::one(),
                *packed_val_idx,
            )
        })
        .collect();

    // Compute the sums over the LHS and RHS and check that they are equal.
    let sum_for_table = r1cs.add_sum(binop_logup_frac_rhs_r1cs_indices);
    let sum_for_witness = r1cs.add_sum(binop_logup_frac_lhs_r1cs_indices);
    r1cs.matrices.add_constraint(
        &[
            (FieldElement::one(), sum_for_table),
            (FieldElement::one().neg(), sum_for_witness),
        ],
        &[(FieldElement::one(), r1cs.solver.witness_one())],
        &[(FieldElement::zero(), r1cs.solver.witness_one())],
    );
}
