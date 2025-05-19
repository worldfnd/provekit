use std::ops::Neg;
use acir::{AcirField, FieldElement};

use crate::{compiler::{ConstantOrR1CSWitness, R1CS}, digits::{add_digital_decomposition, decompose_into_digits}, solver::WitnessBuilder};

#[derive(Clone, Debug, Copy)]
pub enum BinOp {
    AND,
    XOR,
}

/// The number of bits that ACIR uses for the arguments and output of the binop.
pub const BINOP_BITS: usize = 32;

/// The number of bits that used by us for the arguments and output of the binop.
/// 2x the number of bits is used for the lookup table.
pub const BINOP_ATOMIC_BITS: usize = 8;

/// Each operand is decomposed into this many digits.
pub const NUM_DIGITS: usize = BINOP_BITS / BINOP_ATOMIC_BITS;

pub(crate) fn add_binop(
    r1cs: &mut R1CS,
    op: BinOp,
    operands_and_outputs: Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>
) {
    let log_bases = vec![BINOP_ATOMIC_BITS; NUM_DIGITS];

    // Collect all witnesses for digital decomposition into u8s
    let mut witnesses_to_decompose = vec![];
    for (lhs, rhs, output) in &operands_and_outputs {
        if let ConstantOrR1CSWitness::Witness(witness) = lhs {
            witnesses_to_decompose.push(*witness);
        }
        if let ConstantOrR1CSWitness::Witness(witness) = rhs {
            witnesses_to_decompose.push(*witness);
        }
        witnesses_to_decompose.push(*output);
    }
    let dd_struct = add_digital_decomposition(
        r1cs,
        log_bases.clone(),
        witnesses_to_decompose
    );

    // Match up digit witnesses and digits of decompositions of constants to obtain
    // a decomposed version of operations.
    let mut operands_and_outputs_u8 = vec![];
    let mut dd_counter = 0;
    for (lhs, rhs, _output) in operands_and_outputs {
        // How many digital decompositions we've seen so far
        let lhs_u8s = match lhs {
            ConstantOrR1CSWitness::Witness(_) => {
                let digit_witnesses = (0..4).map(|digit_place| {
                    digit_place * dd_struct.witnesses_to_decompose.len() + dd_counter
                }).collect::<Vec<_>>();
                dd_counter += 1;
                digit_witnesses.iter().map(|witness| ConstantOrR1CSWitness::Witness(*witness)).collect::<Vec<_>>()
            },
            ConstantOrR1CSWitness::Constant(value) => {
                let digits = decompose_into_digits(value, &log_bases);
                digits.iter().map(|digit| {
                    ConstantOrR1CSWitness::Constant(*digit)
                }).collect::<Vec<_>>()
            }
        };
        let rhs_u8s = match rhs {
            ConstantOrR1CSWitness::Witness(_) => {
                let digit_witnesses = (0..4).map(|digit_place| {
                    digit_place * dd_struct.witnesses_to_decompose.len() + dd_counter
                }).collect::<Vec<_>>();
                dd_counter += 1;
                digit_witnesses.iter().map(|witness| ConstantOrR1CSWitness::Witness(*witness)).collect::<Vec<_>>()
            },
            ConstantOrR1CSWitness::Constant(value) => {
                let digits = decompose_into_digits(value, &log_bases);
                digits.iter().map(|digit| {
                    ConstantOrR1CSWitness::Constant(*digit)
                }).collect::<Vec<_>>()
            }
        };
        let output_u8s = (0..4).map(|digit_place| {
            digit_place * dd_struct.witnesses_to_decompose.len() + dd_counter
        }).collect::<Vec<_>>();
        dd_counter += 1;

        lhs_u8s.into_iter().zip(rhs_u8s.into_iter()).zip(output_u8s.into_iter()).for_each(|((lhs, rhs), output)| {
            operands_and_outputs_u8.push((lhs, rhs, output));
        });
    }

    let multiplicities_wb = WitnessBuilder::MultiplicitiesForBinOp(
        r1cs.num_witnesses(),
        operands_and_outputs_u8
            .iter()
            .map(|(lh_operand, rh_operand, _output)| (lh_operand.clone(), rh_operand.clone()))
            .collect(),
    );
    let multiplicities_first_witness = r1cs.add_witness_builder(multiplicities_wb);

    // Add two verifier challenges for the lookup
    let sz_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));
    let rs_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));
    let rs_challenge_sqrd = r1cs.add_product(rs_challenge, rs_challenge);

    // Calculate the sum, over all invocations of the bin op, of 1 / denominator
    let summands_for_bin_op = operands_and_outputs_u8
        .into_iter()
        .map(|(lhs, rhs, output)| {
            add_lookup_summand(
                r1cs,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                lhs,
                rhs,
                ConstantOrR1CSWitness::Witness(output),
            )
        })
        .map(|coeff| (None, coeff))
        .collect();
    let sum_for_bin_op = r1cs.add_sum(summands_for_bin_op);

    // Calculate the sum over all table elements of multiplicity/factor
    let summands_for_table = (0..1 << BINOP_ATOMIC_BITS)
        .flat_map(|lh_operand: u32|
            (0..1 << BINOP_ATOMIC_BITS)
                .map(move |rh_operand: u32| {
                    let output = match op {
                        BinOp::AND => lh_operand & rh_operand,
                        BinOp::XOR => lh_operand ^ rh_operand,
                    };
                    (lh_operand, rh_operand, output)
                })
        )
        .map(|(lh_operand, rh_operand, output)| {
            let denominator = add_lookup_summand(
                r1cs,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                ConstantOrR1CSWitness::Constant(FieldElement::from(lh_operand)),
                ConstantOrR1CSWitness::Constant(FieldElement::from(rh_operand)),
                ConstantOrR1CSWitness::Constant(FieldElement::from(output)),
            );
            let multiplicity_witness_idx = multiplicities_first_witness + (lh_operand << BINOP_ATOMIC_BITS) as usize + rh_operand as usize;
            r1cs.add_product(multiplicity_witness_idx, denominator)
        })
        .map(|coeff| (None, coeff))
        .collect();
    let sum_for_table = r1cs.add_sum(summands_for_table);

    // Check that these two sums are equal.
    r1cs.matrices.add_constraint(
        &[(FieldElement::one(), r1cs.witness_one())],
        &[(FieldElement::one(), sum_for_bin_op)],
        &[(FieldElement::one(), sum_for_table)],
    );
}

// Add and return a new witness `denominator` and constrains it to represent:
// `w[sz_challenge] - (w[lh_operand] + w[rs_challenge] * w[rh_operand] + w[rs_challenge_sqrd] * w[output])`
// where `w` is the witness vector, if `output` is a witness.
// If `output` is a constant, then the `rs_challenge_sqrd` is instead scaled by this constant.
// Finally, adds a new witness for its inverse, constrains it to be such, and returns its index.
fn add_lookup_summand(
    r1cs: &mut R1CS,
    sz_challenge: usize,
    rs_challenge: usize,
    rs_challenge_sqrd: usize,
    lh_operand: ConstantOrR1CSWitness,
    rh_operand: ConstantOrR1CSWitness,
    output: ConstantOrR1CSWitness,
) -> usize {
    let wb = WitnessBuilder::BinOpLookupDenominator(
        r1cs.num_witnesses(),
        sz_challenge,
        rs_challenge,
        rs_challenge_sqrd,
        lh_operand.clone(),
        rh_operand.clone(),
        output.clone(),
    );
    let denominator = r1cs.add_witness_builder(wb);
    // Add an intermediate witness if the output is a witness (otherwise can just scale)
    let rs_challenge_sqrd_summand = match output {
        ConstantOrR1CSWitness::Constant(value) => (FieldElement::from(value), rs_challenge_sqrd),
        ConstantOrR1CSWitness::Witness(witness) => (FieldElement::one(), r1cs.add_product(rs_challenge_sqrd, witness))
    };
    r1cs.matrices.add_constraint(
        &[(FieldElement::one().neg(), rs_challenge)],
        &[rh_operand.to_tuple()],
        &[
            (FieldElement::one(), denominator),
            (FieldElement::one().neg(), sz_challenge),
            (lh_operand.to_tuple()),
            rs_challenge_sqrd_summand,
        ],
    );
    let inverse = r1cs.add_witness_builder(WitnessBuilder::Inverse(r1cs.num_witnesses(), denominator));
    r1cs.matrices.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), inverse)],
        &[(FieldElement::one(), r1cs.witness_one())],
    );
    inverse
}
