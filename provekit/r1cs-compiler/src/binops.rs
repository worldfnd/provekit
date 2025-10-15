use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_std::One,
    provekit_common::{
        witness::{
            decompose_into_digits, ConstantOrR1CSWitness, SumTerm, WitnessBuilder,
            BINOP_ATOMIC_BITS, NUM_DIGITS,
        },
        FieldElement,
    },
    std::ops::Neg,
};

#[derive(Clone, Debug, Copy)]
pub enum BinOp {
    And,
    Xor,
}

/// Allocate a witness for a binary operation result, add the appropriate
/// WitnessBuilder for value computation, and collect the operation for later
/// constraint generation. Returns the witness index of the result.
pub(crate) fn add_binop(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    op: BinOp,
    collected_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    lhs: ConstantOrR1CSWitness,
    rhs: ConstantOrR1CSWitness,
) -> usize {
    let result_witness = match op {
        BinOp::And => r1cs_compiler.add_witness_builder(WitnessBuilder::And(
            r1cs_compiler.num_witnesses(),
            lhs,
            rhs,
        )),
        BinOp::Xor => r1cs_compiler.add_witness_builder(WitnessBuilder::Xor(
            r1cs_compiler.num_witnesses(),
            lhs,
            rhs,
        )),
    };

    collected_ops.push((lhs, rhs, result_witness));

    result_witness
}

/// Add the witnesses and constraints for a [BinOp] (i.e. AND, XOR). Uses a
/// digital decomposition of the operands and output into [NUM_DIGITS] digits of
/// [BINOP_ATOMIC_BITS] bits each, followed by a lookup table of size 2x
/// [BINOP_ATOMIC_BITS].
pub(crate) fn add_binop_constraints(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    op: BinOp,
    inputs_and_outputs: Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
) {
    let log_bases = vec![BINOP_ATOMIC_BITS; NUM_DIGITS];

    if inputs_and_outputs.is_empty() {
        return;
    }

    // Collect all witnesses that require digital decomposition (constants are
    // decomposed separately).
    let mut witnesses_to_decompose = vec![];
    for (lh, rh, output) in &inputs_and_outputs {
        if let ConstantOrR1CSWitness::Witness(witness) = lh {
            witnesses_to_decompose.push(*witness);
        }
        if let ConstantOrR1CSWitness::Witness(witness) = rh {
            witnesses_to_decompose.push(*witness);
        }
        witnesses_to_decompose.push(*output);
    }
    let dd_struct =
        add_digital_decomposition(r1cs_compiler, log_bases.clone(), witnesses_to_decompose);

    // Match up the digit witnesses and the digits of decompositions of constants to
    // obtain a decomposed version of the inputs and outputs.
    let mut inputs_and_outputs_atomic = vec![];
    // Track how many witness digital decompositions we've seen so far (for
    // associating the digit witnesses with the original witnesses).
    let mut witness_dd_counter = 0;
    for (lh, rh, _output) in inputs_and_outputs {
        let lh_atoms: Box<dyn Iterator<Item = ConstantOrR1CSWitness>> = match lh {
            ConstantOrR1CSWitness::Witness(_) => {
                let counter = witness_dd_counter;
                let r#struct = &dd_struct;

                witness_dd_counter += 1;

                Box::new(
                    (0..NUM_DIGITS)
                        .map(move |digit_place| {
                            r#struct.get_digit_witness_index(digit_place, counter)
                        })
                        .map(ConstantOrR1CSWitness::Witness),
                )
            }
            ConstantOrR1CSWitness::Constant(value) => Box::new(
                decompose_into_digits(value, &log_bases)
                    .into_iter()
                    .map(ConstantOrR1CSWitness::Constant),
            ),
        };
        let rh_atoms: Box<dyn Iterator<Item = ConstantOrR1CSWitness>> = match rh {
            ConstantOrR1CSWitness::Witness(_) => {
                let counter = witness_dd_counter;
                let r#struct = &dd_struct;

                witness_dd_counter += 1;

                Box::new(
                    (0..NUM_DIGITS)
                        .map(move |digit_place| {
                            r#struct.get_digit_witness_index(digit_place, counter)
                        })
                        .map(ConstantOrR1CSWitness::Witness),
                )
            }
            ConstantOrR1CSWitness::Constant(value) => Box::new(
                decompose_into_digits(value, &log_bases)
                    .into_iter()
                    .map(ConstantOrR1CSWitness::Constant),
            ),
        };
        let output_atoms = {
            let counter = witness_dd_counter;
            let dd = &dd_struct;
            (0..NUM_DIGITS).map(move |digit_place| dd.get_digit_witness_index(digit_place, counter))
        };
        witness_dd_counter += 1;

        lh_atoms
            .zip(rh_atoms)
            .zip(output_atoms)
            .for_each(|((lh, rh), output)| {
                inputs_and_outputs_atomic.push((lh, rh, output));
            });
    }

    let multiplicities_wb = WitnessBuilder::MultiplicitiesForBinOp(
        r1cs_compiler.num_witnesses(),
        inputs_and_outputs_atomic
            .iter()
            .map(|(lh_operand, rh_operand, _output)| (*lh_operand, *rh_operand))
            .collect(),
    );
    let multiplicities_first_witness = r1cs_compiler.add_witness_builder(multiplicities_wb);

    // Add two verifier challenges for the lookup
    let sz_challenge =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let rs_challenge =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let rs_challenge_sqrd = r1cs_compiler.add_product(rs_challenge, rs_challenge);

    // Calculate the sum, over all invocations of the bin op, of 1 / denominator
    let summands_for_bin_op = inputs_and_outputs_atomic
        .into_iter()
        .map(|(lh, rh, output)| {
            add_lookup_summand(
                r1cs_compiler,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                lh,
                rh,
                ConstantOrR1CSWitness::Witness(output),
            )
        })
        .map(|coeff| SumTerm(None, coeff))
        .collect();
    let sum_for_bin_op = r1cs_compiler.add_sum(summands_for_bin_op);

    // Calculate the sum over all table elements of multiplicity / denominator
    let summands_for_table = (0..1 << BINOP_ATOMIC_BITS)
        .flat_map(|lh_operand: u32| {
            (0..1 << BINOP_ATOMIC_BITS).map(move |rh_operand: u32| {
                let output = match op {
                    BinOp::And => lh_operand & rh_operand,
                    BinOp::Xor => lh_operand ^ rh_operand,
                };
                (lh_operand, rh_operand, output)
            })
        })
        .map(|(lh_operand, rh_operand, output)| {
            let denominator = add_lookup_summand(
                r1cs_compiler,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                ConstantOrR1CSWitness::Constant(FieldElement::from(lh_operand)),
                ConstantOrR1CSWitness::Constant(FieldElement::from(rh_operand)),
                ConstantOrR1CSWitness::Constant(FieldElement::from(output)),
            );
            let multiplicity_witness_idx = multiplicities_first_witness
                + (lh_operand << BINOP_ATOMIC_BITS) as usize
                + rh_operand as usize;
            r1cs_compiler.add_product(multiplicity_witness_idx, denominator)
        })
        .map(|coeff| SumTerm(None, coeff))
        .collect();
    let sum_for_table = r1cs_compiler.add_sum(summands_for_table);

    // Check that these two sums are equal.
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), sum_for_bin_op)],
        &[(FieldElement::one(), sum_for_table)],
    );
}

// Add and return a new witness `denominator` and constrain it to represent
// (assuming `output` is a witness):
// `w[sz_challenge] - (w[lh_operand] + w[rs_challenge] * w[rh_operand] +
// w[rs_challenge_sqrd] * w[output])` where `w` is the witness vector. If
// `output` is a constant, then the `rs_challenge_sqrd` is instead scaled by
// that constant. Finally, adds a new witness for the inverse of `denominator`,
// constrains it to be such, and returns its index.
fn add_lookup_summand(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    sz_challenge: usize,
    rs_challenge: usize,
    rs_challenge_sqrd: usize,
    lh_operand: ConstantOrR1CSWitness,
    rh_operand: ConstantOrR1CSWitness,
    output: ConstantOrR1CSWitness,
) -> usize {
    let wb = WitnessBuilder::BinOpLookupDenominator(
        r1cs_compiler.num_witnesses(),
        sz_challenge,
        rs_challenge,
        rs_challenge_sqrd,
        lh_operand,
        rh_operand,
        output,
    );
    let denominator = r1cs_compiler.add_witness_builder(wb);
    // Add an intermediate witness if the output is a witness (otherwise can just
    // scale)
    let rs_challenge_sqrd_summand = match output {
        ConstantOrR1CSWitness::Constant(value) => (FieldElement::from(value), rs_challenge_sqrd),
        ConstantOrR1CSWitness::Witness(witness) => (
            FieldElement::one(),
            r1cs_compiler.add_product(rs_challenge_sqrd, witness),
        ),
    };
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one().neg(), rs_challenge)],
        &[rh_operand.to_tuple()],
        &[
            (FieldElement::one(), denominator),
            (FieldElement::one().neg(), sz_challenge),
            (lh_operand.to_tuple()),
            rs_challenge_sqrd_summand,
        ],
    );
    let inverse = r1cs_compiler.add_witness_builder(WitnessBuilder::Inverse(
        r1cs_compiler.num_witnesses(),
        denominator,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), inverse)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
    );
    inverse
}
