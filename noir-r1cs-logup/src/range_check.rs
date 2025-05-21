use {
    crate::{
        compiler::R1CS,
        digits::{add_digital_decomposition, DigitalDecompositionWitnesses},
        solver::WitnessBuilder,
    },
    acir::{AcirField, FieldElement},
    std::{collections::BTreeMap, ops::Neg},
};

const NUM_WITNESS_THRESHOLD_FOR_LOOKUP_TABLE: usize = 5;
pub const NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP: u32 = 8;

/// Add witnesses and constraints that ensure that the values of the witness
/// belong to a range 0..2^k (for some k). If k is larger than
/// `NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP`, then a digital decomposition is
/// performed: witnesses are allocated for the digits of the decomposition, a
/// constraint is added that enforces the correctness of the digital
/// decomposition, and then the digits themselves are range checked.
/// `range_checks` is a map from the number of bits k to the vector of witness
/// indices that are to be constrained within the range [0..2^k].
pub(crate) fn add_range_checks(r1cs: &mut R1CS, range_checks: BTreeMap<u32, Vec<usize>>) {
    // Do a pass through everything that needs to be range checked,
    // decomposing each value into digits that are at most
    // [NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP] and creating a map
    // `atomic_range_blocks` of each `num_bits` from 1 to the
    // NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP (inclusive) to the vec of witness
    // indices that are constrained to that range.

    // Mapping the log of the range size k to the vector of witness indices that
    // are to be constrained within the range [0..2^k].
    // The witnesses of all small range op codes are added to this map, along with
    // witnesses of digits for digital decompositions of larger range checks.
    let mut atomic_range_checks: Vec<Vec<Vec<usize>>> =
        vec![vec![vec![]]; NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP as usize + 1];

    range_checks
        .into_iter()
        .for_each(|(num_bits, values_to_lookup)| {
            if num_bits > NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP {
                let num_big_digits = num_bits / NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP;
                let logbase_of_remainder_digit = num_bits % NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP;
                let mut log_bases =
                    vec![NUM_BITS_THRESHOLD_FOR_DIGITAL_DECOMP as usize; num_big_digits as usize];
                if logbase_of_remainder_digit != 0 {
                    log_bases.push(logbase_of_remainder_digit as usize);
                }
                let dd_struct =
                    add_digital_decomposition(r1cs, log_bases.clone(), values_to_lookup.clone());

                // Add the witness indices for the digits to the atomic range checks
                dd_struct
                    .digit_ranges()
                    .into_iter()
                    .for_each(|(log_base, digit_witnesses)| {
                        atomic_range_checks[log_base as usize].push(digit_witnesses);
                    });
            } else {
                atomic_range_checks[num_bits as usize].push(values_to_lookup);
            }
        });

    // For each of the atomic range checks, add the range check constraints.
    // Use logup if the range is large; otherwise use a naive range check.
    atomic_range_checks
        .iter()
        .enumerate()
        .for_each(|(num_bits, all_values_to_lookup)| {
            let values_to_lookup = all_values_to_lookup
                .iter()
                .flat_map(|v| v.iter())
                .copied()
                .collect::<Vec<_>>();
            if values_to_lookup.len() > NUM_WITNESS_THRESHOLD_FOR_LOOKUP_TABLE {
                add_range_check_via_lookup(r1cs, num_bits as u32, &values_to_lookup);
            } else {
                values_to_lookup.iter().for_each(|value| {
                    add_naive_range_check(r1cs, num_bits as u32, *value);
                })
            }
        });
}

/// Helper function which computes all the terms of the summation for
/// each side (LHS and RHS) of the log-derivative multiset check.
///
/// Checks that both sums (LHS and RHS) are equal at the end.
fn add_range_check_via_lookup(r1cs: &mut R1CS, num_bits: u32, values_to_lookup: &[usize]) {
    // Add witnesses for the multiplicities
    let wb = WitnessBuilder::MultiplicitiesForRange(
        r1cs.num_witnesses(),
        1 << num_bits,
        values_to_lookup.into(),
    );
    let multiplicities_first_witness = r1cs.add_witness_builder(wb);
    // Sample the Schwartz-Zippel challenge for the log derivative
    // multiset check.
    let sz_challenge = r1cs.add_witness_builder(WitnessBuilder::Challenge(r1cs.num_witnesses()));

    // Compute all the terms in the summation for multiplicity/(X - table_value)
    // for each table value.
    let table_summands = (0..(1 << num_bits))
        .map(|table_value| {
            let table_denom = add_lookup_factor(
                r1cs,
                sz_challenge,
                FieldElement::from(table_value),
                r1cs.witness_one(),
            );
            let multiplicity_witness = multiplicities_first_witness + table_value;
            (None, r1cs.add_product(table_denom, multiplicity_witness))
        })
        .collect();
    let sum_for_table = r1cs.add_sum(table_summands);
    // Compute all the terms in the summation for 1/(X - witness_value) for each
    // witness value.
    let witness_summands = values_to_lookup
        .iter()
        .map(|value| {
            let witness_idx = add_lookup_factor(r1cs, sz_challenge, FieldElement::one(), *value);
            (None, witness_idx)
        })
        .collect();
    let sum_for_witness = r1cs.add_sum(witness_summands);
    // Check that these two sums are equal.
    r1cs.matrices.add_constraint(
        &[
            (FieldElement::one(), sum_for_table),
            (FieldElement::one().neg(), sum_for_witness),
        ],
        &[(FieldElement::one(), r1cs.witness_one())],
        &[(FieldElement::zero(), r1cs.witness_one())],
    );
}

/// Helper function that computes the LogUp denominator either for
/// the table values: (X - t_j), or for the witness values:
/// (X - w_i). Computes the inverse and also checks that this is
/// the appropriate inverse.
pub(crate) fn add_lookup_factor(
    r1cs: &mut R1CS,
    sz_challenge: usize,
    value_coeff: FieldElement,
    value_witness: usize,
) -> usize {
    let denom_wb = WitnessBuilder::LogUpDenominator(
        r1cs.num_witnesses(),
        sz_challenge,
        (value_coeff, value_witness),
    );
    let denominator = r1cs.add_witness_builder(denom_wb);
    r1cs.matrices.add_constraint(
        &[
            (FieldElement::one(), sz_challenge),
            (FieldElement::one().neg() * value_coeff, value_witness),
        ],
        &[(FieldElement::one(), r1cs.witness_one())],
        &[(FieldElement::one(), denominator)],
    );
    let inverse =
        r1cs.add_witness_builder(WitnessBuilder::Inverse(r1cs.num_witnesses(), denominator));
    r1cs.matrices.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), inverse)],
        &[(FieldElement::one(), r1cs.witness_one())],
    );
    inverse
}

/// A naive range check helper function, computing the
/// $\prod_{i = 0}^{range}(a - i) = 0$ to check whether a witness found at
/// `index_witness`, which is $a$, is in the $range$, which is `num_bits`.
fn add_naive_range_check(r1cs: &mut R1CS, num_bits: u32, index_witness: usize) {
    let mut current_product_witness = index_witness;
    (1..(1 << num_bits) - 1).for_each(|index: u32| {
        let next_product_witness =
            r1cs.add_witness_builder(WitnessBuilder::ProductLinearOperation(
                r1cs.num_witnesses(),
                (
                    current_product_witness,
                    FieldElement::one(),
                    FieldElement::zero(),
                ),
                (
                    index_witness,
                    FieldElement::one(),
                    FieldElement::from(index).neg(),
                ),
            ));
        r1cs.matrices.add_constraint(
            &[(FieldElement::one(), current_product_witness)],
            &[
                (FieldElement::one(), index_witness),
                (FieldElement::from(index).neg(), r1cs.witness_one()),
            ],
            &[(FieldElement::one(), next_product_witness)],
        );
        current_product_witness = next_product_witness;
    });

    r1cs.matrices.add_constraint(
        &[(FieldElement::one(), current_product_witness)],
        &[
            (FieldElement::one(), index_witness),
            (
                FieldElement::from((1 << num_bits) - 1 as u32).neg(),
                r1cs.witness_one(),
            ),
        ],
        &[(FieldElement::zero(), r1cs.witness_one())],
    );
}
