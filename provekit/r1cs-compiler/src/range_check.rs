use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_std::{One, Zero},
    provekit_common::{
        witness::{ProductLinearTerm, WitnessBuilder, WitnessCoefficient},
        FieldElement,
    },
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
pub(crate) fn add_range_checks(
    r1cs: &mut NoirToR1CSCompiler,
    range_checks: BTreeMap<u32, Vec<usize>>,
) {
    if range_checks.is_empty() {
        return;
    }

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
                let dd_struct = add_digital_decomposition(r1cs, log_bases, values_to_lookup);

                // Add the witness indices for the digits to the atomic range checks
                dd_struct
                    .log_bases
                    .iter()
                    .enumerate()
                    .map(|(digit_place, log_base)| {
                        (
                            *log_base as u32,
                            (0..dd_struct.num_witnesses_to_decompose)
                                .map(|i| dd_struct.get_digit_witness_index(digit_place, i))
                                .collect::<Vec<_>>(),
                        )
                    })
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
/// Uses a fused constraint to check equality of both sums directly.
fn add_range_check_via_lookup(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    num_bits: u32,
    values_to_lookup: &[usize],
) {
    // Add witnesses for the multiplicities
    let wb = WitnessBuilder::MultiplicitiesForRange(
        r1cs_compiler.num_witnesses(),
        1 << num_bits,
        values_to_lookup.into(),
    );
    let multiplicities_first_witness = r1cs_compiler.add_witness_builder(wb);
    // Sample the Schwartz-Zippel challenge for the log derivative
    // multiset check.
    let sz_challenge =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));

    // Collect table side terms: multiplicity * 1/(X - table_value)
    let mut fused_terms: Vec<(FieldElement, usize)> = (0..(1 << num_bits))
        .map(|table_value| {
            let table_denom = add_lookup_factor(
                r1cs_compiler,
                sz_challenge,
                FieldElement::from(table_value as u64),
                r1cs_compiler.witness_one(),
            );
            let multiplicity_witness = multiplicities_first_witness + table_value;
            (
                FieldElement::one(),
                r1cs_compiler.add_product(table_denom, multiplicity_witness),
            )
        })
        .collect();

    // Collect witness side terms with negated coefficients: -1/(X - witness_value)
    for value in values_to_lookup {
        let witness_idx =
            add_lookup_factor(r1cs_compiler, sz_challenge, FieldElement::one(), *value);
        fused_terms.push((FieldElement::one().neg(), witness_idx));
    }

    // Single fused constraint: (Σ table_terms - Σ witness_terms) * 1 = 0
    r1cs_compiler.r1cs.add_constraint(
        &fused_terms,
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::zero(), r1cs_compiler.witness_one())],
    );
}

/// Helper function that computes the inverse of the LogUp denominator
/// for table values: 1/(X - t_j), or for witness values: 1/(X - w_i).
/// Uses a single fused constraint to verify the inverse.
pub(crate) fn add_lookup_factor(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    sz_challenge: usize,
    value_coeff: FieldElement,
    value_witness: usize,
) -> usize {
    // Directly compute inverse of (X - c·v) using LogUpInverse
    let inverse = r1cs_compiler.add_witness_builder(WitnessBuilder::LogUpInverse(
        r1cs_compiler.num_witnesses(),
        sz_challenge,
        WitnessCoefficient(value_coeff, value_witness),
    ));
    // Single fused constraint: (X - c·v) * inverse = 1
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), sz_challenge),
            (FieldElement::one().neg() * value_coeff, value_witness),
        ],
        &[(FieldElement::one(), inverse)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
    );
    inverse
}

/// A naive range check helper function, computing the
/// $\prod_{i = 0}^{range}(a - i) = 0$ to check whether a witness found at
/// `index_witness`, which is $a$, is in the $range$, which is `num_bits`.
fn add_naive_range_check(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    num_bits: u32,
    index_witness: usize,
) {
    let mut current_product_witness = index_witness;
    (1..(1 << num_bits) - 1).for_each(|index: u32| {
        let next_product_witness =
            r1cs_compiler.add_witness_builder(WitnessBuilder::ProductLinearOperation(
                r1cs_compiler.num_witnesses(),
                ProductLinearTerm(
                    current_product_witness,
                    FieldElement::one(),
                    FieldElement::zero(),
                ),
                ProductLinearTerm(
                    index_witness,
                    FieldElement::one(),
                    FieldElement::from(index).neg(),
                ),
            ));
        r1cs_compiler.r1cs.add_constraint(
            &[(FieldElement::one(), current_product_witness)],
            &[
                (FieldElement::one(), index_witness),
                (FieldElement::from(index).neg(), r1cs_compiler.witness_one()),
            ],
            &[(FieldElement::one(), next_product_witness)],
        );
        current_product_witness = next_product_witness;
    });

    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), current_product_witness)],
        &[
            (FieldElement::one(), index_witness),
            (
                FieldElement::from((1 << num_bits) - 1_u32).neg(),
                r1cs_compiler.witness_one(),
            ),
        ],
        &[(FieldElement::zero(), r1cs_compiler.witness_one())],
    );
}
