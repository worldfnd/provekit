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
    std::{
        collections::{BTreeMap, HashSet},
        ops::Neg,
    },
};

/// Minimum base width to consider during optimization.
const MIN_BASE_WIDTH: u32 = 2;

/// Maximum base width to consider during optimization. Beyond 17 bits
/// the table side alone (2^18+ entries) always exceeds the cost of
/// decomposing into smaller digits.
const MAX_BASE_WIDTH: u32 = 17;

/// A single range check request: a witness that must be in [0, 2^bits).
struct RangeCheckRequest {
    witness_idx: usize,
    bits:        u32,
}

/// Returns the constraint cost for a single atomic bucket of `num_bits`-wide
/// checks containing `count` witnesses, choosing whichever strategy (LogUp
/// or naive) is cheaper. Returns `usize::MAX` for impractically large bit
/// widths where the table would overflow.
fn bucket_cost(num_bits: u32, count: usize) -> usize {
    if count == 0 || num_bits == 0 {
        return 0;
    }
    // Guard against overflow: a table of 2^num_bits entries is impractical
    // for large bit widths. usize is at least 32 bits wide, but even
    // 2^30 entries would be enormous; cap at (usize::BITS - 2) to avoid
    // overflow in the arithmetic below.
    if num_bits >= (usize::BITS - 1) {
        return usize::MAX;
    }
    let table_size = 1usize << num_bits;
    // LogUp cost: 2^bits (table fused constraints)
    //           + count  (witness inverse constraints)
    //           + 1      (grand sum check)
    let logup_cost = table_size.saturating_add(count).saturating_add(1);
    // Naive cost: (2^bits - 1) constraints per witness
    let naive_cost = count.saturating_mul(table_size - 1);
    logup_cost.min(naive_cost)
}

/// Calculates the total R1CS constraint cost for a given `base_width`.
///
/// For each request with `bits > base_width`, a digital decomposition is
/// performed (1 recomposition constraint per witness). The resulting digits
/// are bucketed by their bit width. Each bucket's cost is the cheaper of
/// LogUp lookup and naive product checks.
fn calculate_constraint_cost(base_width: u32, collected: &[RangeCheckRequest]) -> usize {
    let mut decomposition_constraints: usize = 0;
    let mut atomic_buckets: BTreeMap<u32, usize> = BTreeMap::new();

    for check in collected {
        if check.bits <= base_width {
            // No decomposition needed; goes directly to atomic bucket.
            *atomic_buckets.entry(check.bits).or_default() += 1;
        } else {
            // Decomposition: 1 recomposition constraint per witness.
            decomposition_constraints += 1;

            let num_full_digits = check.bits / base_width;
            let remainder = check.bits % base_width;

            *atomic_buckets.entry(base_width).or_default() += num_full_digits as usize;
            if remainder > 0 {
                *atomic_buckets.entry(remainder).or_default() += 1;
            }
        }
    }

    let mut total = decomposition_constraints;
    for (&num_bits, &count) in &atomic_buckets {
        total = total.saturating_add(bucket_cost(num_bits, count));
    }
    total
}

/// Finds the base width that minimizes the total R1CS constraint count for
/// the given set of range check requests.
///
/// Searches widths from [MIN_BASE_WIDTH, MAX_BASE_WIDTH]. Base widths
/// above 17 are never beneficial because the table side alone would
/// require 2^18+ constraints, which always exceeds the cost of
/// decomposing into smaller digits.
fn get_optimal_base_width(collected: &[RangeCheckRequest]) -> u32 {
    let mut min_cost = usize::MAX;
    let mut optimal_width = 8u32;

    for base_width in MIN_BASE_WIDTH..=MAX_BASE_WIDTH {
        let cost = calculate_constraint_cost(base_width, collected);
        if cost < min_cost {
            min_cost = cost;
            optimal_width = base_width;
        }
    }

    optimal_width
}

/// Add witnesses and constraints that ensure that the values of the witness
/// belong to a range 0..2^k (for some k).
///
/// Uses dynamic base width optimization: all range check requests are
/// collected, and the optimal decomposition base width is determined by
/// minimizing the total R1CS constraint cost. The search evaluates every
/// base width from [MIN_BASE_WIDTH] to [MAX_BASE_WIDTH]. For each
/// candidate, the cost model picks the cheaper of LogUp and naive for
/// every atomic bucket.
///
/// Values with bit widths larger than the chosen base are digitally
/// decomposed; the resulting digits (and values already ≤ the base) are then
/// range checked via LogUp lookup or naive product checks, whichever is
/// cheaper per bucket.
///
/// `range_checks` is a map from the number of bits k to the vector of
/// witness indices that are to be constrained within the range [0..2^k].
pub(crate) fn add_range_checks(
    r1cs: &mut NoirToR1CSCompiler,
    range_checks: BTreeMap<u32, Vec<usize>>,
) {
    if range_checks.is_empty() {
        return;
    }

    // Phase 1: Flatten all range checks into individual requests and
    // deduplicate per bit-width group.
    let collected: Vec<RangeCheckRequest> = range_checks
        .into_iter()
        .flat_map(|(num_bits, values)| {
            let mut seen = HashSet::new();
            values
                .into_iter()
                .filter(move |v| seen.insert(*v))
                .map(move |witness_idx| RangeCheckRequest {
                    witness_idx,
                    bits: num_bits,
                })
        })
        .collect();

    if collected.is_empty() {
        return;
    }

    // Phase 2: Find the optimal base width that minimizes total constraint
    // cost.
    let base_width = get_optimal_base_width(&collected);

    // Phase 3: Decompose values larger than base_width and collect atomic
    // range check buckets.
    let max_bucket = base_width as usize + 1;
    let mut atomic_range_checks: Vec<Vec<Vec<usize>>> = vec![vec![vec![]]; max_bucket];

    // Group collected requests by bit width for batch decomposition.
    let mut by_bits: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for req in &collected {
        by_bits.entry(req.bits).or_default().push(req.witness_idx);
    }

    for (num_bits, values_to_lookup) in by_bits {
        if num_bits > base_width {
            let num_full_digits = num_bits / base_width;
            let remainder = num_bits % base_width;
            let mut log_bases = vec![base_width as usize; num_full_digits as usize];
            if remainder > 0 {
                log_bases.push(remainder as usize);
            }
            let dd_struct = add_digital_decomposition(r1cs, log_bases, values_to_lookup);

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
    }

    // Phase 4: For each atomic bucket, add range check constraints.
    // Choose LogUp or naive based on whichever produces fewer constraints.
    atomic_range_checks
        .iter()
        .enumerate()
        .for_each(|(num_bits, all_values_to_lookup)| {
            // Deduplicate across digit groups.
            let values_to_lookup: Vec<usize> = {
                let mut seen = HashSet::new();
                all_values_to_lookup
                    .iter()
                    .flat_map(|v| v.iter())
                    .copied()
                    .filter(|v| seen.insert(*v))
                    .collect()
            };
            if values_to_lookup.is_empty() {
                return;
            }
            let num_bits = num_bits as u32;
            let count = values_to_lookup.len();
            let table_size = 1usize << num_bits;
            let logup_cost = table_size + count + 1;
            let naive_cost = count.saturating_mul(table_size - 1);
            if logup_cost < naive_cost {
                add_range_check_via_lookup(r1cs, num_bits, &values_to_lookup);
            } else {
                values_to_lookup.iter().for_each(|value| {
                    add_naive_range_check(r1cs, num_bits, *value);
                })
            }
        });
}

/// Helper function which computes all the terms of the summation for
/// each side (LHS and RHS) of the log-derivative multiset check.
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

    // Collect table side terms: multiplicity / (X - table_value)
    // Uses fused single constraint: (X - table_value) × quotient = multiplicity
    // instead of two constraints (inverse + product).
    let mut logup_summands: Vec<(FieldElement, usize)> = (0..(1 << num_bits))
        .map(|table_value| {
            let multiplicity_witness = multiplicities_first_witness + table_value;
            (
                FieldElement::one(),
                add_range_table_entry_quotient(
                    r1cs_compiler,
                    sz_challenge,
                    table_value as u64,
                    multiplicity_witness,
                ),
            )
        })
        .collect();

    // Collect witness side terms with negated coefficients: -1/(X - witness_value)
    for value in values_to_lookup {
        let witness_idx =
            add_lookup_factor(r1cs_compiler, sz_challenge, FieldElement::one(), *value);
        logup_summands.push((FieldElement::one().neg(), witness_idx));
    }

    // Constraint: (Σ table_terms - Σ witness_terms) * 1 = 0
    r1cs_compiler.r1cs.add_constraint(
        &logup_summands,
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
            (value_coeff.neg(), value_witness),
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

/// Computes quotient = multiplicity / (X - table_value) using a single R1CS
/// constraint: (X - table_value) × quotient = multiplicity.
///
/// Internally creates an inverse witness (for batch inversion) and a product
/// witness (inverse × multiplicity), but only emits one constraint instead
/// of the usual two (inverse constraint + product constraint).
fn add_range_table_entry_quotient(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    sz_challenge: usize,
    table_value: u64,
    multiplicity_witness: usize,
) -> usize {
    // Step 1: Create inverse witness 1/(X - table_value) for batch inversion
    let inverse = r1cs_compiler.add_witness_builder(WitnessBuilder::LogUpInverse(
        r1cs_compiler.num_witnesses(),
        sz_challenge,
        WitnessCoefficient(FieldElement::from(table_value), r1cs_compiler.witness_one()),
    ));

    // Step 2: Create product witness (multiplicity * inverse = quotient)
    // Note: we do NOT call add_product() because that would add a constraint.
    let quotient = r1cs_compiler.add_witness_builder(WitnessBuilder::Product(
        r1cs_compiler.num_witnesses(),
        multiplicity_witness,
        inverse,
    ));

    // Step 3: Single constraint: (X - table_value) × quotient = multiplicity
    // This replaces two constraints: (X - table_value) × inverse = 1 and
    // inverse × multiplicity = quotient.
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), sz_challenge),
            (
                FieldElement::from(table_value).neg(),
                r1cs_compiler.witness_one(),
            ),
        ],
        &[(FieldElement::one(), quotient)],
        &[(FieldElement::one(), multiplicity_witness)],
    );

    quotient
}
