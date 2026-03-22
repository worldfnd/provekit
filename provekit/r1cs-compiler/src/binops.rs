use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
        uints::U8,
    },
    ark_ff::PrimeField,
    ark_std::One,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        ops::Neg,
    },
};

#[derive(Clone, Debug, Copy)]
pub enum BinOp {
    And,
    Xor,
}

struct LookupChallenges {
    sz:       usize,
    rs:       usize,
    rs_sqrd:  usize,
    rs_cubed: usize,
}

type PairMapEntry = (
    Option<usize>,
    Option<usize>,
    ConstantOrR1CSWitness,
    ConstantOrR1CSWitness,
);
/// Calculates the total witness cost for a given atomic bit-width `w`.
///
/// The formula accounts for:
/// - Table: 3 witnesses per entry (multiplicity + inverse + quotient) with
///   2^(2w) entries.
/// - Per digit-pair query: 4 witnesses (denominator + rs²·and product
///   + rs³·xor product + inverse).
/// - Decomposition: when w < 8, each byte-level op requires decomposing 4 byte
///   witnesses (lhs, rhs, and_out, xor_out) into ceil(8/w) digits.
/// - Complementary: worst case one per op (missing AND or XOR).
/// - Overhead: 4 challenges (sz, rs, rs², rs³) + 2 grand sum witnesses.
fn calculate_binop_witness_cost(w: u32, n: usize) -> usize {
    assert!(
        matches!(w, 2 | 4 | 8),
        "width must be in {{2, 4, 8}} to evenly divide 8, got {w}"
    );
    let d = 8u32.div_ceil(w) as usize;
    let table = 3 * (1usize << (2 * w));
    let queries = 4 * n * d;
    let decomp = if w < 8 { 4 * n * d } else { 0 };
    let complementary = n;
    let overhead = 6;
    table + queries + decomp + complementary + overhead
}

/// Finds the atomic bit-width in {2, 4, 8} that minimizes the total
/// witness count for `n` byte-level binop pairs.
/// (3, 5, 6, 7) need a separate range check on the last chunk to
/// restore byte semantics; once that cost is included, they compute
/// to roughly the same witness count as the dividing widths.
fn get_optimal_binop_width(n: usize) -> u32 {
    [2u32, 4, 8]
        .into_iter()
        .min_by_key(|&w| calculate_binop_witness_cost(w, n))
        .unwrap()
}

/// Extracts the digit value of a `ConstantOrR1CSWitness` at a given
/// digit position, using compile-time extraction for constants and
/// the digital decomposition witness for variables.
fn cow_to_digit(
    cow: ConstantOrR1CSWitness,
    digit_i: usize,
    atomic_bits: u32,
    dd: &provekit_common::witness::DigitalDecompositionWitnesses,
    witness_to_offset: &HashMap<usize, usize>,
) -> ConstantOrR1CSWitness {
    match cow {
        ConstantOrR1CSWitness::Constant(c) => {
            let val = c.into_bigint().0[0];
            let digit =
                (val >> (digit_i as u64 * atomic_bits as u64)) & ((1u64 << atomic_bits) - 1);
            ConstantOrR1CSWitness::Constant(FieldElement::from(digit))
        }
        ConstantOrR1CSWitness::Witness(w) => {
            let offset = witness_to_offset[&w];
            ConstantOrR1CSWitness::Witness(dd.get_digit_witness_index(digit_i, offset))
        }
    }
}

/// Allocate a witness for a byte-level binary operation (AND / XOR).
/// This path performs the operation directly at the byte level,
/// without any digital decomposition.
pub(crate) fn add_byte_binop(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    op: BinOp,
    ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    a: U8,
    b: U8,
) -> U8 {
    debug_assert!(
        a.range_checked && b.range_checked,
        "Byte binop requires inputs to be range-checked U8s"
    );

    let result = match op {
        BinOp::And => r1cs_compiler.add_witness_builder(WitnessBuilder::And(
            r1cs_compiler.num_witnesses(),
            ConstantOrR1CSWitness::Witness(a.idx),
            ConstantOrR1CSWitness::Witness(b.idx),
        )),
        BinOp::Xor => r1cs_compiler.add_witness_builder(WitnessBuilder::Xor(
            r1cs_compiler.num_witnesses(),
            ConstantOrR1CSWitness::Witness(a.idx),
            ConstantOrR1CSWitness::Witness(b.idx),
        )),
    };

    // Record the operation for batched lookup constraint generation
    ops.push((
        ConstantOrR1CSWitness::Witness(a.idx),
        ConstantOrR1CSWitness::Witness(b.idx),
        result,
    ));

    // Output remains a valid byte since AND/XOR preserve [0, 255]
    U8::new(result, true)
}

/// Add combined AND/XOR lookup constraints using a single table.
///
/// Uses dynamic bit-width optimization: searches widths in {2, 4, 8}
/// to minimize total witness count. When the optimal width is less than
/// 8, byte-level operands are decomposed into smaller digits via
/// `add_digital_decomposition`.
///
/// Table encoding: sz - (lhs + rs*rhs + rs²*and_out + rs³*xor_out)
///
/// For each AND operation, we compute the complementary XOR output.
/// For each XOR operation, we compute the complementary AND output.
///
/// Returns the chosen atomic bit-width, or `None` if no ops were provided.
pub(crate) fn add_combined_binop_constraints(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
) -> Option<u32> {
    if and_ops.is_empty() && xor_ops.is_empty() {
        return None;
    }

    // For combined table, each operation needs both AND and XOR outputs.
    // Convert ops to atomic (byte-level) operations with both outputs.
    // Optimization: If the same (lhs, rhs) pair appears in both AND and XOR ops,
    // we already have both outputs and don't need to create complementary
    // witnesses.

    // Key type that captures the full field element to avoid collisions.
    // Uses all 4 limbs of the BigInt representation for constants.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum OperandKey {
        Witness(usize),
        Constant([u64; 4]),
    }

    fn operand_key(op: &ConstantOrR1CSWitness) -> OperandKey {
        match op {
            ConstantOrR1CSWitness::Witness(idx) => OperandKey::Witness(*idx),
            ConstantOrR1CSWitness::Constant(fe) => OperandKey::Constant(fe.into_bigint().0),
        }
    }

    let mut pair_map: BTreeMap<(OperandKey, OperandKey), PairMapEntry> = BTreeMap::new();

    for (lhs, rhs, and_out) in &and_ops {
        let key = (operand_key(lhs), operand_key(rhs));
        pair_map
            .entry(key)
            .and_modify(|e| {
                if let Some(existing) = e.0 {
                    // Duplicate AND for same inputs — constrain
                    // equality so the earlier result stays sound.
                    r1cs_compiler.r1cs.add_constraint(
                        &[(FieldElement::one(), existing)],
                        &[(FieldElement::one(), r1cs_compiler.witness_one())],
                        &[(FieldElement::one(), *and_out)],
                    );
                }
                e.0 = Some(*and_out);
            })
            .or_insert((Some(*and_out), None, *lhs, *rhs));
    }

    for (lhs, rhs, xor_out) in &xor_ops {
        let key = (operand_key(lhs), operand_key(rhs));
        pair_map
            .entry(key)
            .and_modify(|e| {
                if let Some(existing) = e.1 {
                    // Duplicate XOR for same inputs — constrain
                    // equality so the earlier result stays sound.
                    r1cs_compiler.r1cs.add_constraint(
                        &[(FieldElement::one(), existing)],
                        &[(FieldElement::one(), r1cs_compiler.witness_one())],
                        &[(FieldElement::one(), *xor_out)],
                    );
                }
                e.1 = Some(*xor_out);
            })
            .or_insert((None, Some(*xor_out), *lhs, *rhs));
    }

    // Now build combined ops, creating complementary witnesses only when needed
    let mut combined_ops_atomic = Vec::with_capacity(pair_map.len());
    for (_key, (and_opt, xor_opt, lhs, rhs)) in pair_map {
        let and_out = and_opt.unwrap_or_else(|| {
            r1cs_compiler.add_witness_builder(WitnessBuilder::And(
                r1cs_compiler.num_witnesses(),
                lhs,
                rhs,
            ))
        });
        let xor_out = xor_opt.unwrap_or_else(|| {
            r1cs_compiler.add_witness_builder(WitnessBuilder::Xor(
                r1cs_compiler.num_witnesses(),
                lhs,
                rhs,
            ))
        });
        combined_ops_atomic.push((lhs, rhs, and_out, xor_out));
    }

    // Choose optimal atomic bit-width based on witness cost model.
    let atomic_bits = get_optimal_binop_width(combined_ops_atomic.len());

    // Build lookup operations: either byte-level (w=8) or digit-level (w<8).
    let lookup_ops: Vec<(
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
    )> = if atomic_bits == 8 {
        // No decomposition needed — use byte-level ops directly.
        combined_ops_atomic
            .iter()
            .map(|(lhs, rhs, and_out, xor_out)| {
                (
                    *lhs,
                    *rhs,
                    ConstantOrR1CSWitness::Witness(*and_out),
                    ConstantOrR1CSWitness::Witness(*xor_out),
                )
            })
            .collect()
    } else {
        // Decompose byte-level operands into w-bit digits.
        let d = 8u32.div_ceil(atomic_bits) as usize;
        let log_bases = vec![atomic_bits as usize; d];

        // Collect all unique witness byte indices that need decomposition.
        let mut witness_set: BTreeSet<usize> = BTreeSet::new();
        for (lhs, rhs, and_out, xor_out) in &combined_ops_atomic {
            if let ConstantOrR1CSWitness::Witness(w) = lhs {
                witness_set.insert(*w);
            }
            if let ConstantOrR1CSWitness::Witness(w) = rhs {
                witness_set.insert(*w);
            }
            witness_set.insert(*and_out);
            witness_set.insert(*xor_out);
        }
        let witness_bytes: Vec<usize> = witness_set.into_iter().collect();
        let witness_to_offset: HashMap<usize, usize> = witness_bytes
            .iter()
            .enumerate()
            .map(|(i, &w)| (w, i))
            .collect();

        // Create digit witnesses + recomposition constraints.
        // Range checks are provided by the table lookup itself.
        let dd = add_digital_decomposition(r1cs_compiler, log_bases, witness_bytes);

        // Build digit-level lookup operations.
        let mut digit_ops = Vec::with_capacity(combined_ops_atomic.len() * d);
        for (lhs, rhs, and_out, xor_out) in &combined_ops_atomic {
            for digit_i in 0..d {
                let lhs_digit = cow_to_digit(*lhs, digit_i, atomic_bits, &dd, &witness_to_offset);
                let rhs_digit = cow_to_digit(*rhs, digit_i, atomic_bits, &dd, &witness_to_offset);
                let and_digit = ConstantOrR1CSWitness::Witness(
                    dd.get_digit_witness_index(digit_i, witness_to_offset[and_out]),
                );
                let xor_digit = ConstantOrR1CSWitness::Witness(
                    dd.get_digit_witness_index(digit_i, witness_to_offset[xor_out]),
                );
                digit_ops.push((lhs_digit, rhs_digit, and_digit, xor_digit));
            }
        }
        digit_ops
    };

    // Build multiplicities for the combined table (2^(2*atomic_bits) entries).
    let multiplicities_wb = WitnessBuilder::MultiplicitiesForBinOp(
        r1cs_compiler.num_witnesses(),
        atomic_bits,
        lookup_ops.iter().map(|(lh, rh, ..)| (*lh, *rh)).collect(),
    );
    let multiplicities_first_witness = r1cs_compiler.add_witness_builder(multiplicities_wb);

    let sz =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let rs =
        r1cs_compiler.add_witness_builder(WitnessBuilder::Challenge(r1cs_compiler.num_witnesses()));
    let rs_sqrd = r1cs_compiler.add_product(rs, rs);
    let rs_cubed = r1cs_compiler.add_product(rs_sqrd, rs);
    let challenges = LookupChallenges {
        sz,
        rs,
        rs_sqrd,
        rs_cubed,
    };

    let summands_for_ops = lookup_ops
        .into_iter()
        .map(|(lhs, rhs, and_out, xor_out)| {
            add_combined_lookup_summand(r1cs_compiler, &challenges, lhs, rhs, and_out, xor_out)
        })
        .map(|coeff| SumTerm(None, coeff))
        .collect();
    let sum_for_ops = r1cs_compiler.add_sum(summands_for_ops);

    let summands_for_table = (0..1u32 << atomic_bits)
        .flat_map(|lhs| (0..1u32 << atomic_bits).map(move |rhs| (lhs, rhs, lhs & rhs, lhs ^ rhs)))
        .map(|(lhs, rhs, and_out, xor_out)| {
            let multiplicity_idx =
                multiplicities_first_witness + ((lhs << atomic_bits) as usize) + rhs as usize;
            add_table_entry_quotient(
                r1cs_compiler,
                &challenges,
                lhs,
                rhs,
                and_out,
                xor_out,
                multiplicity_idx,
            )
        })
        .map(|quotient| SumTerm(None, quotient))
        .collect();
    let sum_for_table = r1cs_compiler.add_sum(summands_for_table);

    // Check equality
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), sum_for_ops)],
        &[(FieldElement::one(), sum_for_table)],
    );

    Some(atomic_bits)
}

/// Computes quotient = multiplicity / (sz - lhs - rs*rhs - rs²*and_out -
/// rs³*xor_out) using a single R1CS constraint: denominator × quotient =
/// multiplicity.
///
/// Internally creates an inverse witness (for batch inversion) and a product
/// witness (inverse × multiplicity), but only emits one constraint instead
/// of the usual two (inverse constraint + product constraint).
fn add_table_entry_quotient(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    c: &LookupChallenges,
    lhs: u32,
    rhs: u32,
    and_out: u32,
    xor_out: u32,
    multiplicity_witness: usize,
) -> usize {
    use provekit_common::witness::CombinedTableEntryInverseData;

    // Step 1: Create inverse witness (1/denominator) for batch inversion
    let inverse = r1cs_compiler.add_witness_builder(WitnessBuilder::CombinedTableEntryInverse(
        CombinedTableEntryInverseData {
            idx:          r1cs_compiler.num_witnesses(),
            sz_challenge: c.sz,
            rs_challenge: c.rs,
            rs_sqrd:      c.rs_sqrd,
            rs_cubed:     c.rs_cubed,
            lhs:          FieldElement::from(lhs),
            rhs:          FieldElement::from(rhs),
            and_out:      FieldElement::from(and_out),
            xor_out:      FieldElement::from(xor_out),
        },
    ));

    // Step 2: Create product witness (multiplicity * inverse = quotient)
    // Note: we do NOT call add_product() because that would add a constraint.
    let quotient = r1cs_compiler.add_witness_builder(WitnessBuilder::Product(
        r1cs_compiler.num_witnesses(),
        multiplicity_witness,
        inverse,
    ));

    // Step 3: Single constraint: denominator × quotient = multiplicity
    // This replaces two constraints (denominator × inverse = 1) and
    // (multiplicity × inverse = quotient).
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), c.sz),
            (FieldElement::from(lhs).neg(), r1cs_compiler.witness_one()),
            (FieldElement::from(rhs).neg(), c.rs),
            (FieldElement::from(and_out).neg(), c.rs_sqrd),
            (FieldElement::from(xor_out).neg(), c.rs_cubed),
        ],
        &[(FieldElement::one(), quotient)],
        &[(FieldElement::one(), multiplicity_witness)],
    );

    quotient
}

fn add_combined_lookup_summand(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    c: &LookupChallenges,
    lhs: ConstantOrR1CSWitness,
    rhs: ConstantOrR1CSWitness,
    and_out: ConstantOrR1CSWitness,
    xor_out: ConstantOrR1CSWitness,
) -> usize {
    let wb = WitnessBuilder::CombinedBinOpLookupDenominator(
        r1cs_compiler.num_witnesses(),
        c.sz,
        c.rs,
        c.rs_sqrd,
        c.rs_cubed,
        lhs,
        rhs,
        and_out,
        xor_out,
    );
    let denominator = r1cs_compiler.add_witness_builder(wb);

    let rs_sqrd_and_term = match and_out {
        ConstantOrR1CSWitness::Constant(value) => (FieldElement::from(value), c.rs_sqrd),
        ConstantOrR1CSWitness::Witness(witness) => (
            FieldElement::one(),
            r1cs_compiler.add_product(c.rs_sqrd, witness),
        ),
    };

    let rs_cubed_xor_term = match xor_out {
        ConstantOrR1CSWitness::Constant(value) => (FieldElement::from(value), c.rs_cubed),
        ConstantOrR1CSWitness::Witness(witness) => (
            FieldElement::one(),
            r1cs_compiler.add_product(c.rs_cubed, witness),
        ),
    };

    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::one().neg(), c.rs)], &[rhs.to_tuple()], &[
            (FieldElement::one(), denominator),
            (FieldElement::one().neg(), c.sz),
            lhs.to_tuple(),
            rs_sqrd_and_term,
            rs_cubed_xor_term,
        ]);

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

#[cfg(test)]
mod tests {
    use {super::*, crate::digits::add_digital_decomposition};

    /// Check R1CS satisfaction: for every constraint row, (A·w)*(B·w) == C·w.
    fn constraints_satisfied(r1cs: &provekit_common::R1CS, witness: &[FieldElement]) -> bool {
        let a = r1cs.a() * witness;
        let b = r1cs.b() * witness;
        let c = r1cs.c() * witness;
        a.iter()
            .zip(b.iter())
            .zip(c.iter())
            .all(|((av, bv), cv)| *av * *bv == *cv)
    }

    /// Decompose `value` into `d` digits of `w` bits each (little-endian).
    fn decompose(value: u64, w: u32, d: usize) -> Vec<u64> {
        let mask = (1u64 << w) - 1;
        (0..d)
            .map(|i| (value >> (i as u64 * w as u64)) & mask)
            .collect()
    }

    /// `get_optimal_binop_width` must never return a width that does not divide
    /// 8, because non-dividing widths (e.g. 3) cause digit decompositions
    /// that overallocate bit capacity beyond [0, 255], breaking byte
    /// semantics.
    #[test]
    fn optimal_binop_width_always_divides_8() {
        for n in 1..=1024 {
            let w = get_optimal_binop_width(n);
            assert!(
                8 % w == 0,
                "get_optimal_binop_width({n}) returned {w}, which does not divide 8"
            );
        }
    }

    /// Regression test for Issue D: when atomic_bits divides 8, the digital
    /// decomposition recomposition constraint rejects non-canonical byte
    /// values (> 255).
    ///
    /// The recomposition constraint enforces:
    ///     byte = d0 + 2^w * d1 + 2^(2w) * d2 + ... + 2^((d-1)*w) * d_{d-1}
    ///
    /// When w divides 8, d = 8/w digits of w bits each cover exactly 8 bits,
    /// so the maximum representable value with in-range digits is 255. A byte
    /// witness of 256 cannot satisfy this constraint with any valid digit
    /// assignment.
    #[test]
    fn non_canonical_byte_rejected_by_recomposition() {
        // Test for each valid atomic width that decomposes bytes.
        for atomic_bits in [2u32, 4] {
            let d = (8 / atomic_bits) as usize;
            let log_bases = vec![atomic_bits as usize; d];

            let mut compiler = NoirToR1CSCompiler::new();

            // Add a witness slot for the "byte" value.
            let byte_idx = compiler.num_witnesses();
            compiler.r1cs.add_witnesses(1);
            compiler.witness_builders.push(WitnessBuilder::Constant(
                provekit_common::witness::ConstantTerm(byte_idx, FieldElement::from(200u64)),
            ));

            // Decompose — adds digit witnesses + recomposition constraints.
            let dd = add_digital_decomposition(&mut compiler, log_bases, vec![byte_idx]);

            let num_w = compiler.num_witnesses();

            // --- Canonical case: byte = 200, valid digits ---
            let mut witness = vec![FieldElement::from(0u64); num_w];
            witness[0] = FieldElement::from(1u64); // constant-one witness
            witness[byte_idx] = FieldElement::from(200u64);

            for (i, digit) in decompose(200, atomic_bits, d).into_iter().enumerate() {
                witness[dd.get_digit_witness_index(i, 0)] = FieldElement::from(digit);
            }

            assert!(
                constraints_satisfied(&compiler.r1cs, &witness),
                "Canonical byte=200 with w={atomic_bits} must satisfy recomposition"
            );

            // --- Non-canonical case: tamper byte to 256, digits unchanged ---
            // Digits still sum to 200, but byte is 256 → mismatch.
            witness[byte_idx] = FieldElement::from(256u64);
            assert!(
                !constraints_satisfied(&compiler.r1cs, &witness),
                "byte=256 with digits for 200 (w={atomic_bits}) must NOT satisfy recomposition"
            );

            // --- Verify that no in-range digit combination can represent 256 ---
            let max_representable: u64 = (0..d)
                .map(|i| ((1u64 << atomic_bits) - 1) << (i as u64 * atomic_bits as u64))
                .sum();
            assert_eq!(
                max_representable, 255,
                "Max representable value with w={atomic_bits}, d={d} digits must be exactly 255"
            );
        }
    }
}
