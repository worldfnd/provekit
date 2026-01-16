use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
        uints::U8,
    },
    ark_ff::PrimeField,
    ark_std::One,
    provekit_common::{
        witness::{
            decompose_into_digits, ConstantOrR1CSWitness, DigitalDecompositionWitnesses, SumTerm,
            WitnessBuilder, BINOP_ATOMIC_BITS, NUM_DIGITS,
        },
        FieldElement,
    },
    std::{collections::BTreeMap, ops::Neg},
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
/// This saves one entire lookup table (~196,608 constraints) compared to
/// having separate AND and XOR tables.
///
/// Table encoding: sz - (lhs + rs*rhs + rs²*and_out + rs³*xor_out)
///
/// For each AND operation, we compute the complementary XOR output.
/// For each XOR operation, we compute the complementary AND output.
pub(crate) fn add_combined_binop_constraints(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    is_byte_level: bool,
) {
    if and_ops.is_empty() && xor_ops.is_empty() {
        return;
    }

    // For combined table, each operation needs both AND and XOR outputs.
    // Convert ops to atomic (byte-level) operations with both outputs.
    let combined_ops_atomic = if is_byte_level {
        // Already byte-level. Create combined ops with complementary outputs.
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
                .and_modify(|e| e.0 = Some(*and_out))
                .or_insert((Some(*and_out), None, *lhs, *rhs));
        }

        for (lhs, rhs, xor_out) in &xor_ops {
            let key = (operand_key(lhs), operand_key(rhs));
            pair_map
                .entry(key)
                .and_modify(|e| e.1 = Some(*xor_out))
                .or_insert((None, Some(*xor_out), *lhs, *rhs));
        }

        // Now build combined ops, creating complementary witnesses only when needed
        let mut combined = Vec::with_capacity(pair_map.len());
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
            combined.push((lhs, rhs, and_out, xor_out));
        }

        combined
    } else {
        // Need digital decomposition for 32-bit operands
        let log_bases = vec![BINOP_ATOMIC_BITS; NUM_DIGITS];

        // Collect all witnesses that require digital decomposition
        let mut witnesses_to_decompose = vec![];
        for (lh, rh, output) in and_ops.iter().chain(xor_ops.iter()) {
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

        let mut combined = vec![];
        let mut witness_dd_counter = 0;

        // Process AND ops - decompose and create complementary XOR outputs
        for (lh, rh, _and_output) in &and_ops {
            let lh_atoms = get_atoms(lh, &dd_struct, &log_bases, &mut witness_dd_counter);
            let rh_atoms = get_atoms(rh, &dd_struct, &log_bases, &mut witness_dd_counter);
            let and_output_atoms = (0..NUM_DIGITS)
                .map(|digit_place| {
                    dd_struct.get_digit_witness_index(digit_place, witness_dd_counter)
                })
                .collect::<Vec<_>>();
            witness_dd_counter += 1;

            for ((lh_atom, rh_atom), and_atom) in
                lh_atoms.into_iter().zip(rh_atoms).zip(and_output_atoms)
            {
                // Create XOR output witness for this digit
                let xor_atom = r1cs_compiler.add_witness_builder(WitnessBuilder::Xor(
                    r1cs_compiler.num_witnesses(),
                    lh_atom,
                    rh_atom,
                ));
                combined.push((lh_atom, rh_atom, and_atom, xor_atom));
            }
        }

        // Process XOR ops - decompose and create complementary AND outputs
        for (lh, rh, _xor_output) in &xor_ops {
            let lh_atoms = get_atoms(lh, &dd_struct, &log_bases, &mut witness_dd_counter);
            let rh_atoms = get_atoms(rh, &dd_struct, &log_bases, &mut witness_dd_counter);
            let xor_output_atoms = (0..NUM_DIGITS)
                .map(|digit_place| {
                    dd_struct.get_digit_witness_index(digit_place, witness_dd_counter)
                })
                .collect::<Vec<_>>();
            witness_dd_counter += 1;

            for ((lh_atom, rh_atom), xor_atom) in
                lh_atoms.into_iter().zip(rh_atoms).zip(xor_output_atoms)
            {
                // Create AND output witness for this digit
                let and_atom = r1cs_compiler.add_witness_builder(WitnessBuilder::And(
                    r1cs_compiler.num_witnesses(),
                    lh_atom,
                    rh_atom,
                ));
                combined.push((lh_atom, rh_atom, and_atom, xor_atom));
            }
        }

        combined
    };

    // Build multiplicities for the combined table
    let multiplicities_wb = WitnessBuilder::MultiplicitiesForBinOp(
        r1cs_compiler.num_witnesses(),
        combined_ops_atomic
            .iter()
            .map(|(lh, rh, ..)| (*lh, *rh))
            .collect(),
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

    let summands_for_ops = combined_ops_atomic
        .into_iter()
        .map(|(lhs, rhs, and_out, xor_out)| {
            add_combined_lookup_summand(
                r1cs_compiler,
                &challenges,
                lhs,
                rhs,
                ConstantOrR1CSWitness::Witness(and_out),
                ConstantOrR1CSWitness::Witness(xor_out),
            )
        })
        .map(|coeff| SumTerm(None, coeff))
        .collect();
    let sum_for_ops = r1cs_compiler.add_sum(summands_for_ops);

    let summands_for_table = (0..1 << BINOP_ATOMIC_BITS)
        .flat_map(|lhs: u32| {
            (0..1 << BINOP_ATOMIC_BITS).map(move |rhs: u32| (lhs, rhs, lhs & rhs, lhs ^ rhs))
        })
        .map(|(lhs, rhs, and_out, xor_out)| {
            let inverse =
                add_table_entry_inverse(r1cs_compiler, &challenges, lhs, rhs, and_out, xor_out);
            let multiplicity_idx =
                multiplicities_first_witness + (lhs << BINOP_ATOMIC_BITS) as usize + rhs as usize;
            r1cs_compiler.add_product(multiplicity_idx, inverse)
        })
        .map(|coeff| SumTerm(None, coeff))
        .collect();
    let sum_for_table = r1cs_compiler.add_sum(summands_for_table);

    // Check equality
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), sum_for_ops)],
        &[(FieldElement::one(), sum_for_table)],
    );
}

/// Helper to get atomic (digit-level) operands for combined binop.
fn get_atoms(
    operand: &ConstantOrR1CSWitness,
    dd_struct: &DigitalDecompositionWitnesses,
    log_bases: &[usize],
    witness_dd_counter: &mut usize,
) -> Vec<ConstantOrR1CSWitness> {
    match operand {
        ConstantOrR1CSWitness::Witness(_) => {
            let counter = *witness_dd_counter;
            *witness_dd_counter += 1;
            (0..NUM_DIGITS)
                .map(|digit_place| {
                    ConstantOrR1CSWitness::Witness(
                        dd_struct.get_digit_witness_index(digit_place, counter),
                    )
                })
                .collect()
        }
        ConstantOrR1CSWitness::Constant(value) => decompose_into_digits(*value, log_bases)
            .into_iter()
            .map(ConstantOrR1CSWitness::Constant)
            .collect(),
    }
}

fn add_table_entry_inverse(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    c: &LookupChallenges,
    lhs: u32,
    rhs: u32,
    and_out: u32,
    xor_out: u32,
) -> usize {
    use provekit_common::witness::CombinedTableEntryInverseData;

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

    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), c.sz),
            (FieldElement::from(lhs).neg(), r1cs_compiler.witness_one()),
            (FieldElement::from(rhs).neg(), c.rs),
            (FieldElement::from(and_out).neg(), c.rs_sqrd),
            (FieldElement::from(xor_out).neg(), c.rs_cubed),
        ],
        &[(FieldElement::one(), inverse)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
    );

    inverse
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
