use {
    crate::{
        bigint_mod::{
            add_4limb, bigint_to_fe, cmp_4limb, compute_mul_mod_carries, decompose_to_u128_limbs,
            divmod, divmod_wide, ec_point_add_with_lambda, ec_point_double_with_lambda,
            ec_scalar_mul, fe_to_bigint, half_gcd, mod_pow, reconstruct_from_halves,
            reconstruct_from_u128_limbs, sub_u64, widening_mul,
        },
        witness::{digits::DigitalDecompositionWitnessesSolver, ram::SpiceWitnessesSolver},
    },
    acir::native_types::WitnessMap,
    ark_ff::{BigInteger, Field, PrimeField},
    ark_std::Zero,
    provekit_common::{
        utils::noir_to_native,
        witness::{
            compute_spread, ConstantOrR1CSWitness, ConstantTerm, ProductLinearTerm, SumTerm,
            WitnessBuilder, WitnessCoefficient,
        },
        FieldElement, NoirElement, TranscriptSponge,
    },
    whir::transcript::{ProverState, VerifierMessage},
};

pub trait WitnessBuilderSolver {
    fn solve(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        witness: &mut [Option<FieldElement>],
        transcript: &mut ProverState<TranscriptSponge>,
    );
}

/// Resolve a ConstantOrR1CSWitness to its FieldElement value.
fn resolve(witness: &[Option<FieldElement>], v: &ConstantOrR1CSWitness) -> FieldElement {
    match v {
        ConstantOrR1CSWitness::Constant(c) => *c,
        ConstantOrR1CSWitness::Witness(idx) => witness[*idx].unwrap(),
    }
}

/// Convert a u128 value to a FieldElement.
fn u128_to_fe(val: u128) -> FieldElement {
    FieldElement::from_bigint(ark_ff::BigInt([val as u64, (val >> 64) as u64, 0, 0])).unwrap()
}

/// Read witness limbs and reconstruct as [u64; 4].
fn read_witness_limbs(
    witness: &[Option<FieldElement>],
    indices: &[usize],
    limb_bits: u32,
) -> [u64; 4] {
    let limb_values: Vec<u128> = indices
        .iter()
        .map(|&idx| {
            let bigint = witness[idx].unwrap().into_bigint().0;
            bigint[0] as u128 | ((bigint[1] as u128) << 64)
        })
        .collect();
    reconstruct_from_u128_limbs(&limb_values, limb_bits)
}

/// Write u128 limb values as FieldElement witnesses starting at `start`.
fn write_limbs(witness: &mut [Option<FieldElement>], start: usize, vals: &[u128]) {
    for (i, &val) in vals.iter().enumerate() {
        witness[start + i] = Some(u128_to_fe(val));
    }
}

impl WitnessBuilderSolver for WitnessBuilder {
    fn solve(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirElement>,
        witness: &mut [Option<FieldElement>],
        transcript: &mut ProverState<TranscriptSponge>,
    ) {
        match self {
            WitnessBuilder::Constant(ConstantTerm(witness_idx, c)) => {
                witness[*witness_idx] = Some(*c);
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = Some(noir_to_native(
                    *acir_witness_idx_to_value_map
                        .get_index(*acir_witness_idx as u32)
                        .unwrap(),
                ));
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                witness[*witness_idx] = Some(
                    operands
                        .iter()
                        .map(|SumTerm(coeff, witness_idx)| {
                            if let Some(coeff) = coeff {
                                *coeff * witness[*witness_idx].unwrap()
                            } else {
                                witness[*witness_idx].unwrap()
                            }
                        })
                        .fold(FieldElement::zero(), |acc, x| acc + x),
                );
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a: FieldElement = witness[*operand_idx_a].unwrap();
                let b: FieldElement = witness[*operand_idx_b].unwrap();
                witness[*witness_idx] = Some(a * b);
            }
            WitnessBuilder::Inverse(..) | WitnessBuilder::LogUpInverse(..) => {
                unreachable!(
                    "Inverse/LogUpInverse should not be called - handled by batch inversion"
                )
            }
            WitnessBuilder::SafeInverse(witness_idx, operand_idx) => {
                let val = witness[*operand_idx].unwrap();
                witness[*witness_idx] = Some(if val == FieldElement::zero() {
                    FieldElement::zero()
                } else {
                    val.inverse().unwrap()
                });
            }
            WitnessBuilder::ModularInverse(witness_idx, operand_idx, modulus) => {
                let a_limbs = fe_to_bigint(witness[*operand_idx].unwrap());
                let m_limbs = modulus.into_bigint().0;
                let exp = sub_u64(&m_limbs, 2);
                witness[*witness_idx] = Some(bigint_to_fe(&mod_pow(&a_limbs, &exp, &m_limbs)));
            }
            WitnessBuilder::IntegerQuotient(witness_idx, dividend_idx, divisor) => {
                let d_limbs = fe_to_bigint(witness[*dividend_idx].unwrap());
                let m_limbs = divisor.into_bigint().0;
                let (quotient, _) = divmod(&d_limbs, &m_limbs);
                witness[*witness_idx] = Some(bigint_to_fe(&quotient));
            }
            WitnessBuilder::IndexedLogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(index_coeff, index),
                rs_challenge,
                value,
            ) => {
                let index = witness[*index].unwrap();
                let value = witness[*value].unwrap();
                let rs_challenge = witness[*rs_challenge].unwrap();
                let sz_challenge = witness[*sz_challenge].unwrap();
                witness[*witness_idx] =
                    Some(sz_challenge - (*index_coeff * index + rs_challenge * value));
            }
            WitnessBuilder::MultiplicitiesForRange(start_idx, range_size, value_witnesses) => {
                let mut multiplicities = vec![0u32; *range_size];
                for value_witness_idx in value_witnesses {
                    // If the value is representable as just a u64, then it should be the least
                    // significant value in the BigInt representation.
                    let value = witness[*value_witness_idx].unwrap().into_bigint().0[0];
                    multiplicities[value as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[start_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::Challenge(witness_idx) => {
                let challenge: FieldElement = transcript.verifier_message();
                witness[*witness_idx] = Some(challenge);
            }
            WitnessBuilder::LogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(value_coeff, value),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap() - (*value_coeff * witness[*value].unwrap()),
                );
            }
            WitnessBuilder::ProductLinearOperation(
                witness_idx,
                ProductLinearTerm(x, a, b),
                ProductLinearTerm(y, c, d),
            ) => {
                witness[*witness_idx] =
                    Some((*a * witness[*x].unwrap() + *b) * (*c * witness[*y].unwrap() + *d));
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => {
                dd_struct.solve(witness);
            }
            WitnessBuilder::SpiceMultisetFactor(
                witness_idx,
                sz_challenge,
                rs_challenge,
                WitnessCoefficient(addr, addr_witness),
                value,
                WitnessCoefficient(timer, timer_witness),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (*addr * witness[*addr_witness].unwrap()
                            + witness[*rs_challenge].unwrap() * witness[*value].unwrap()
                            + witness[*rs_challenge].unwrap()
                                * witness[*rs_challenge].unwrap()
                                * *timer
                                * witness[*timer_witness].unwrap()),
                );
            }
            WitnessBuilder::SpiceWitnesses(spice_witnesses) => {
                spice_witnesses.solve(witness);
            }
            WitnessBuilder::BinOpLookupDenominator(
                witness_idx,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                lhs,
                rhs,
                output,
            ) => {
                let lhs = resolve(witness, lhs);
                let rhs = resolve(witness, rhs);
                let output = resolve(witness, output);
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (lhs
                            + witness[*rs_challenge].unwrap() * rhs
                            + witness[*rs_challenge_sqrd].unwrap() * output),
                );
            }
            WitnessBuilder::CombinedBinOpLookupDenominator(
                witness_idx,
                sz_challenge,
                rs_challenge,
                rs_sqrd,
                rs_cubed,
                lhs,
                rhs,
                and_output,
                xor_output,
            ) => {
                let lhs = resolve(witness, lhs);
                let rhs = resolve(witness, rhs);
                let and_out = resolve(witness, and_output);
                let xor_out = resolve(witness, xor_output);
                // Encoding: sz - (lhs + rs*rhs + rs²*and_out + rs³*xor_out)
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (lhs
                            + witness[*rs_challenge].unwrap() * rhs
                            + witness[*rs_sqrd].unwrap() * and_out
                            + witness[*rs_cubed].unwrap() * xor_out),
                );
            }
            WitnessBuilder::MultiplicitiesForBinOp(witness_idx, atomic_bits, operands) => {
                let mut multiplicities = vec![0u32; 2usize.pow(2 * *atomic_bits)];
                for (lhs, rhs) in operands {
                    let lhs = resolve(witness, lhs);
                    let rhs = resolve(witness, rhs);
                    let index = (lhs.into_bigint().0[0] << *atomic_bits) + rhs.into_bigint().0[0];
                    multiplicities[index as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[witness_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::U32Addition(result_witness_idx, carry_witness_idx, a, b) => {
                let a_val = resolve(witness, a);
                let b_val = resolve(witness, b);
                assert!(
                    a_val.into_bigint().num_bits() <= 32,
                    "a_val must be less than or equal to 32 bits, got {}",
                    a_val.into_bigint().num_bits()
                );
                assert!(
                    b_val.into_bigint().num_bits() <= 32,
                    "b_val must be less than or equal to 32 bits, got {}",
                    b_val.into_bigint().num_bits()
                );
                let sum = a_val + b_val;
                let sum_big = sum.into_bigint();
                let two_pow_32 = 1u64 << 32;
                let remainder = sum_big.0[0] % two_pow_32; // result
                let quotient = sum_big.0[0] / two_pow_32; // carry
                assert!(
                    quotient == 0 || quotient == 1,
                    "quotient must be 0 or 1, got {}",
                    quotient
                );
                witness[*result_witness_idx] = Some(FieldElement::from(remainder));
                witness[*carry_witness_idx] = Some(FieldElement::from(quotient));
            }
            WitnessBuilder::U32AdditionMulti(result_witness_idx, carry_witness_idx, inputs) => {
                // Sum all inputs as u64 to handle overflow.
                let mut sum: u64 = 0;
                for input in inputs {
                    let val = resolve(witness, input).into_bigint().0[0];
                    assert!(val < (1u64 << 32), "input must be 32-bit");
                    sum += val;
                }
                let two_pow_32 = 1u64 << 32;
                let remainder = sum % two_pow_32;
                let quotient = sum / two_pow_32;
                witness[*result_witness_idx] = Some(FieldElement::from(remainder));
                witness[*carry_witness_idx] = Some(FieldElement::from(quotient));
            }
            WitnessBuilder::And(result_witness_idx, lh, rh) => {
                let lh_val = resolve(witness, lh);
                let rh_val = resolve(witness, rh);
                assert!(
                    lh_val.into_bigint().num_bits() <= 32,
                    "lh_val must be less than or equal to 32 bits, got {}",
                    lh_val.into_bigint().num_bits()
                );
                assert!(
                    rh_val.into_bigint().num_bits() <= 32,
                    "rh_val must be less than or equal to 32 bits, got {}",
                    rh_val.into_bigint().num_bits()
                );
                witness[*result_witness_idx] = Some(FieldElement::new(
                    lh_val.into_bigint() & rh_val.into_bigint(),
                ));
            }
            WitnessBuilder::Xor(result_witness_idx, lh, rh) => {
                let lh_val = resolve(witness, lh);
                let rh_val = resolve(witness, rh);
                assert!(
                    lh_val.into_bigint().num_bits() <= 32,
                    "lh_val must be less than or equal to 32 bits, got {}",
                    lh_val.into_bigint().num_bits()
                );
                assert!(
                    rh_val.into_bigint().num_bits() <= 32,
                    "rh_val must be less than or equal to 32 bits, got {}",
                    rh_val.into_bigint().num_bits()
                );
                witness[*result_witness_idx] = Some(FieldElement::new(
                    lh_val.into_bigint() ^ rh_val.into_bigint(),
                ));
            }
            WitnessBuilder::MultiLimbMulModHint {
                output_start,
                a_limbs,
                b_limbs,
                modulus,
                limb_bits,
                num_limbs,
            } => {
                let n = *num_limbs as usize;
                let w = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, w);
                let b_val = read_witness_limbs(witness, b_limbs, w);

                let product = widening_mul(&a_val, &b_val);
                let (q_val, r_val) = divmod_wide(&product, modulus);

                let q_limbs_vals = decompose_to_u128_limbs(&q_val, n, w);
                let r_limbs_vals = decompose_to_u128_limbs(&r_val, n, w);

                let carries = compute_mul_mod_carries(
                    &decompose_to_u128_limbs(&a_val, n, w),
                    &decompose_to_u128_limbs(&b_val, n, w),
                    &decompose_to_u128_limbs(modulus, n, w),
                    &q_limbs_vals,
                    &r_limbs_vals,
                    w,
                );

                write_limbs(witness, *output_start, &q_limbs_vals);
                write_limbs(witness, *output_start + n, &r_limbs_vals);
                write_limbs(witness, *output_start + 2 * n, &carries);
            }
            WitnessBuilder::MultiLimbModularInverse {
                output_start,
                a_limbs,
                modulus,
                limb_bits,
                num_limbs,
            } => {
                let n = *num_limbs as usize;
                let w = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, w);
                let exp = sub_u64(modulus, 2);
                let inv = mod_pow(&a_val, &exp, modulus);
                write_limbs(witness, *output_start, &decompose_to_u128_limbs(&inv, n, w));
            }
            WitnessBuilder::MultiLimbAddQuotient {
                output,
                a_limbs,
                b_limbs,
                modulus,
                limb_bits,
                ..
            } => {
                let w = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, w);
                let b_val = read_witness_limbs(witness, b_limbs, w);

                let sum = add_4limb(&a_val, &b_val);
                let q = if sum[4] > 0 {
                    1u64
                } else {
                    let sum4 = [sum[0], sum[1], sum[2], sum[3]];
                    if cmp_4limb(&sum4, modulus) != std::cmp::Ordering::Less {
                        1u64
                    } else {
                        0u64
                    }
                };

                witness[*output] = Some(FieldElement::from(q));
            }
            WitnessBuilder::MultiLimbSubBorrow {
                output,
                a_limbs,
                b_limbs,
                limb_bits,
                ..
            } => {
                let w = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, w);
                let b_val = read_witness_limbs(witness, b_limbs, w);

                let q = if cmp_4limb(&a_val, &b_val) == std::cmp::Ordering::Less {
                    1u64
                } else {
                    0u64
                };

                witness[*output] = Some(FieldElement::from(q));
            }
            WitnessBuilder::BytePartition { lo, hi, x, k } => {
                let x_val = witness[*x].unwrap().into_bigint().0[0];
                debug_assert!(x_val < 256, "BytePartition input must be 8-bit");

                let mask = (1u64 << *k) - 1;
                let lo_val = x_val & mask;
                let hi_val = x_val >> *k;

                witness[*lo] = Some(FieldElement::from(lo_val));
                witness[*hi] = Some(FieldElement::from(hi_val));
            }
            WitnessBuilder::FakeGLVHint {
                output_start,
                s_lo,
                s_hi,
                curve_order,
            } => {
                let s_val = reconstruct_from_halves(
                    &fe_to_bigint(witness[*s_lo].unwrap()),
                    &fe_to_bigint(witness[*s_hi].unwrap()),
                );

                let (val1, val2, neg1, neg2) = half_gcd(&s_val, curve_order);

                witness[*output_start] = Some(bigint_to_fe(&val1));
                witness[*output_start + 1] = Some(bigint_to_fe(&val2));
                witness[*output_start + 2] = Some(FieldElement::from(neg1 as u64));
                witness[*output_start + 3] = Some(FieldElement::from(neg2 as u64));
            }
            WitnessBuilder::EcDoubleHint {
                output_start,
                px,
                py,
                curve_a,
                field_modulus_p,
            } => {
                let px_val = fe_to_bigint(witness[*px].unwrap());
                let py_val = fe_to_bigint(witness[*py].unwrap());

                let (lambda, x3, y3) =
                    ec_point_double_with_lambda(&px_val, &py_val, curve_a, field_modulus_p);

                witness[*output_start] = Some(bigint_to_fe(&lambda));
                witness[*output_start + 1] = Some(bigint_to_fe(&x3));
                witness[*output_start + 2] = Some(bigint_to_fe(&y3));
            }
            WitnessBuilder::EcAddHint {
                output_start,
                x1,
                y1,
                x2,
                y2,
                field_modulus_p,
            } => {
                let x1_val = fe_to_bigint(witness[*x1].unwrap());
                let y1_val = fe_to_bigint(witness[*y1].unwrap());
                let x2_val = fe_to_bigint(witness[*x2].unwrap());
                let y2_val = fe_to_bigint(witness[*y2].unwrap());

                let (lambda, x3, y3) =
                    ec_point_add_with_lambda(&x1_val, &y1_val, &x2_val, &y2_val, field_modulus_p);

                witness[*output_start] = Some(bigint_to_fe(&lambda));
                witness[*output_start + 1] = Some(bigint_to_fe(&x3));
                witness[*output_start + 2] = Some(bigint_to_fe(&y3));
            }
            WitnessBuilder::EcScalarMulHint {
                output_start,
                px,
                py,
                s_lo,
                s_hi,
                curve_a,
                field_modulus_p,
            } => {
                let scalar = reconstruct_from_halves(
                    &fe_to_bigint(witness[*s_lo].unwrap()),
                    &fe_to_bigint(witness[*s_hi].unwrap()),
                );
                let px_val = fe_to_bigint(witness[*px].unwrap());
                let py_val = fe_to_bigint(witness[*py].unwrap());

                let (rx, ry) = ec_scalar_mul(&px_val, &py_val, &scalar, curve_a, field_modulus_p);

                witness[*output_start] = Some(bigint_to_fe(&rx));
                witness[*output_start + 1] = Some(bigint_to_fe(&ry));
            }
            WitnessBuilder::SelectWitness {
                output,
                flag,
                on_false,
                on_true,
            } => {
                let f = witness[*flag].unwrap();
                let a = witness[*on_false].unwrap();
                let b = witness[*on_true].unwrap();
                witness[*output] = Some(a + f * (b - a));
            }
            WitnessBuilder::BooleanOr { output, a, b } => {
                let a_val = witness[*a].unwrap();
                let b_val = witness[*b].unwrap();
                witness[*output] = Some(a_val + b_val - a_val * b_val);
            }
            WitnessBuilder::SignedBitHint {
                output_start,
                scalar,
                num_bits,
            } => {
                let s_fe = witness[*scalar].unwrap();
                let s_big = s_fe.into_bigint().0;
                // NOTE: Only reads lower 128 bits. Safe for FakeGLV half-scalars
                // (≤128 bits for 256-bit curves) but would silently truncate
                // larger values. The R1CS reconstruction constraint catches this.
                let s_val: u128 = s_big[0] as u128 | ((s_big[1] as u128) << 64);
                let n = *num_bits;
                let skew: u128 = if s_val & 1 == 0 { 1 } else { 0 };
                let s_adj = s_val + skew;
                let t = (s_adj + ((1u128 << n) - 1)) / 2;
                for i in 0..n {
                    witness[*output_start + i] = Some(FieldElement::from(((t >> i) & 1) as u64));
                }
                witness[*output_start + n] = Some(FieldElement::from(skew as u64));
            }
            WitnessBuilder::CombinedTableEntryInverse(..) => {
                unreachable!(
                    "CombinedTableEntryInverse should not be called - handled by batch inversion"
                )
            }
            WitnessBuilder::ChunkDecompose {
                output_start,
                packed,
                chunk_bits,
            } => {
                let packed_val = witness[*packed].unwrap().into_bigint().0[0];
                let mut offset = 0u32;
                for (i, &bits) in chunk_bits.iter().enumerate() {
                    let mask = (1u64 << bits) - 1;
                    let chunk_val = (packed_val >> offset) & mask;
                    witness[output_start + i] = Some(FieldElement::from(chunk_val));
                    offset += bits;
                }
            }
            WitnessBuilder::SpreadWitness(output_idx, input_idx) => {
                let input_val = witness[*input_idx].unwrap().into_bigint().0[0];
                let spread = compute_spread(input_val);
                witness[*output_idx] = Some(FieldElement::from(spread));
            }
            WitnessBuilder::SpreadBitExtract {
                output_start,
                chunk_bits,
                sum_terms,
                extract_even,
            } => {
                // Compute the spread sum inline from terms (no phantom witness needed)
                let sum_fe: FieldElement = sum_terms
                    .iter()
                    .map(|SumTerm(coeff, idx)| {
                        let v = witness[*idx].unwrap();
                        if let Some(c) = coeff {
                            *c * v
                        } else {
                            v
                        }
                    })
                    .fold(FieldElement::zero(), |acc, x| acc + x);
                let sum_val = sum_fe.into_bigint().0[0];
                // Extract even or odd bits from the spread sum
                let bit_offset = if *extract_even { 0 } else { 1 };
                let total_bits: u32 = chunk_bits.iter().sum();
                let mut extracted = 0u64;
                for i in 0..total_bits {
                    extracted |= ((sum_val >> (2 * i + bit_offset)) & 1) << i;
                }
                // Decompose extracted value into chunks
                let mut offset = 0u32;
                for (i, &bits) in chunk_bits.iter().enumerate() {
                    let mask = (1u64 << bits) - 1;
                    let chunk_val = (extracted >> offset) & mask;
                    witness[output_start + i] = Some(FieldElement::from(chunk_val));
                    offset += bits;
                }
            }
            WitnessBuilder::MultiplicitiesForSpread(first_idx, num_bits, queries) => {
                let table_size = 1usize << *num_bits;
                let mut multiplicities = vec![0u32; table_size];
                for query in queries {
                    let val = resolve(witness, query).into_bigint().0[0];
                    multiplicities[val as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[first_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::SpreadLookupDenominator(idx, sz, rs, input, spread_output) => {
                let sz_val = witness[*sz].unwrap();
                let rs_val = witness[*rs].unwrap();
                let input_val = resolve(witness, input);
                let spread_val = resolve(witness, spread_output);
                // sz - (input + rs * spread_output)
                witness[*idx] = Some(sz_val - (input_val + rs_val * spread_val));
            }
            WitnessBuilder::SpreadTableQuotient { .. } => {
                unreachable!(
                    "SpreadTableQuotient should not be called - handled by batch inversion"
                )
            }
        }
    }
}
