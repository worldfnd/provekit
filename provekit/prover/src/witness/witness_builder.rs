use {
    crate::{
        bigint_mod::{
            add_4limb, bigint_to_fe, cmp_4limb, compute_mul_mod_carries, decompose_to_u128_limbs,
            divmod, divmod_wide, fe_to_bigint, half_gcd, mod_pow, mul_mod, reconstruct_from_halves,
            signed_quotient_wide, sub_u64, to_i128_limbs, widening_mul,
        },
        ec_arith::{
            compute_ec_verification_carries, ec_point_add_with_lambda, ec_point_double_with_lambda,
            ec_scalar_mul,
        },
        witness::{digits::DigitalDecompositionWitnessesSolver, ram::SpiceWitnessesSolver},
    },
    acir::native_types::WitnessMap,
    ark_ff::{BigInteger, Field, PrimeField},
    ark_std::Zero,
    provekit_common::{
        utils::noir_to_native,
        witness::{
            compute_spread, ConstantOrR1CSWitness, ConstantTerm, NonNativeEcOp, ProductLinearTerm,
            SumTerm, WitnessBuilder, WitnessCoefficient,
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

use super::limb_io::{
    read_witness_limbs, setup_3eq_ec_hint, solve_and_write_equation, split_quotient, write_limbs,
    ColumnEqParams, ColumnEqTerms,
};

/// Resolve a ConstantOrR1CSWitness to its FieldElement value.
fn resolve(witness: &[Option<FieldElement>], v: &ConstantOrR1CSWitness) -> FieldElement {
    match v {
        ConstantOrR1CSWitness::Constant(c) => *c,
        ConstantOrR1CSWitness::Witness(idx) => witness[*idx].unwrap(),
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
            WitnessBuilder::SumQuotient {
                output,
                terms,
                divisor,
            } => {
                let sum: FieldElement = terms
                    .iter()
                    .map(|SumTerm(coeff, idx)| {
                        let val = witness[*idx].unwrap();
                        coeff.map_or(val, |c| c * val)
                    })
                    .fold(FieldElement::zero(), |acc, x| acc + x);
                let d_limbs = fe_to_bigint(sum);
                let m_limbs = divisor.into_bigint().0;
                let (quotient, _) = divmod(&d_limbs, &m_limbs);
                witness[*output] = Some(bigint_to_fe(&quotient));
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
                let limb_bits = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, limb_bits);
                let b_val = read_witness_limbs(witness, b_limbs, limb_bits);

                let product = widening_mul(&a_val, &b_val);
                let (q_val, r_val) = divmod_wide(&product, modulus);

                let q_limbs_vals = decompose_to_u128_limbs(&q_val, n, limb_bits);
                let r_limbs_vals = decompose_to_u128_limbs(&r_val, n, limb_bits);

                let carries = compute_mul_mod_carries(
                    &decompose_to_u128_limbs(&a_val, n, limb_bits),
                    &decompose_to_u128_limbs(&b_val, n, limb_bits),
                    &decompose_to_u128_limbs(modulus, n, limb_bits),
                    &q_limbs_vals,
                    &r_limbs_vals,
                    limb_bits,
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
                let limb_bits = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, limb_bits);
                let exp = sub_u64(modulus, 2);
                let inv = mod_pow(&a_val, &exp, modulus);
                write_limbs(
                    witness,
                    *output_start,
                    &decompose_to_u128_limbs(&inv, n, limb_bits),
                );
            }
            WitnessBuilder::MultiLimbAddQuotient {
                output,
                a_limbs,
                b_limbs,
                modulus,
                limb_bits,
                ..
            } => {
                let limb_bits = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, limb_bits);
                let b_val = read_witness_limbs(witness, b_limbs, limb_bits);

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
                let limb_bits = *limb_bits;

                let a_val = read_witness_limbs(witness, a_limbs, limb_bits);
                let b_val = read_witness_limbs(witness, b_limbs, limb_bits);

                let q = if cmp_4limb(&a_val, &b_val) == std::cmp::Ordering::Less {
                    1u64
                } else {
                    0u64
                };

                witness[*output] = Some(FieldElement::from(q));
            }
            WitnessBuilder::BytePartition { lo, hi, x, k } => {
                let x_val = witness[*x].unwrap().into_bigint().0[0];
                assert!(
                    x_val < 256,
                    "BytePartition input must be 8-bit, got {x_val}"
                );

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
            WitnessBuilder::NonNativeEcHint {
                output_start,
                op,
                inputs,
                curve_a,
                curve_b,
                field_modulus_p,
                limb_bits,
                num_limbs,
            } => {
                let n = *num_limbs as usize;
                let limb_bits = *limb_bits;
                let os = *output_start;

                let p_l = decompose_to_u128_limbs(field_modulus_p, n, limb_bits);

                match op {
                    NonNativeEcOp::Double => {
                        let px_val = read_witness_limbs(witness, inputs[0].as_slice(), limb_bits);
                        let py_val = read_witness_limbs(witness, inputs[1].as_slice(), limb_bits);
                        let ec_result =
                            ec_point_double_with_lambda(&px_val, &py_val, curve_a, field_modulus_p);
                        let v = setup_3eq_ec_hint(
                            witness,
                            os,
                            n,
                            limb_bits,
                            &[px_val, py_val],
                            ec_result,
                        );
                        let ll = &v.lambda_limbs;
                        let xl = &v.x3_limbs;
                        let yl = &v.y3_limbs;
                        let pl = &v.input_limbs[0];
                        let pyl = &v.input_limbs[1];
                        let a_l = decompose_to_u128_limbs(curve_a, n, limb_bits);

                        // Per-equation max_coeff_sum must match compiler
                        // (see hints_non_native.rs:point_double_verified_non_native)

                        // Eq1: 2*λ*py - 3*px² - a = q1*p
                        solve_and_write_equation(
                            witness,
                            os,
                            3 * n,
                            &ColumnEqParams {
                                num_limbs: n,
                                limb_bits,
                                max_coeff_sum: 6 + 2 * n as u64,
                                field_modulus_p,
                                p_limbs: &p_l,
                            },
                            &ColumnEqTerms {
                                lhs_products:   &[(&v.lambda, &py_val, 2)],
                                rhs_products:   &[(&px_val, &px_val, 3)],
                                lhs_linear:     &[],
                                rhs_linear:     &[(curve_a, 1)],
                                carry_products: &[(ll, pyl, 2), (pl, pl, -3)],
                                carry_linear:   &[(to_i128_limbs(&a_l), -1)],
                            },
                        );
                        // Eq2: λ² - x3 - 2*px = q2*p
                        solve_and_write_equation(
                            witness,
                            os,
                            7 * n - 2,
                            &ColumnEqParams {
                                num_limbs: n,
                                limb_bits,
                                max_coeff_sum: 4 + 2 * n as u64,
                                field_modulus_p,
                                p_limbs: &p_l,
                            },
                            &ColumnEqTerms {
                                lhs_products:   &[(&v.lambda, &v.lambda, 1)],
                                rhs_products:   &[],
                                lhs_linear:     &[],
                                rhs_linear:     &[(&v.x3, 1), (&px_val, 2)],
                                carry_products: &[(ll, ll, 1)],
                                carry_linear:   &[(to_i128_limbs(xl), -1), (to_i128_limbs(pl), -2)],
                            },
                        );
                        // Eq3: λ*px - λ*x3 - y3 - py = q3*p
                        solve_and_write_equation(
                            witness,
                            os,
                            11 * n - 4,
                            &ColumnEqParams {
                                num_limbs: n,
                                limb_bits,
                                max_coeff_sum: 4 + 2 * n as u64,
                                field_modulus_p,
                                p_limbs: &p_l,
                            },
                            &ColumnEqTerms {
                                lhs_products:   &[(&v.lambda, &px_val, 1)],
                                rhs_products:   &[(&v.lambda, &v.x3, 1)],
                                lhs_linear:     &[],
                                rhs_linear:     &[(&v.y3, 1), (&py_val, 1)],
                                carry_products: &[(ll, pl, 1), (ll, xl, -1)],
                                carry_linear:   &[
                                    (to_i128_limbs(yl), -1),
                                    (to_i128_limbs(pyl), -1),
                                ],
                            },
                        );
                    }
                    NonNativeEcOp::Add => {
                        let x1v = read_witness_limbs(witness, inputs[0].as_slice(), limb_bits);
                        let y1v = read_witness_limbs(witness, inputs[1].as_slice(), limb_bits);
                        let x2v = read_witness_limbs(witness, inputs[2].as_slice(), limb_bits);
                        let y2v = read_witness_limbs(witness, inputs[3].as_slice(), limb_bits);
                        let ec_result =
                            ec_point_add_with_lambda(&x1v, &y1v, &x2v, &y2v, field_modulus_p);
                        let v = setup_3eq_ec_hint(
                            witness,
                            os,
                            n,
                            limb_bits,
                            &[x1v, y1v, x2v, y2v],
                            ec_result,
                        );
                        let ll = &v.lambda_limbs;
                        let xl = &v.x3_limbs;
                        let yl = &v.y3_limbs;
                        let x1l = &v.input_limbs[0];
                        let y1l = &v.input_limbs[1];
                        let x2l = &v.input_limbs[2];
                        let y2l = &v.input_limbs[3];

                        // Must match compiler's max_coeff_sum
                        // (see hints_non_native.rs:point_add_verified_non_native)
                        let mcs = 4 + 2 * n as u64; // 1+1+1+1+2n for all 3 eqs
                        let params = ColumnEqParams {
                            num_limbs: n,
                            limb_bits,
                            max_coeff_sum: mcs,
                            field_modulus_p,
                            p_limbs: &p_l,
                        };

                        // Eq1: λ*x2 - λ*x1 + y1 - y2 = q1*p
                        solve_and_write_equation(witness, os, 3 * n, &params, &ColumnEqTerms {
                            lhs_products:   &[(&v.lambda, &x2v, 1)],
                            rhs_products:   &[(&v.lambda, &x1v, 1)],
                            lhs_linear:     &[(&y1v, 1)],
                            rhs_linear:     &[(&y2v, 1)],
                            carry_products: &[(ll, x2l, 1), (ll, x1l, -1)],
                            carry_linear:   &[(to_i128_limbs(y2l), -1), (to_i128_limbs(y1l), 1)],
                        });
                        // Eq2: λ² - x3 - x1 - x2 = q2*p
                        solve_and_write_equation(witness, os, 7 * n - 2, &params, &ColumnEqTerms {
                            lhs_products:   &[(&v.lambda, &v.lambda, 1)],
                            rhs_products:   &[],
                            lhs_linear:     &[],
                            rhs_linear:     &[(&v.x3, 1), (&x1v, 1), (&x2v, 1)],
                            carry_products: &[(ll, ll, 1)],
                            carry_linear:   &[
                                (to_i128_limbs(xl), -1),
                                (to_i128_limbs(x1l), -1),
                                (to_i128_limbs(x2l), -1),
                            ],
                        });
                        // Eq3: λ*x1 - λ*x3 - y3 - y1 = q3*p
                        solve_and_write_equation(
                            witness,
                            os,
                            11 * n - 4,
                            &params,
                            &ColumnEqTerms {
                                lhs_products:   &[(&v.lambda, &x1v, 1)],
                                rhs_products:   &[(&v.lambda, &v.x3, 1)],
                                lhs_linear:     &[],
                                rhs_linear:     &[(&v.y3, 1), (&y1v, 1)],
                                carry_products: &[(ll, x1l, 1), (ll, xl, -1)],
                                carry_linear:   &[
                                    (to_i128_limbs(yl), -1),
                                    (to_i128_limbs(y1l), -1),
                                ],
                            },
                        );
                    }
                    NonNativeEcOp::OnCurve => {
                        let px_val = read_witness_limbs(witness, inputs[0].as_slice(), limb_bits);
                        let py_val = read_witness_limbs(witness, inputs[1].as_slice(), limb_bits);
                        let x_sq_val = mul_mod(&px_val, &px_val, field_modulus_p);
                        let xsl = decompose_to_u128_limbs(&x_sq_val, n, limb_bits);
                        let pl = decompose_to_u128_limbs(&px_val, n, limb_bits);
                        let pyl = decompose_to_u128_limbs(&py_val, n, limb_bits);
                        write_limbs(witness, os, &xsl);

                        let a_is_zero = curve_a.iter().all(|&v| v == 0);
                        // Per-equation max_coeff_sum must match compiler
                        // (see hints_non_native.rs:verify_on_curve_non_native)
                        let mcs_eq1: u64 = 2 + 2 * n as u64; // px·px(1)+x_sq(1)+pq(2n)
                        let mcs_eq2: u64 = if a_is_zero {
                            3 + 2 * n as u64 // x³(1)+y²(1)+b(1)+pq(2n)
                        } else {
                            4 + 2 * n as u64 // x³(1)+y²(1)+ax(1)+b(1)+pq(2n)
                        };

                        // Eq1: px·px - x_sq = q1·p
                        solve_and_write_equation(
                            witness,
                            os,
                            n,
                            &ColumnEqParams {
                                num_limbs: n,
                                limb_bits,
                                max_coeff_sum: mcs_eq1,
                                field_modulus_p,
                                p_limbs: &p_l,
                            },
                            &ColumnEqTerms {
                                lhs_products:   &[(&px_val, &px_val, 1)],
                                rhs_products:   &[],
                                lhs_linear:     &[],
                                rhs_linear:     &[(&x_sq_val, 1)],
                                carry_products: &[(&pl, &pl, 1)],
                                carry_linear:   &[(to_i128_limbs(&xsl), -1)],
                            },
                        );

                        // Eq2: py·py - x_sq·px - a·px - b = q2·p
                        let a_l = decompose_to_u128_limbs(curve_a, n, limb_bits);
                        let b_l = decompose_to_u128_limbs(curve_b, n, limb_bits);

                        let mut rhs_prods: Vec<(&[u64; 4], &[u64; 4], u64)> =
                            vec![(&x_sq_val, &px_val, 1)];
                        if !a_is_zero {
                            rhs_prods.push((curve_a, &px_val, 1));
                        }
                        let (q2_abs, q2_neg) = signed_quotient_wide(
                            &[(&py_val, &py_val, 1)],
                            &rhs_prods,
                            &[],
                            &[(curve_b, 1)],
                            field_modulus_p,
                            n,
                            limb_bits,
                        );

                        let (q2_pos, q2_neg) = split_quotient(q2_abs, q2_neg, n);
                        write_limbs(witness, os + 5 * n - 2, &q2_pos);
                        write_limbs(witness, os + 6 * n - 2, &q2_neg);

                        let mut prod_sets: Vec<(&[u128], &[u128], i64)> =
                            vec![(&pyl, &pyl, 1), (&xsl, &pl, -1)];
                        if !a_is_zero {
                            prod_sets.push((&a_l, &pl, -1));
                        }
                        let c2 = compute_ec_verification_carries(
                            &prod_sets,
                            &[(to_i128_limbs(&b_l), -1)],
                            &p_l,
                            &q2_pos,
                            &q2_neg,
                            n,
                            limb_bits,
                            mcs_eq2,
                        );
                        write_limbs(witness, os + 7 * n - 2, &c2);
                    }
                }
            }
            WitnessBuilder::EcScalarMulHint {
                output_start,
                px_limbs,
                py_limbs,
                s_lo,
                s_hi,
                curve_a,
                field_modulus_p,
                num_limbs,
                limb_bits,
            } => {
                let n = *num_limbs as usize;
                let scalar = reconstruct_from_halves(
                    &fe_to_bigint(witness[*s_lo].unwrap()),
                    &fe_to_bigint(witness[*s_hi].unwrap()),
                );

                let px_val = if n == 1 {
                    fe_to_bigint(witness[px_limbs[0]].unwrap())
                } else {
                    read_witness_limbs(witness, px_limbs, *limb_bits)
                };
                let py_val = if n == 1 {
                    fe_to_bigint(witness[py_limbs[0]].unwrap())
                } else {
                    read_witness_limbs(witness, py_limbs, *limb_bits)
                };

                let (rx, ry) = ec_scalar_mul(&px_val, &py_val, &scalar, curve_a, field_modulus_p);

                if n == 1 {
                    witness[*output_start] = Some(bigint_to_fe(&rx));
                    witness[*output_start + 1] = Some(bigint_to_fe(&ry));
                } else {
                    let rx_limbs = decompose_to_u128_limbs(&rx, n, *limb_bits);
                    let ry_limbs = decompose_to_u128_limbs(&ry, n, *limb_bits);
                    write_limbs(witness, *output_start, &rx_limbs);
                    write_limbs(witness, *output_start + n, &ry_limbs);
                }
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
                assert!(
                    *num_bits <= 128,
                    "SignedBitHint: num_bits={} exceeds 128; scalar would be silently truncated",
                    num_bits
                );
                let s_fe = witness[*scalar].unwrap();
                let s_big = s_fe.into_bigint().0;
                let s_val: u128 = s_big[0] as u128 | ((s_big[1] as u128) << 64);
                let n = *num_bits;
                let skew: u128 = if s_val & 1 == 0 { 1 } else { 0 };
                let s_adj = s_val + skew;
                // t = (s_adj + 2^n - 1) / 2
                // Both s_adj and 2^n-1 are odd, so sum is even.
                // To avoid u128 overflow when n >= 128, rewrite as:
                //   t = (s_adj - 1) / 2 + (2^n - 1 + 1) / 2 = (s_adj - 1) / 2 + 2^(n-1)
                let t = if n == 0 {
                    s_adj / 2
                } else {
                    (s_adj - 1) / 2 + (1u128 << (n - 1))
                };
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
