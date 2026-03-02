use {
    crate::witness::{digits::DigitalDecompositionWitnessesSolver, ram::SpiceWitnessesSolver},
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
                let a = witness[*operand_idx].unwrap();
                let a_limbs = a.into_bigint().0;
                let m_limbs = modulus.into_bigint().0;
                // Fermat's little theorem: a^{-1} = a^{m-2} mod m
                let exp = crate::witness::bigint_mod::sub_u64(&m_limbs, 2);
                let result_limbs = crate::witness::bigint_mod::mod_pow(&a_limbs, &exp, &m_limbs);
                witness[*witness_idx] =
                    Some(FieldElement::from_bigint(ark_ff::BigInt(result_limbs)).unwrap());
            }
            WitnessBuilder::IntegerQuotient(witness_idx, dividend_idx, divisor) => {
                let dividend = witness[*dividend_idx].unwrap();
                let d_limbs = dividend.into_bigint().0;
                let m_limbs = divisor.into_bigint().0;
                let (quotient, _remainder) = crate::witness::bigint_mod::divmod(&d_limbs, &m_limbs);
                witness[*witness_idx] =
                    Some(FieldElement::from_bigint(ark_ff::BigInt(quotient)).unwrap());
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
                let lhs = match lhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rhs = match rhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let output = match output {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
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
                let lhs = match lhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rhs = match rhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let and_out = match and_output {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let xor_out = match xor_output {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
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
                    let lhs = match lhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let rhs = match rhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let index = (lhs.into_bigint().0[0] << *atomic_bits) + rhs.into_bigint().0[0];
                    multiplicities[index as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[witness_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::U32Addition(result_witness_idx, carry_witness_idx, a, b) => {
                let a_val = match a {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(idx) => witness[*idx].unwrap(),
                };
                let b_val = match b {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(idx) => witness[*idx].unwrap(),
                };
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
                    let val = match input {
                        ConstantOrR1CSWitness::Constant(c) => c.into_bigint().0[0],
                        ConstantOrR1CSWitness::Witness(idx) => {
                            witness[*idx].unwrap().into_bigint().0[0]
                        }
                    };
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
                let lh_val = match lh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rh_val = match rh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
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
                let lh_val = match lh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rh_val = match rh {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
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
                use crate::witness::bigint_mod::{divmod_wide, widening_mul};
                let n = *num_limbs as usize;
                let w = *limb_bits;
                let limb_mask: u128 = if w >= 128 {
                    u128::MAX
                } else {
                    (1u128 << w) - 1
                };

                // Reconstruct a, b as [u64; 4] from N limbs
                let reconstruct = |limbs: &[usize]| -> [u64; 4] {
                    let mut val = [0u64; 4];
                    let mut bit_offset = 0u32;
                    for &limb_idx in limbs.iter() {
                        let limb_val = witness[limb_idx].unwrap().into_bigint().0;
                        let limb_u128 = limb_val[0] as u128 | ((limb_val[1] as u128) << 64);
                        // Place into val at bit_offset
                        let word_start = (bit_offset / 64) as usize;
                        let bit_within = bit_offset % 64;
                        if word_start < 4 {
                            val[word_start] |= (limb_u128 as u64) << bit_within;
                            if word_start + 1 < 4 {
                                val[word_start + 1] |= (limb_u128 >> (64 - bit_within)) as u64;
                            }
                            if word_start + 2 < 4 && bit_within > 0 {
                                let upper = limb_u128 >> (128 - bit_within);
                                if upper > 0 {
                                    val[word_start + 2] |= upper as u64;
                                }
                            }
                        }
                        bit_offset += w;
                    }
                    val
                };

                let a_val = reconstruct(a_limbs);
                let b_val = reconstruct(b_limbs);

                // Compute product and divmod
                let product = widening_mul(&a_val, &b_val);
                let (q_val, r_val) = divmod_wide(&product, modulus);

                // Decompose a [u64;4] into N limbs of limb_bits width.
                let decompose_n_from_u64 = |val: &[u64; 4]| -> Vec<u128> {
                    let mut limbs = Vec::with_capacity(n);
                    let mut remaining = *val;
                    for _ in 0..n {
                        let lo = remaining[0] as u128 | ((remaining[1] as u128) << 64);
                        limbs.push(lo & limb_mask);
                        // Shift right by w bits
                        if w >= 256 {
                            remaining = [0; 4];
                        } else {
                            let mut shifted = [0u64; 4];
                            let word_shift = (w / 64) as usize;
                            let bit_shift = w % 64;
                            for i in 0..4 {
                                if i + word_shift < 4 {
                                    shifted[i] = remaining[i + word_shift] >> bit_shift;
                                    if bit_shift > 0 && i + word_shift + 1 < 4 {
                                        shifted[i] |=
                                            remaining[i + word_shift + 1] << (64 - bit_shift);
                                    }
                                }
                            }
                            remaining = shifted;
                        }
                    }
                    limbs
                };

                let q_limbs_vals = decompose_n_from_u64(&q_val);
                let r_limbs_vals = decompose_n_from_u64(&r_val);

                // Compute carries for schoolbook verification:
                // a·b = p·q + r in base W = 2^limb_bits
                // For each column k (0..2N-2):
                //   lhs_k = Σ_{i+j=k} a[i]*b[j] + carry_{k-1}
                //   rhs_k = Σ_{i+j=k} p[i]*q[j] + r[k] + carry_k * W
                let p_limbs_vals = decompose_n_from_u64(modulus);
                let a_limbs_vals = decompose_n_from_u64(&a_val);
                let b_limbs_vals = decompose_n_from_u64(&b_val);

                let w_val = 1u128 << w;
                let num_carries = 2 * n - 2;
                let carry_offset = 1u128 << (w + ((n as f64).log2().ceil() as u32) + 1);
                let mut carries = Vec::with_capacity(num_carries);
                let mut running: i128 = 0;

                for k in 0..(2 * n - 1) {
                    // Sum a[i]*b[j] for i+j=k
                    let mut ab_sum: i128 = 0;
                    for i in 0..n {
                        let j = k as isize - i as isize;
                        if j >= 0 && (j as usize) < n {
                            ab_sum +=
                                a_limbs_vals[i] as i128 * b_limbs_vals[j as usize] as i128;
                        }
                    }
                    // Sum p[i]*q[j] for i+j=k
                    let mut pq_sum: i128 = 0;
                    for i in 0..n {
                        let j = k as isize - i as isize;
                        if j >= 0 && (j as usize) < n {
                            pq_sum +=
                                p_limbs_vals[i] as i128 * q_limbs_vals[j as usize] as i128;
                        }
                    }
                    let r_k = if k < n { r_limbs_vals[k] as i128 } else { 0 };

                    // column: ab_sum + carry_prev = pq_sum + r_k + carry_next * W
                    // carry_next = (ab_sum + carry_prev - pq_sum - r_k) / W
                    running += ab_sum - pq_sum - r_k;
                    if k < 2 * n - 2 {
                        let carry = running / w_val as i128;
                        carries.push(carry);
                        running -= carry * w_val as i128;
                    }
                }

                let u128_to_fe = |val: u128| -> FieldElement {
                    FieldElement::from_bigint(ark_ff::BigInt([
                        val as u64,
                        (val >> 64) as u64,
                        0,
                        0,
                    ]))
                    .unwrap()
                };

                // Write q limbs
                for i in 0..n {
                    witness[*output_start + i] = Some(u128_to_fe(q_limbs_vals[i]));
                }
                // Write r limbs
                for i in 0..n {
                    witness[*output_start + n + i] = Some(u128_to_fe(r_limbs_vals[i]));
                }
                // Write carries (unsigned-offset)
                for i in 0..num_carries {
                    let c_unsigned = (carries[i] + carry_offset as i128) as u128;
                    witness[*output_start + 2 * n + i] = Some(u128_to_fe(c_unsigned));
                }
            }
            WitnessBuilder::MultiLimbModularInverse {
                output_start,
                a_limbs,
                modulus,
                limb_bits,
                num_limbs,
            } => {
                use crate::witness::bigint_mod::{mod_pow, sub_u64};
                let n = *num_limbs as usize;
                let w = *limb_bits;
                let limb_mask: u128 = if w >= 128 {
                    u128::MAX
                } else {
                    (1u128 << w) - 1
                };

                // Reconstruct a as [u64; 4] from N limbs
                let mut a_val = [0u64; 4];
                let mut bit_offset = 0u32;
                for &limb_idx in a_limbs.iter() {
                    let limb_val = witness[limb_idx].unwrap().into_bigint().0;
                    let limb_u128 = limb_val[0] as u128 | ((limb_val[1] as u128) << 64);
                    let word_start = (bit_offset / 64) as usize;
                    let bit_within = bit_offset % 64;
                    if word_start < 4 {
                        a_val[word_start] |= (limb_u128 as u64) << bit_within;
                        if word_start + 1 < 4 {
                            a_val[word_start + 1] |= (limb_u128 >> (64 - bit_within)) as u64;
                        }
                    }
                    bit_offset += w;
                }

                // Compute inverse: a^{p-2} mod p
                let exp = sub_u64(modulus, 2);
                let inv = mod_pow(&a_val, &exp, modulus);

                // Decompose into N limbs
                let mut remaining = inv;
                let u128_to_fe = |val: u128| -> FieldElement {
                    FieldElement::from_bigint(ark_ff::BigInt([
                        val as u64,
                        (val >> 64) as u64,
                        0,
                        0,
                    ]))
                    .unwrap()
                };
                for i in 0..n {
                    let lo = remaining[0] as u128 | ((remaining[1] as u128) << 64);
                    witness[*output_start + i] = Some(u128_to_fe(lo & limb_mask));
                    // Shift right by w bits
                    let mut shifted = [0u64; 4];
                    let word_shift = (w / 64) as usize;
                    let bit_shift = w % 64;
                    for j in 0..4 {
                        if j + word_shift < 4 {
                            shifted[j] = remaining[j + word_shift] >> bit_shift;
                            if bit_shift > 0 && j + word_shift + 1 < 4 {
                                shifted[j] |= remaining[j + word_shift + 1] << (64 - bit_shift);
                            }
                        }
                    }
                    remaining = shifted;
                }
            }
            WitnessBuilder::MultiLimbAddQuotient {
                output,
                a_limbs,
                b_limbs,
                modulus,
                limb_bits,
                ..
            } => {
                use crate::witness::bigint_mod::{add_4limb, cmp_4limb};
                let w = *limb_bits;

                // Reconstruct from N limbs
                let reconstruct = |limbs: &[usize]| -> [u64; 4] {
                    let mut val = [0u64; 4];
                    let mut bit_offset = 0u32;
                    for &limb_idx in limbs.iter() {
                        let limb_val = witness[limb_idx].unwrap().into_bigint().0;
                        let limb_u128 = limb_val[0] as u128 | ((limb_val[1] as u128) << 64);
                        let word_start = (bit_offset / 64) as usize;
                        let bit_within = bit_offset % 64;
                        if word_start < 4 {
                            val[word_start] |= (limb_u128 as u64) << bit_within;
                            if word_start + 1 < 4 {
                                val[word_start + 1] |= (limb_u128 >> (64 - bit_within)) as u64;
                            }
                        }
                        bit_offset += w;
                    }
                    val
                };

                let a_val = reconstruct(a_limbs);
                let b_val = reconstruct(b_limbs);

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
                use crate::witness::bigint_mod::cmp_4limb;
                let w = *limb_bits;

                let reconstruct = |limbs: &[usize]| -> [u64; 4] {
                    let mut val = [0u64; 4];
                    let mut bit_offset = 0u32;
                    for &limb_idx in limbs.iter() {
                        let limb_val = witness[limb_idx].unwrap().into_bigint().0;
                        let limb_u128 = limb_val[0] as u128 | ((limb_val[1] as u128) << 64);
                        let word_start = (bit_offset / 64) as usize;
                        let bit_within = bit_offset % 64;
                        if word_start < 4 {
                            val[word_start] |= (limb_u128 as u64) << bit_within;
                            if word_start + 1 < 4 {
                                val[word_start + 1] |= (limb_u128 >> (64 - bit_within)) as u64;
                            }
                        }
                        bit_offset += w;
                    }
                    val
                };

                let a_val = reconstruct(a_limbs);
                let b_val = reconstruct(b_limbs);

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
                    let val = match query {
                        ConstantOrR1CSWitness::Constant(c) => c.into_bigint().0[0],
                        ConstantOrR1CSWitness::Witness(w) => {
                            witness[*w].unwrap().into_bigint().0[0]
                        }
                    };
                    multiplicities[val as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[first_idx + i] = Some(FieldElement::from(*count));
                }
            }
            WitnessBuilder::SpreadLookupDenominator(idx, sz, rs, input, spread_output) => {
                let sz_val = witness[*sz].unwrap();
                let rs_val = witness[*rs].unwrap();
                let input_val = match input {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(w) => witness[*w].unwrap(),
                };
                let spread_val = match spread_output {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(w) => witness[*w].unwrap(),
                };
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
