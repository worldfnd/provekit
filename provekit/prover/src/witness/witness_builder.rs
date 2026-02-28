use {
    crate::witness::{digits::DigitalDecompositionWitnessesSolver, ram::SpiceWitnessesSolver},
    acir::native_types::WitnessMap,
    ark_ff::{BigInteger, PrimeField},
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
            WitnessBuilder::MulModHint {
                output_start,
                a_lo,
                a_hi,
                b_lo,
                b_hi,
                modulus,
            } => {
                use crate::witness::bigint_mod::{
                    compute_carries_86, decompose_128, decompose_86, divmod_wide, widening_mul,
                    CARRY_OFFSET,
                };

                // Read inputs: a and b as 128-bit limb pairs
                let a_lo_fe = witness[*a_lo].unwrap();
                let a_hi_fe = witness[*a_hi].unwrap();
                let b_lo_fe = witness[*b_lo].unwrap();
                let b_hi_fe = witness[*b_hi].unwrap();

                // Reconstruct a, b as [u64; 4]
                let a_lo_limbs = a_lo_fe.into_bigint().0;
                let a_hi_limbs = a_hi_fe.into_bigint().0;
                let a_val = [a_lo_limbs[0], a_lo_limbs[1], a_hi_limbs[0], a_hi_limbs[1]];

                let b_lo_limbs = b_lo_fe.into_bigint().0;
                let b_hi_limbs = b_hi_fe.into_bigint().0;
                let b_val = [b_lo_limbs[0], b_lo_limbs[1], b_hi_limbs[0], b_hi_limbs[1]];

                // Compute product and divmod
                let product = widening_mul(&a_val, &b_val);
                let (q_val, r_val) = divmod_wide(&product, modulus);

                // Decompose into 128-bit limbs
                let (q_lo, q_hi) = decompose_128(&q_val);
                let (r_lo, r_hi) = decompose_128(&r_val);

                // Decompose into 86-bit limbs
                let (a86_0, a86_1, a86_2) = decompose_86(&a_val);
                let (b86_0, b86_1, b86_2) = decompose_86(&b_val);
                let (q86_0, q86_1, q86_2) = decompose_86(&q_val);
                let (r86_0, r86_1, r86_2) = decompose_86(&r_val);

                // Compute carries
                let carries = compute_carries_86(
                    [a86_0, a86_1, a86_2],
                    [b86_0, b86_1, b86_2],
                    {
                        let (p0, p1, p2) = decompose_86(modulus);
                        [p0, p1, p2]
                    },
                    [q86_0, q86_1, q86_2],
                    [r86_0, r86_1, r86_2],
                );

                // Helper: convert u128 to FieldElement
                let u128_to_fe = |val: u128| -> FieldElement {
                    FieldElement::from_bigint(ark_ff::BigInt([
                        val as u64,
                        (val >> 64) as u64,
                        0,
                        0,
                    ]))
                    .unwrap()
                };

                // Write outputs: [0..2) q_lo, q_hi
                witness[*output_start] = Some(u128_to_fe(q_lo));
                witness[*output_start + 1] = Some(u128_to_fe(q_hi));
                // [2..4) r_lo, r_hi
                witness[*output_start + 2] = Some(u128_to_fe(r_lo));
                witness[*output_start + 3] = Some(u128_to_fe(r_hi));
                // [4..7) a_86 limbs
                witness[*output_start + 4] = Some(u128_to_fe(a86_0));
                witness[*output_start + 5] = Some(u128_to_fe(a86_1));
                witness[*output_start + 6] = Some(u128_to_fe(a86_2));
                // [7..10) b_86 limbs
                witness[*output_start + 7] = Some(u128_to_fe(b86_0));
                witness[*output_start + 8] = Some(u128_to_fe(b86_1));
                witness[*output_start + 9] = Some(u128_to_fe(b86_2));
                // [10..13) q_86 limbs
                witness[*output_start + 10] = Some(u128_to_fe(q86_0));
                witness[*output_start + 11] = Some(u128_to_fe(q86_1));
                witness[*output_start + 12] = Some(u128_to_fe(q86_2));
                // [13..16) r_86 limbs
                witness[*output_start + 13] = Some(u128_to_fe(r86_0));
                witness[*output_start + 14] = Some(u128_to_fe(r86_1));
                witness[*output_start + 15] = Some(u128_to_fe(r86_2));
                // [16..20) carries (unsigned-offset)
                for i in 0..4 {
                    let c_unsigned = (carries[i] + CARRY_OFFSET as i128) as u128;
                    witness[*output_start + 16 + i] = Some(u128_to_fe(c_unsigned));
                }
            }
            WitnessBuilder::WideModularInverse {
                output_start,
                a_lo,
                a_hi,
                modulus,
            } => {
                use crate::witness::bigint_mod::{decompose_128, mod_pow, sub_u64};

                // Read input a as 128-bit limb pair
                let a_lo_fe = witness[*a_lo].unwrap();
                let a_hi_fe = witness[*a_hi].unwrap();

                let a_lo_limbs = a_lo_fe.into_bigint().0;
                let a_hi_limbs = a_hi_fe.into_bigint().0;
                let a_val = [a_lo_limbs[0], a_lo_limbs[1], a_hi_limbs[0], a_hi_limbs[1]];

                // Compute inverse: a^{p-2} mod p (Fermat's little theorem)
                let exp = sub_u64(modulus, 2);
                let inv = mod_pow(&a_val, &exp, modulus);

                // Decompose into 128-bit limbs
                let (inv_lo, inv_hi) = decompose_128(&inv);

                let u128_to_fe = |val: u128| -> FieldElement {
                    FieldElement::from_bigint(ark_ff::BigInt([
                        val as u64,
                        (val >> 64) as u64,
                        0,
                        0,
                    ]))
                    .unwrap()
                };

                witness[*output_start] = Some(u128_to_fe(inv_lo));
                witness[*output_start + 1] = Some(u128_to_fe(inv_hi));
            }
            WitnessBuilder::WideAddQuotient {
                output,
                a_lo,
                a_hi,
                b_lo,
                b_hi,
                modulus,
            } => {
                use crate::witness::bigint_mod::{add_4limb, cmp_4limb};

                let a_lo_fe = witness[*a_lo].unwrap();
                let a_hi_fe = witness[*a_hi].unwrap();
                let b_lo_fe = witness[*b_lo].unwrap();
                let b_hi_fe = witness[*b_hi].unwrap();

                let a_lo_limbs = a_lo_fe.into_bigint().0;
                let a_hi_limbs = a_hi_fe.into_bigint().0;
                let a_val = [a_lo_limbs[0], a_lo_limbs[1], a_hi_limbs[0], a_hi_limbs[1]];

                let b_lo_limbs = b_lo_fe.into_bigint().0;
                let b_hi_limbs = b_hi_fe.into_bigint().0;
                let b_val = [b_lo_limbs[0], b_lo_limbs[1], b_hi_limbs[0], b_hi_limbs[1]];

                let sum = add_4limb(&a_val, &b_val);
                // q = 1 if sum >= p, else 0
                let q = if sum[4] > 0 {
                    // sum > 2^256 > any 256-bit modulus
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
            WitnessBuilder::WideSubBorrow {
                output,
                a_lo,
                a_hi,
                b_lo,
                b_hi,
            } => {
                use crate::witness::bigint_mod::cmp_4limb;

                let a_lo_limbs = witness[*a_lo].unwrap().into_bigint().0;
                let a_hi_limbs = witness[*a_hi].unwrap().into_bigint().0;
                let a_val = [a_lo_limbs[0], a_lo_limbs[1], a_hi_limbs[0], a_hi_limbs[1]];

                let b_lo_limbs = witness[*b_lo].unwrap().into_bigint().0;
                let b_hi_limbs = witness[*b_hi].unwrap().into_bigint().0;
                let b_val = [b_lo_limbs[0], b_lo_limbs[1], b_hi_limbs[0], b_hi_limbs[1]];

                // q = 1 if a < b (need to add p to make result non-negative)
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
