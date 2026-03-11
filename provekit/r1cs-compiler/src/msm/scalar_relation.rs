//! Scalar relation verification: (-1)^neg1 * |s1| + (-1)^neg2 * |s2| * s ≡ 0
//! (mod n).
//!
//! Shared by both the native and non-native MSM paths.

use {
    super::{
        constrain_zero, cost_model, curve,
        multi_limb_ops::{MultiLimbOps, MultiLimbParams},
        FieldOps, Limbs,
    },
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{Field, PrimeField},
    curve::CurveParams,
    provekit_common::{
        witness::{ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// The 256-bit scalar is split into two 128-bit halves (s_lo, s_hi) because the
/// full value doesn't fit in the native field.
const SCALAR_HALF_BITS: usize = 128;

/// Compute digit widths for decomposing `total_bits` into chunks of at most
/// `max_width` bits. The last chunk may be smaller.
fn limb_widths(total_bits: usize, max_width: u32) -> Vec<usize> {
    let n = (total_bits + max_width as usize - 1) / max_width as usize;
    (0..n)
        .map(|i| {
            let remaining = total_bits - i * max_width as usize;
            remaining.min(max_width as usize)
        })
        .collect()
}

/// Builds `MultiLimbParams` for scalar relation verification (mod
/// curve_order_n).
fn build_scalar_relation_params(
    num_limbs: usize,
    limb_bits: u32,
    curve: &CurveParams,
) -> MultiLimbParams {
    // Scalar relation uses curve_order_n as the modulus.
    // This is always non-native (curve_order_n ≠ BN254 scalar field modulus,
    // except for Grumpkin where they're very close but still different).
    let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);
    let n_limbs = curve.curve_order_n_limbs(limb_bits, num_limbs);
    let n_minus_1_limbs = curve.curve_order_n_minus_1_limbs(limb_bits, num_limbs);

    // For N=1 non-native, we need the modulus as a FieldElement
    let modulus_fe = if num_limbs == 1 {
        Some(curve::curve_native_point_fe(&curve.curve_order_n))
    } else {
        None
    };

    MultiLimbParams {
        num_limbs,
        limb_bits,
        p_limbs: n_limbs,
        p_minus_1_limbs: n_minus_1_limbs,
        two_pow_w,
        modulus_raw: curve.curve_order_n,
        curve_a_limbs: vec![FieldElement::from(0u64); num_limbs], // unused
        is_native: false,                                         // always non-native
        modulus_fe,
    }
}

/// Verifies the scalar relation: (-1)^neg1 * |s1| + (-1)^neg2 * |s2| * s ≡ 0
/// (mod n).
///
/// Uses multi-limb arithmetic with curve_order_n as the modulus.
pub(super) fn verify_scalar_relation(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    s_lo: usize,
    s_hi: usize,
    s1_witness: usize,
    s2_witness: usize,
    neg1_witness: usize,
    neg2_witness: usize,
    curve: &CurveParams,
) {
    let order_bits = curve.curve_order_bits() as usize;
    let limb_bits =
        cost_model::scalar_relation_limb_bits(FieldElement::MODULUS_BIT_SIZE, order_bits);
    let num_limbs = (order_bits + limb_bits as usize - 1) / limb_bits as usize;
    let half_bits = curve.glv_half_bits() as usize;

    let params = build_scalar_relation_params(num_limbs, limb_bits, curve);
    let mut ops = MultiLimbOps {
        compiler,
        range_checks,
        params: &params,
    };

    let s_limbs = decompose_scalar_from_halves(&mut ops, s_lo, s_hi, num_limbs, limb_bits);
    let s1_limbs = decompose_half_scalar(&mut ops, s1_witness, num_limbs, half_bits, limb_bits);
    let s2_limbs = decompose_half_scalar(&mut ops, s2_witness, num_limbs, half_bits, limb_bits);

    let product = ops.mul(s2_limbs, s_limbs);

    // Sign handling: when signs match check s1+product=0, otherwise s1-product=0.
    // XOR = neg1 + neg2 - 2*neg1*neg2 gives 0 for same signs, 1 for different.
    let sum = ops.add(s1_limbs, product);
    let diff = ops.sub(s1_limbs, product);

    let xor_prod = ops.compiler.add_product(neg1_witness, neg2_witness);
    let xor = ops.compiler.add_sum(vec![
        SumTerm(None, neg1_witness),
        SumTerm(None, neg2_witness),
        SumTerm(Some(-FieldElement::from(2u64)), xor_prod),
    ]);

    let effective = ops.select_unchecked(xor, sum, diff);
    for i in 0..num_limbs {
        constrain_zero(ops.compiler, effective[i]);
    }
}

/// Decompose a 256-bit scalar from two 128-bit halves into `num_limbs` limbs.
///
/// When `limb_bits` divides 128 (e.g. 64), limb boundaries align with the
/// s_lo/s_hi split. Otherwise (e.g. 85-bit limbs), one limb straddles bit 128
/// and is assembled from a partial s_lo digit and a partial s_hi digit.
fn decompose_scalar_from_halves(
    ops: &mut MultiLimbOps,
    s_lo: usize,
    s_hi: usize,
    num_limbs: usize,
    limb_bits: u32,
) -> Limbs {
    let lo_tail = SCALAR_HALF_BITS % limb_bits as usize;

    if lo_tail == 0 {
        let widths = limb_widths(SCALAR_HALF_BITS, limb_bits);
        let dd_lo = add_digital_decomposition(ops.compiler, widths.clone(), vec![s_lo]);
        let dd_hi = add_digital_decomposition(ops.compiler, widths.clone(), vec![s_hi]);
        let mut limbs = Limbs::new(num_limbs);
        let from_lo = widths.len().min(num_limbs);
        for (i, &w) in widths.iter().enumerate().take(from_lo) {
            limbs[i] = dd_lo.get_digit_witness_index(i, 0);
            ops.range_checks.entry(w as u32).or_default().push(limbs[i]);
        }
        for (i, &w) in widths.iter().enumerate().take(num_limbs - from_lo) {
            limbs[from_lo + i] = dd_hi.get_digit_witness_index(i, 0);
            ops.range_checks
                .entry(w as u32)
                .or_default()
                .push(limbs[from_lo + i]);
        }
        limbs
    } else {
        // Example: 85-bit limbs, 254-bit order →
        //   s_lo DD [85, 43], s_hi DD [42, 86]
        //   L0 = s_lo[0..85), L1 = s_lo[85..128) | s_hi[0..42), L2 = s_hi[42..128)
        let hi_head = limb_bits as usize - lo_tail;
        let hi_rest = SCALAR_HALF_BITS - hi_head;
        let lo_full = SCALAR_HALF_BITS / limb_bits as usize;

        let lo_widths = limb_widths(SCALAR_HALF_BITS, limb_bits);
        let hi_widths = vec![hi_head, hi_rest];

        let dd_lo = add_digital_decomposition(ops.compiler, lo_widths, vec![s_lo]);
        let dd_hi = add_digital_decomposition(ops.compiler, hi_widths, vec![s_hi]);
        let mut limbs = Limbs::new(num_limbs);

        for i in 0..lo_full {
            limbs[i] = dd_lo.get_digit_witness_index(i, 0);
            ops.range_checks
                .entry(limb_bits)
                .or_default()
                .push(limbs[i]);
        }

        // Cross-boundary limb: lo_tail bits from s_lo + hi_head bits from s_hi
        let shift = FieldElement::from(2u64).pow([lo_tail as u64]);
        let lo_digit = dd_lo.get_digit_witness_index(lo_full, 0);
        let hi_digit = dd_hi.get_digit_witness_index(0, 0);
        limbs[lo_full] = ops.compiler.add_sum(vec![
            SumTerm(None, lo_digit),
            SumTerm(Some(shift), hi_digit),
        ]);
        ops.range_checks
            .entry(lo_tail as u32)
            .or_default()
            .push(lo_digit);
        ops.range_checks
            .entry(hi_head as u32)
            .or_default()
            .push(hi_digit);

        if hi_rest > 0 {
            limbs[lo_full + 1] = dd_hi.get_digit_witness_index(1, 0);
            ops.range_checks
                .entry(hi_rest as u32)
                .or_default()
                .push(limbs[lo_full + 1]);
        }

        limbs
    }
}

/// Decompose a half-scalar witness into `num_limbs` limbs, zero-padding the
/// upper limbs beyond `half_bits`.
fn decompose_half_scalar(
    ops: &mut MultiLimbOps,
    witness: usize,
    num_limbs: usize,
    half_bits: usize,
    limb_bits: u32,
) -> Limbs {
    let widths = limb_widths(half_bits, limb_bits);
    let dd = add_digital_decomposition(ops.compiler, widths.clone(), vec![witness]);
    let mut limbs = Limbs::new(num_limbs);

    for (i, &w) in widths.iter().enumerate() {
        limbs[i] = dd.get_digit_witness_index(i, 0);
        ops.range_checks.entry(w as u32).or_default().push(limbs[i]);
    }

    for i in widths.len()..num_limbs {
        let w = ops.compiler.num_witnesses();
        ops.compiler
            .add_witness_builder(WitnessBuilder::Constant(ConstantTerm(
                w,
                FieldElement::from(0u64),
            )));
        limbs[i] = w;
        constrain_zero(ops.compiler, limbs[i]);
    }

    limbs
}
