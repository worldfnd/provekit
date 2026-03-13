use {
    super::{
        curve::CurveParams,
        multi_limb_arith::less_than_p_check_multi,
        multi_limb_ops::{MultiLimbOps, MultiLimbParams},
        Limbs,
    },
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{Field, PrimeField},
    provekit_common::{
        witness::{NonNativeEcOp, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// Dispatching point doubling: uses hint-verified for multi-limb non-native,
/// generic field-ops otherwise.
pub fn point_double_dispatch(ops: &mut MultiLimbOps, x1: Limbs, y1: Limbs) -> (Limbs, Limbs) {
    if ops.params.num_limbs >= 2 && !ops.params.is_native {
        point_double_verified_non_native(ops.compiler, ops.range_checks, x1, y1, ops.params)
    } else {
        point_double(ops, x1, y1)
    }
}

/// Dispatching point addition: uses hint-verified for multi-limb non-native,
/// generic field-ops otherwise.
pub fn point_add_dispatch(
    ops: &mut MultiLimbOps,
    x1: Limbs,
    y1: Limbs,
    x2: Limbs,
    y2: Limbs,
) -> (Limbs, Limbs) {
    if ops.params.num_limbs >= 2 && !ops.params.is_native {
        point_add_verified_non_native(ops.compiler, ops.range_checks, x1, y1, x2, y2, ops.params)
    } else {
        point_add(ops, x1, y1, x2, y2)
    }
}

/// Generic point doubling on y^2 = x^3 + ax + b.
///
/// Given P = (x1, y1), computes 2P = (x3, y3):
///   lambda = (3 * x1^2 + a) / (2 * y1)
///   x3     = lambda^2 - 2 * x1
///   y3     = lambda * (x1 - x3) - y1
///
/// Edge case — y1 = 0 (point of order 2):
///   When y1 = 0, the denominator 2*y1 = 0 and the inverse does not exist.
///   The result should be the point at infinity (identity element).
///   This function does NOT handle that case — the constraint system will
///   be unsatisfiable if y1 = 0 (the inverse verification will fail to
///   verify 0 * inv = 1 mod p). The caller must check y1 = 0 using
///   compute_is_zero and conditionally select the point-at-infinity
///   result before calling this function.
pub fn point_double(ops: &mut MultiLimbOps, x1: Limbs, y1: Limbs) -> (Limbs, Limbs) {
    let a = ops.curve_a();

    // Computing numerator = 3 * x1^2 + a
    let x1_sq = ops.mul(x1, x1);
    let two_x1_sq = ops.add(x1_sq, x1_sq);
    let three_x1_sq = ops.add(two_x1_sq, x1_sq);
    let numerator = ops.add(three_x1_sq, a);

    // Computing denominator = 2 * y1
    let denominator = ops.add(y1, y1);

    // Computing lambda = numerator * denominator^(-1)
    let denom_inv = ops.inv(denominator);
    let lambda = ops.mul(numerator, denom_inv);

    // Computing x3 = lambda^2 - 2 * x1
    let lambda_sq = ops.mul(lambda, lambda);
    let two_x1 = ops.add(x1, x1);
    let x3 = ops.sub(lambda_sq, two_x1);

    // Computing y3 = lambda * (x1 - x3) - y1
    let x1_minus_x3 = ops.sub(x1, x3);
    let lambda_dx = ops.mul(lambda, x1_minus_x3);
    let y3 = ops.sub(lambda_dx, y1);

    (x3, y3)
}

/// Generic point addition on y^2 = x^3 + ax + b.
///
/// Given P1 = (x1, y1) and P2 = (x2, y2), computes P1 + P2 = (x3, y3):
///   lambda = (y2 - y1) / (x2 - x1)
///   x3     = lambda^2 - x1 - x2
///   y3     = lambda * (x1 - x3) - y1
///
/// Edge cases — x1 = x2:
///   When x1 = x2, the denominator (x2 - x1) = 0 and the inverse does
///   not exist. This covers two cases:
///     - P1 = P2 (same point): use `point_double` instead.
///     - P1 = -P2 (y1 = -y2): the result is the point at infinity.
///   This function does NOT handle either case — the constraint system
///   will be unsatisfiable if x1 = x2. The caller must detect this
///   and branch accordingly.
pub fn point_add(
    ops: &mut MultiLimbOps,
    x1: Limbs,
    y1: Limbs,
    x2: Limbs,
    y2: Limbs,
) -> (Limbs, Limbs) {
    // Computing lambda = (y2 - y1) / (x2 - x1)
    let numerator = ops.sub(y2, y1);
    let denominator = ops.sub(x2, x1);
    let denom_inv = ops.inv(denominator);
    let lambda = ops.mul(numerator, denom_inv);

    // Computing x3 = lambda^2 - x1 - x2
    let lambda_sq = ops.mul(lambda, lambda);
    let x1_plus_x2 = ops.add(x1, x2);
    let x3 = ops.sub(lambda_sq, x1_plus_x2);

    // Computing y3 = lambda * (x1 - x3) - y1
    let x1_minus_x3 = ops.sub(x1, x3);
    let lambda_dx = ops.mul(lambda, x1_minus_x3);
    let y3 = ops.sub(lambda_dx, y1);

    (x3, y3)
}

/// Conditional point select without boolean constraint on `flag`.
/// Caller must ensure `flag` is already constrained boolean.
pub fn point_select_unchecked(
    ops: &mut MultiLimbOps,
    flag: usize,
    on_false: (Limbs, Limbs),
    on_true: (Limbs, Limbs),
) -> (Limbs, Limbs) {
    let x = ops.select_unchecked(flag, on_false.0, on_true.0);
    let y = ops.select_unchecked(flag, on_false.1, on_true.1);
    (x, y)
}

/// Builds a signed point table of odd multiples for signed-digit windowed
/// scalar multiplication.
///
/// T\[0\] = P, T\[1\] = 3P, T\[2\] = 5P, ..., T\[k-1\] = (2k-1)P
/// where k = `half_table_size` = 2^(w-1).
///
/// Build cost: 1 point_double (for 2P) + (k-1) point_adds when k >= 2.
fn build_signed_point_table(
    ops: &mut MultiLimbOps,
    px: Limbs,
    py: Limbs,
    half_table_size: usize,
) -> Vec<(Limbs, Limbs)> {
    assert!(half_table_size >= 1);
    let mut table = Vec::with_capacity(half_table_size);
    table.push((px, py)); // T[0] = 1*P
    if half_table_size >= 2 {
        let two_p = point_double_dispatch(ops, px, py); // 2P
        for i in 1..half_table_size {
            let prev = table[i - 1];
            table.push(point_add_dispatch(ops, prev.0, prev.1, two_p.0, two_p.1));
        }
    }
    table
}

/// Selects T\[d\] from a point table using bit witnesses, where `d = Σ
/// bits\[i\] * 2^i`.
///
/// Uses a binary tree of `point_select`s: processes bits from MSB to LSB,
/// halving the candidate set at each level. Total: `(2^w - 1)` point selects
/// for a table of `2^w` entries.
///
/// Each bit is constrained boolean exactly once, then all subsequent selects
/// on that bit use the unchecked variant.
fn table_lookup(
    ops: &mut MultiLimbOps,
    table: &[(Limbs, Limbs)],
    bits: &[usize],
) -> (Limbs, Limbs) {
    assert_eq!(table.len(), 1 << bits.len());
    let mut current: Vec<(Limbs, Limbs)> = table.to_vec();
    // Process bits from MSB to LSB
    for &bit in bits.iter().rev() {
        ops.constrain_flag(bit); // constrain boolean once per bit
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            next.push(point_select_unchecked(
                ops,
                bit,
                current[i],
                current[i + half],
            ));
        }
        current = next;
    }
    current[0]
}

/// Like `table_lookup`, but skips boolean constraints on bits.
///
/// Use when bits are already known boolean (e.g. XOR'd bits derived from
/// boolean-constrained inputs in `signed_table_lookup`).
fn table_lookup_unchecked(
    ops: &mut MultiLimbOps,
    table: &[(Limbs, Limbs)],
    bits: &[usize],
) -> (Limbs, Limbs) {
    assert_eq!(table.len(), 1 << bits.len());
    let mut current: Vec<(Limbs, Limbs)> = table.to_vec();
    for &bit in bits.iter().rev() {
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            next.push(point_select_unchecked(
                ops,
                bit,
                current[i],
                current[i + half],
            ));
        }
        current = next;
    }
    current[0]
}

/// Signed-digit table lookup: selects from a half-size table using XOR'd
/// index bits, then conditionally negates y based on the sign bit.
///
/// For a w-bit window with bits \[b_0, ..., b_{w-1}\] (LSB first):
///   - sign_bit = b_{w-1} (MSB): 1 = positive digit, 0 = negative digit
///   - index_bits = \[b_0, ..., b_{w-2}\] (lower w-1 bits)
///   - When positive: table index = lower bits as-is
///   - When negative: table index = bitwise complement of lower bits, and y is
///     negated
///
/// The XOR'd bits are computed as: `idx_i = 1 - b_i - MSB + 2*b_i*MSB`,
/// which equals `b_i` when MSB=1, and `1-b_i` when MSB=0.
///
/// # Precondition
/// `sign_bit` must be boolean-constrained by the caller. This function uses
/// it in `select_unchecked` without re-constraining. Currently satisfied:
/// `decompose_signed_bits` boolean-constrains all bits including the MSB
/// used as `sign_bit`.
fn signed_table_lookup(
    ops: &mut MultiLimbOps,
    table: &[(Limbs, Limbs)],
    index_bits: &[usize],
    sign_bit: usize,
) -> (Limbs, Limbs) {
    let (x, y) = if index_bits.is_empty() {
        // w=1: single entry, no lookup needed
        assert_eq!(table.len(), 1);
        table[0]
    } else {
        // Compute XOR'd index bits: idx_i = 1 - b_i - MSB + 2*b_i*MSB
        let one_w = ops.compiler.witness_one();
        let two = FieldElement::from(2u64);
        let xor_bits: Vec<usize> = index_bits
            .iter()
            .map(|&bit| {
                let prod = ops.compiler.add_product(bit, sign_bit);
                ops.compiler.add_sum(vec![
                    SumTerm(Some(FieldElement::ONE), one_w),
                    SumTerm(Some(-FieldElement::ONE), bit),
                    SumTerm(Some(-FieldElement::ONE), sign_bit),
                    SumTerm(Some(two), prod),
                ])
            })
            .collect();

        // XOR'd bits are boolean by construction (product of two booleans
        // combined linearly), so skip redundant boolean constraints.
        table_lookup_unchecked(ops, table, &xor_bits)
    };

    // Conditionally negate y: sign_bit=0 (negative) → -y, sign_bit=1 (positive) → y
    let neg_y = ops.negate(y);
    let eff_y = ops.select_unchecked(sign_bit, neg_y, y);
    // select_unchecked(flag, on_false, on_true):
    //   sign_bit=0 → on_false=neg_y (negative digit, negate y) ✓
    //   sign_bit=1 → on_true=y (positive digit, keep y) ✓

    (x, eff_y)
}

/// Per-point data for merged multi-point GLV scalar multiplication.
pub struct MergedGlvPoint {
    /// Point P x-coordinate (limbs)
    pub px:      Limbs,
    /// Point P y-coordinate (effective, post-negation)
    pub py:      Limbs,
    /// Signed-bit decomposition of |s1| (half-scalar for P), LSB first
    pub s1_bits: Vec<usize>,
    /// Skew correction witness for s1 branch (boolean)
    pub s1_skew: usize,
    /// Point R x-coordinate (limbs)
    pub rx:      Limbs,
    /// Point R y-coordinate (effective, post-negation)
    pub ry:      Limbs,
    /// Signed-bit decomposition of |s2| (half-scalar for R), LSB first
    pub s2_bits: Vec<usize>,
    /// Skew correction witness for s2 branch (boolean)
    pub s2_skew: usize,
}

/// Merged multi-point GLV scalar multiplication with shared doublings
/// and signed-digit windows.
///
/// Uses signed-digit encoding: each w-bit window produces a signed odd digit
/// d ∈ {±1, ±3, ..., ±(2^w - 1)}, eliminating zero-digit handling.
/// Tables store odd multiples \[P, 3P, 5P, ..., (2^w-1)P\] with only
/// 2^(w-1) entries (half the unsigned table size).
///
/// After the main loop, applies skew corrections: if skew=1, subtracts P
/// (or R) to account for the signed decomposition bias.
///
/// Returns the final accumulator `(x, y)`.
pub fn scalar_mul_merged_glv(
    ops: &mut MultiLimbOps,
    points: &[MergedGlvPoint],
    window_size: usize,
    offset_x: Limbs,
    offset_y: Limbs,
) -> (Limbs, Limbs) {
    assert!(!points.is_empty());
    let n = points[0].s1_bits.len();
    let w = window_size;
    let half_table_size = 1usize << (w - 1);

    // Build signed point tables (odd multiples) for all points upfront
    let tables: Vec<(Vec<(Limbs, Limbs)>, Vec<(Limbs, Limbs)>)> = points
        .iter()
        .map(|pt| {
            let tp = build_signed_point_table(ops, pt.px, pt.py, half_table_size);
            let tr = build_signed_point_table(ops, pt.rx, pt.ry, half_table_size);
            (tp, tr)
        })
        .collect();

    let num_windows = (n + w - 1) / w;
    let mut acc = (offset_x, offset_y);

    // Process all windows from MSB down to LSB
    for i in (0..num_windows).rev() {
        let bit_start = i * w;
        let bit_end = std::cmp::min(bit_start + w, n);
        let actual_w = bit_end - bit_start;

        // w shared doublings on the accumulator (shared across ALL points)
        let mut doubled_acc = acc;
        for _ in 0..w {
            doubled_acc = point_double_dispatch(ops, doubled_acc.0, doubled_acc.1);
        }

        let mut cur = doubled_acc;

        // For each point: P branch + R branch (signed-digit lookup)
        for (pt, (table_p, table_r)) in points.iter().zip(tables.iter()) {
            // --- P branch (s1 window) ---
            let s1_window_bits = &pt.s1_bits[bit_start..bit_end];
            let sign_bit_p = s1_window_bits[actual_w - 1]; // MSB
            let index_bits_p = &s1_window_bits[..actual_w - 1]; // lower bits
            let actual_table_p = if actual_w < w {
                &table_p[..1 << (actual_w - 1)]
            } else {
                &table_p[..]
            };
            let looked_up_p = signed_table_lookup(ops, actual_table_p, index_bits_p, sign_bit_p);
            // All signed digits are non-zero — no is_zero check needed
            cur = point_add_dispatch(ops, cur.0, cur.1, looked_up_p.0, looked_up_p.1);

            // --- R branch (s2 window) ---
            let s2_window_bits = &pt.s2_bits[bit_start..bit_end];
            let sign_bit_r = s2_window_bits[actual_w - 1]; // MSB
            let index_bits_r = &s2_window_bits[..actual_w - 1]; // lower bits
            let actual_table_r = if actual_w < w {
                &table_r[..1 << (actual_w - 1)]
            } else {
                &table_r[..]
            };
            let looked_up_r = signed_table_lookup(ops, actual_table_r, index_bits_r, sign_bit_r);
            cur = point_add_dispatch(ops, cur.0, cur.1, looked_up_r.0, looked_up_r.1);
        }

        acc = cur;
    }

    // Skew corrections: subtract P (or R) if skew=1 for each point.
    // The signed decomposition gives: scalar = Σ d_i * 2^i - skew,
    // so the main loop computed (scalar + skew) * P. If skew=1, subtract P.
    for pt in points {
        // P branch skew
        let neg_py = ops.negate(pt.py);
        let (sub_px, sub_py) = point_add_dispatch(ops, acc.0, acc.1, pt.px, neg_py);
        let new_x = ops.select_unchecked(pt.s1_skew, acc.0, sub_px);
        let new_y = ops.select_unchecked(pt.s1_skew, acc.1, sub_py);
        acc = (new_x, new_y);

        // R branch skew
        let neg_ry = ops.negate(pt.ry);
        let (sub_rx, sub_ry) = point_add_dispatch(ops, acc.0, acc.1, pt.rx, neg_ry);
        let new_x = ops.select_unchecked(pt.s2_skew, acc.0, sub_rx);
        let new_y = ops.select_unchecked(pt.s2_skew, acc.1, sub_ry);
        acc = (new_x, new_y);
    }

    acc
}

// ===========================================================================
// Native-field hint-verified EC operations
// ===========================================================================
// These operate on single native field element witnesses (no multi-limb).
// Each EC op allocates a hint for (lambda, x3, y3) and verifies via raw
// R1CS constraints, eliminating expensive field inversions from the circuit.

/// Hint-verified point doubling for native field.
///
/// Allocates EcDoubleHint → (lambda, x3, y3) = 3W.
/// Verification constraints (4C):
///   1. x_sq = px * px                             (1C via add_product)
///   2. lambda * 2*py = 3*x_sq + a                 (1C raw)
///   3. lambda * lambda = x3 + 2*px                (1C raw)
///   4. lambda * (px - x3) = y3 + py               (1C raw)
///
/// Total: 4W + 4C (1W for x_sq via add_product, 3W from hint).
pub fn point_double_verified_native(
    compiler: &mut NoirToR1CSCompiler,
    px: usize,
    py: usize,
    curve: &CurveParams,
) -> (usize, usize) {
    // Allocate hint witnesses
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcDoubleHint {
        output_start: hint_start,
        px,
        py,
        curve_a: curve.curve_a,
        field_modulus_p: curve.field_modulus_p,
    });
    let lambda = hint_start;
    let x3 = hint_start + 1;
    let y3 = hint_start + 2;

    // x_sq = px * px (1W + 1C)
    let x_sq = compiler.add_product(px, px);

    // Constraint: lambda * (2 * py) = 3 * x_sq + a
    // A = [lambda], B = [2*py], C = [3*x_sq + a_const]
    let a_fe = FieldElement::from_bigint(ark_ff::BigInt(curve.curve_a)).unwrap();
    let three = FieldElement::from(3u64);
    let two = FieldElement::from(2u64);
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, lambda)], &[(two, py)], &[
            (three, x_sq),
            (a_fe, compiler.witness_one()),
        ]);

    // Constraint: lambda^2 = x3 + 2*px
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, x3), (two, px)],
    );

    // Constraint: lambda * (px - x3) = y3 + py
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, px), (-FieldElement::ONE, x3)],
        &[(FieldElement::ONE, y3), (FieldElement::ONE, py)],
    );

    (x3, y3)
}

/// Hint-verified point addition for native field.
///
/// Allocates EcAddHint → (lambda, x3, y3) = 3W.
/// Verification constraints (3C):
///   1. lambda * (x2 - x1) = y2 - y1               (1C raw)
///   2. lambda^2 = x3 + x1 + x2                    (1C raw)
///   3. lambda * (x1 - x3) = y3 + y1               (1C raw)
///
/// Total: 3W + 3C.
pub fn point_add_verified_native(
    compiler: &mut NoirToR1CSCompiler,
    x1: usize,
    y1: usize,
    x2: usize,
    y2: usize,
    curve: &CurveParams,
) -> (usize, usize) {
    // Allocate hint witnesses
    let hint_start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::EcAddHint {
        output_start: hint_start,
        x1,
        y1,
        x2,
        y2,
        field_modulus_p: curve.field_modulus_p,
    });
    let lambda = hint_start;
    let x3 = hint_start + 1;
    let y3 = hint_start + 2;

    // Constraint: lambda * (x2 - x1) = y2 - y1
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, x2), (-FieldElement::ONE, x1)],
        &[(FieldElement::ONE, y2), (-FieldElement::ONE, y1)],
    );

    // Constraint: lambda^2 = x3 + x1 + x2
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, lambda)],
        &[
            (FieldElement::ONE, x3),
            (FieldElement::ONE, x1),
            (FieldElement::ONE, x2),
        ],
    );

    // Constraint: lambda * (x1 - x3) = y3 + y1
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(FieldElement::ONE, x1), (-FieldElement::ONE, x3)],
        &[(FieldElement::ONE, y3), (FieldElement::ONE, y1)],
    );

    (x3, y3)
}

/// On-curve check for native field: y^2 = x^3 + a*x + b.
///
/// Constraints (3C, 2W):
///   1. x_sq = x * x                                (1C via add_product)
///   2. x_cu = x_sq * x                             (1C via add_product)
///   3. y * y = x_cu + a*x + b                      (1C raw)
///
/// Total: 2W + 3C.
pub fn verify_on_curve_native(
    compiler: &mut NoirToR1CSCompiler,
    x: usize,
    y: usize,
    curve: &CurveParams,
) {
    let x_sq = compiler.add_product(x, x);
    let x_cu = compiler.add_product(x_sq, x);

    let a_fe = FieldElement::from_bigint(ark_ff::BigInt(curve.curve_a)).unwrap();
    let b_fe = FieldElement::from_bigint(ark_ff::BigInt(curve.curve_b)).unwrap();

    // y * y = x_cu + a*x + b
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, y)], &[(FieldElement::ONE, y)], &[
            (FieldElement::ONE, x_cu),
            (a_fe, x),
            (b_fe, compiler.witness_one()),
        ]);
}

// ===========================================================================
// Non-native hint-verified EC operations (multi-limb schoolbook)
// ===========================================================================
// These replace the step-by-step MultiLimbOps chain with prover hints verified
// via schoolbook column equations. Each bilinear mod-p equation is checked by:
// 1. Pre-computing product witnesses a[i]*b[j]
// 2. Column equations: Σ coeff·prod[k] + linear[k] + carry_in + offset = Σ
//    p[i]*q[j] + carry_out * W
// Since p is constant, p[i]*q[j] terms are linear in q (no product witness).

/// Collect witness indices from `start..start+len`.
fn witness_range(start: usize, len: usize) -> Vec<usize> {
    (start..start + len).collect()
}

/// Allocate N×N product witnesses for `a[i]*b[j]`.
fn make_products(compiler: &mut NoirToR1CSCompiler, a: &[usize], b: &[usize]) -> Vec<Vec<usize>> {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    let mut prods = vec![vec![0usize; n]; n];
    for i in 0..n {
        for j in 0..n {
            prods[i][j] = compiler.add_product(a[i], b[j]);
        }
    }
    prods
}

/// Allocate pinned constant witnesses from pre-decomposed `FieldElement` limbs.
fn allocate_pinned_constant_limbs(
    compiler: &mut NoirToR1CSCompiler,
    limb_values: &[FieldElement],
) -> Vec<usize> {
    limb_values
        .iter()
        .map(|&val| {
            let w = compiler.num_witnesses();
            compiler.add_witness_builder(WitnessBuilder::Constant(
                provekit_common::witness::ConstantTerm(w, val),
            ));
            compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, compiler.witness_one())],
                &[(FieldElement::ONE, w)],
                &[(val, compiler.witness_one())],
            );
            w
        })
        .collect()
}

/// Range-check limb witnesses at `limb_bits` and carry witnesses at
/// `carry_range_bits`.
fn range_check_limbs_and_carries(
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    limb_vecs: &[&[usize]],
    carry_vecs: &[&[usize]],
    limb_bits: u32,
    carry_range_bits: u32,
) {
    for limbs in limb_vecs {
        for &w in *limbs {
            range_checks.entry(limb_bits).or_default().push(w);
        }
    }
    for carries in carry_vecs {
        for &c in *carries {
            range_checks.entry(carry_range_bits).or_default().push(c);
        }
    }
}

/// Convert `Vec<usize>` to `Limbs` and do a less-than-p check.
fn less_than_p_check_vec(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    v: &[usize],
    params: &MultiLimbParams,
) {
    let n = v.len();
    let mut limbs = Limbs::new(n);
    for i in 0..n {
        limbs[i] = v[i];
    }
    less_than_p_check_multi(
        compiler,
        range_checks,
        limbs,
        &params.p_minus_1_limbs,
        params.two_pow_w,
        params.limb_bits,
    );
}

/// Emit schoolbook column equations for a merged verification equation.
///
/// Verifies: Σ (coeff_i × A_i ⊗ B_i) + Σ linear_k = q·p  (mod p, as integers)
///
/// `product_sets`: each (products_2d, coefficient) where products_2d[i][j]
///   is the witness index for a[i]*b[j].
/// `linear_limbs`: each (limb_witnesses, coefficient) for non-product terms
///   (limb_witnesses has N entries, zero-padded).
/// `q_witnesses`: quotient limbs (N entries).
/// `carry_witnesses`: unsigned-offset carry witnesses (2N-2 entries).
fn emit_schoolbook_column_equations(
    compiler: &mut NoirToR1CSCompiler,
    product_sets: &[(&[Vec<usize>], FieldElement)], // (products[i][j], coeff)
    linear_limbs: &[(&[usize], FieldElement)],      // (limb_witnesses, coeff)
    q_witnesses: &[usize],
    carry_witnesses: &[usize],
    p_limbs: &[FieldElement],
    n: usize,
    limb_bits: u32,
    max_coeff_sum: u64,
) {
    let w1 = compiler.witness_one();
    let two_pow_w = FieldElement::from(2u64).pow([limb_bits as u64]);

    // Carry offset scaled for the merged equation's larger coefficients
    let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
    let carry_offset_bits = limb_bits + extra_bits;
    let carry_offset_fe = FieldElement::from(2u64).pow([carry_offset_bits as u64]);
    let offset_w = FieldElement::from(2u64).pow([(carry_offset_bits + limb_bits) as u64]);
    let offset_w_minus_carry = offset_w - carry_offset_fe;

    let num_columns = 2 * n - 1;

    for k in 0..num_columns {
        // LHS: Σ coeff * products[i][j] for i+j=k + carry_in + offset
        let mut lhs_terms: Vec<(FieldElement, usize)> = Vec::new();

        for &(products, coeff) in product_sets {
            for i in 0..n {
                let j_val = k as isize - i as isize;
                if j_val >= 0 && (j_val as usize) < n {
                    lhs_terms.push((coeff, products[i][j_val as usize]));
                }
            }
        }

        // Add linear terms (for k < N only, since linear_limbs are N-length)
        for &(limbs, coeff) in linear_limbs {
            if k < limbs.len() {
                lhs_terms.push((coeff, limbs[k]));
            }
        }

        // Add carry_in and offset
        if k > 0 {
            lhs_terms.push((FieldElement::ONE, carry_witnesses[k - 1]));
            lhs_terms.push((offset_w_minus_carry, w1));
        } else {
            lhs_terms.push((offset_w, w1));
        }

        // RHS: Σ p[i]*q[j] for i+j=k + carry_out * W (or offset at last column)
        let mut rhs_terms: Vec<(FieldElement, usize)> = Vec::new();
        for i in 0..n {
            let j_val = k as isize - i as isize;
            if j_val >= 0 && (j_val as usize) < n {
                rhs_terms.push((p_limbs[i], q_witnesses[j_val as usize]));
            }
        }

        if k < num_columns - 1 {
            rhs_terms.push((two_pow_w, carry_witnesses[k]));
        } else {
            // Last column: balance with offset_w (no outgoing carry)
            rhs_terms.push((offset_w, w1));
        }

        compiler
            .r1cs
            .add_constraint(&lhs_terms, &[(FieldElement::ONE, w1)], &rhs_terms);
    }
}

/// Hint-verified on-curve check for non-native field (multi-limb).
///
/// Verifies y² = x³ + ax + b (mod p) via:
///   Eq1: x·x - x_sq = q1·p  (x_sq correctness)
///   Eq2: y·y - x_sq·x - a·x - b = q2·p  (on-curve)
///
/// Total: (7N-4)W hint + (N² + 2N² [+ N²])products + 2×(2N-1) constraints
///        + 1 less-than-p check.
pub fn verify_on_curve_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    params: &MultiLimbParams,
) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified on-curve check requires n >= 2");

    let a_is_zero = params.curve_a_raw.iter().all(|&v| v == 0);

    // Soundness check
    {
        // max terms in a column: px·px(1) + x_sq(1) + py·py(1) + x_sq·px(1) + [a·px(1)]
        // + b(1) + pq(N)
        let max_coeff_sum: u64 = if a_is_zero {
            4 + n as u64
        } else {
            5 + n as u64
        };
        let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
        let max_bits = 2 * params.limb_bits + extra_bits + 1;
        assert!(
            max_bits < FieldElement::MODULUS_BIT_SIZE,
            "On-curve column equation overflow: limb_bits={}, n={n}, needs {max_bits} bits",
            params.limb_bits
        );
    }

    // Allocate hint
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::OnCurve,
        inputs:          vec![px.as_slice()[..n].to_vec(), py.as_slice()[..n].to_vec()],
        curve_a:         params.curve_a_raw,
        curve_b:         params.curve_b_raw,
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    // Parse hint layout: [x_sq(N), q1(N), c1(2N-2), q2(N), c2(2N-2)]
    let x_sq = witness_range(os, n);
    let q1 = witness_range(os + n, n);
    let c1 = witness_range(os + 2 * n, 2 * n - 2);
    let q2 = witness_range(os + 4 * n - 2, n);
    let c2 = witness_range(os + 5 * n - 2, 2 * n - 2);

    // Eq1: px·px - x_sq = q1·p
    let prod_px_px = make_products(compiler, &px.as_slice()[..n], &px.as_slice()[..n]);

    let max_coeff_eq1: u64 = 1 + 1 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_px_px, FieldElement::ONE)],
        &[(&x_sq, -FieldElement::ONE)],
        &q1,
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq1,
    );

    // Eq2: py·py - x_sq·px - a·px - b = q2·p
    let prod_py_py = make_products(compiler, &py.as_slice()[..n], &py.as_slice()[..n]);
    let prod_xsq_px = make_products(compiler, &x_sq, &px.as_slice()[..n]);
    let b_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_b_limbs[..n]);

    if a_is_zero {
        let max_coeff_eq2: u64 = 1 + 1 + 1 + n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
            ],
            &[(&b_limbs, -FieldElement::ONE)],
            &q2,
            &c2,
            &params.p_limbs,
            n,
            params.limb_bits,
            max_coeff_eq2,
        );
    } else {
        let a_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_a_limbs[..n]);
        let prod_a_px = make_products(compiler, &a_limbs, &px.as_slice()[..n]);

        let max_coeff_eq2: u64 = 1 + 1 + 1 + 1 + n as u64;
        emit_schoolbook_column_equations(
            compiler,
            &[
                (&prod_py_py, FieldElement::ONE),
                (&prod_xsq_px, -FieldElement::ONE),
                (&prod_a_px, -FieldElement::ONE),
            ],
            &[(&b_limbs, -FieldElement::ONE)],
            &q2,
            &c2,
            &params.p_limbs,
            n,
            params.limb_bits,
            max_coeff_eq2,
        );
    }

    // Range checks on hint outputs
    let max_coeff = if a_is_zero {
        4 + n as u64
    } else {
        5 + n as u64
    };
    let carry_extra_bits = ((max_coeff as f64 * n as f64).log2().ceil() as u32) + 1;
    let carry_range_bits = params.limb_bits + carry_extra_bits;
    range_check_limbs_and_carries(
        range_checks,
        &[&x_sq, &q1, &q2],
        &[&c1, &c2],
        params.limb_bits,
        carry_range_bits,
    );

    // Less-than-p check for x_sq
    less_than_p_check_vec(compiler, range_checks, &x_sq, params);
}

/// Hint-verified point doubling for non-native field (multi-limb).
///
/// Allocates NonNativeEcDoubleHint → (lambda, x3, y3, q1, c1, q2, c2, q3, c3).
/// Verifies via schoolbook column equations on 3 EC verification equations.
/// Total: (12N-6)W hint + ~(4N²+N) products + 3×(2N-1) column constraints
///        + 3 less-than-p checks.
pub fn point_double_verified_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    px: Limbs,
    py: Limbs,
    params: &MultiLimbParams,
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified non-native requires n >= 2");

    // Soundness check: merged column equations fit native field
    {
        let max_coeff_sum: u64 = 2 + 3 + 1 + n as u64; // λy(2) + xx(3) + a(1) + pq(N)
        let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
        let max_bits = 2 * params.limb_bits + extra_bits + 1;
        assert!(
            max_bits < FieldElement::MODULUS_BIT_SIZE,
            "Merged EC column equation overflow: limb_bits={}, n={n}, needs {max_bits} bits",
            params.limb_bits
        );
    }

    // Allocate hint
    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::Double,
        inputs:          vec![px.as_slice()[..n].to_vec(), py.as_slice()[..n].to_vec()],
        curve_a:         params.curve_a_raw,
        curve_b:         [0; 4], // unused for double
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    // Parse hint layout: [lambda(N), x3(N), y3(N), q1(N), c1(2N-2), q2(N),
    // c2(2N-2), q3(N), c3(2N-2)]
    let lambda = witness_range(os, n);
    let x3 = witness_range(os + n, n);
    let y3 = witness_range(os + 2 * n, n);
    let q1 = witness_range(os + 3 * n, n);
    let c1 = witness_range(os + 4 * n, 2 * n - 2);
    let q2 = witness_range(os + 6 * n - 2, n);
    let c2 = witness_range(os + 7 * n - 2, 2 * n - 2);
    let q3 = witness_range(os + 9 * n - 4, n);
    let c3 = witness_range(os + 10 * n - 4, 2 * n - 2);

    let px_s = &px.as_slice()[..n];
    let py_s = &py.as_slice()[..n];

    // Eq1: 2*lambda*py - 3*px*px - a = q1*p
    let prod_lam_py = make_products(compiler, &lambda, py_s);
    let prod_px_px = make_products(compiler, px_s, px_s);
    let a_limbs = allocate_pinned_constant_limbs(compiler, &params.curve_a_limbs[..n]);

    let max_coeff_eq1: u64 = 2 + 3 + 1 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_py, FieldElement::from(2u64)),
            (&prod_px_px, -FieldElement::from(3u64)),
        ],
        &[(&a_limbs, -FieldElement::ONE)],
        &q1,
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq1,
    );

    // Eq2: lambda² - x3 - 2*px = q2*p
    let prod_lam_lam = make_products(compiler, &lambda, &lambda);

    let max_coeff_eq2: u64 = 1 + 1 + 2 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_lam_lam, FieldElement::ONE)],
        &[(&x3, -FieldElement::ONE), (px_s, -FieldElement::from(2u64))],
        &q2,
        &c2,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq2,
    );

    // Eq3: lambda*px - lambda*x3 - y3 - py = q3*p
    let prod_lam_px = make_products(compiler, &lambda, px_s);
    let prod_lam_x3 = make_products(compiler, &lambda, &x3);

    let max_coeff_eq3: u64 = 1 + 1 + 1 + 1 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_px, FieldElement::ONE),
            (&prod_lam_x3, -FieldElement::ONE),
        ],
        &[(&y3, -FieldElement::ONE), (py_s, -FieldElement::ONE)],
        &q3,
        &c3,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff_eq3,
    );

    // Range checks on hint outputs
    // max_coeff across eqs: Eq1 = 6+N, Eq2 = 4+N, Eq3 = 4+N → worst = 6+N
    let max_coeff_carry = 6u64 + n as u64;
    let carry_extra_bits = ((max_coeff_carry as f64 * n as f64).log2().ceil() as u32) + 1;
    let carry_range_bits = params.limb_bits + carry_extra_bits;
    range_check_limbs_and_carries(
        range_checks,
        &[&lambda, &x3, &y3, &q1, &q2, &q3],
        &[&c1, &c2, &c3],
        params.limb_bits,
        carry_range_bits,
    );

    // Less-than-p checks for lambda, x3, y3
    less_than_p_check_vec(compiler, range_checks, &lambda, params);
    less_than_p_check_vec(compiler, range_checks, &x3, params);
    less_than_p_check_vec(compiler, range_checks, &y3, params);

    let mut x3_limbs = Limbs::new(n);
    let mut y3_limbs = Limbs::new(n);
    for i in 0..n {
        x3_limbs[i] = x3[i];
        y3_limbs[i] = y3[i];
    }
    (x3_limbs, y3_limbs)
}

/// Hint-verified point addition for non-native field (multi-limb).
///
/// Same approach as `point_double_verified_non_native` but verifies:
///   Eq1: lambda*(x2-x1) = y2-y1 (mod p)
///   Eq2: lambda² = x3+x1+x2 (mod p)
///   Eq3: lambda*(x1-x3) = y3+y1 (mod p)
pub fn point_add_verified_non_native(
    compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x1: Limbs,
    y1: Limbs,
    x2: Limbs,
    y2: Limbs,
    params: &MultiLimbParams,
) -> (Limbs, Limbs) {
    let n = params.num_limbs;
    assert!(n >= 2, "hint-verified non-native requires n >= 2");

    // Soundness check: column equations fit native field
    {
        let max_coeff_sum: u64 = 4 + n as u64; // all 3 eqs: 1+1+1+1+N
        let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
        let max_bits = 2 * params.limb_bits + extra_bits + 1;
        assert!(
            max_bits < FieldElement::MODULUS_BIT_SIZE,
            "EC add column equation overflow: limb_bits={}, n={n}, needs {max_bits} bits",
            params.limb_bits
        );
    }

    let os = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::NonNativeEcHint {
        output_start:    os,
        op:              NonNativeEcOp::Add,
        inputs:          vec![
            x1.as_slice()[..n].to_vec(),
            y1.as_slice()[..n].to_vec(),
            x2.as_slice()[..n].to_vec(),
            y2.as_slice()[..n].to_vec(),
        ],
        curve_a:         [0; 4], // unused for add
        curve_b:         [0; 4], // unused for add
        field_modulus_p: params.modulus_raw,
        limb_bits:       params.limb_bits,
        num_limbs:       n as u32,
    });

    let lambda = witness_range(os, n);
    let x3 = witness_range(os + n, n);
    let y3 = witness_range(os + 2 * n, n);
    let q1 = witness_range(os + 3 * n, n);
    let c1 = witness_range(os + 4 * n, 2 * n - 2);
    let q2 = witness_range(os + 6 * n - 2, n);
    let c2 = witness_range(os + 7 * n - 2, 2 * n - 2);
    let q3 = witness_range(os + 9 * n - 4, n);
    let c3 = witness_range(os + 10 * n - 4, 2 * n - 2);

    let x1_s = &x1.as_slice()[..n];
    let y1_s = &y1.as_slice()[..n];
    let x2_s = &x2.as_slice()[..n];
    let y2_s = &y2.as_slice()[..n];

    // Eq1: lambda*x2 - lambda*x1 - y2 + y1 = q1*p
    let prod_lam_x2 = make_products(compiler, &lambda, x2_s);
    let prod_lam_x1 = make_products(compiler, &lambda, x1_s);

    let max_coeff: u64 = 1 + 1 + 1 + 1 + n as u64;
    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_x2, FieldElement::ONE),
            (&prod_lam_x1, -FieldElement::ONE),
        ],
        &[(y2_s, -FieldElement::ONE), (y1_s, FieldElement::ONE)],
        &q1,
        &c1,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff,
    );

    // Eq2: lambda² - x3 - x1 - x2 = q2*p
    let prod_lam_lam = make_products(compiler, &lambda, &lambda);

    emit_schoolbook_column_equations(
        compiler,
        &[(&prod_lam_lam, FieldElement::ONE)],
        &[
            (&x3, -FieldElement::ONE),
            (x1_s, -FieldElement::ONE),
            (x2_s, -FieldElement::ONE),
        ],
        &q2,
        &c2,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff,
    );

    // Eq3: lambda*x1 - lambda*x3 - y3 - y1 = q3*p
    // Reuse prod_lam_x1 from Eq1
    let prod_lam_x3 = make_products(compiler, &lambda, &x3);

    emit_schoolbook_column_equations(
        compiler,
        &[
            (&prod_lam_x1, FieldElement::ONE),
            (&prod_lam_x3, -FieldElement::ONE),
        ],
        &[(&y3, -FieldElement::ONE), (y1_s, -FieldElement::ONE)],
        &q3,
        &c3,
        &params.p_limbs,
        n,
        params.limb_bits,
        max_coeff,
    );

    // Range checks
    // max_coeff across all 3 eqs = 4+N
    let max_coeff_carry = 4u64 + n as u64;
    let carry_extra_bits = ((max_coeff_carry as f64 * n as f64).log2().ceil() as u32) + 1;
    let carry_range_bits = params.limb_bits + carry_extra_bits;
    range_check_limbs_and_carries(
        range_checks,
        &[&lambda, &x3, &y3, &q1, &q2, &q3],
        &[&c1, &c2, &c3],
        params.limb_bits,
        carry_range_bits,
    );

    // Less-than-p checks
    less_than_p_check_vec(compiler, range_checks, &lambda, params);
    less_than_p_check_vec(compiler, range_checks, &x3, params);
    less_than_p_check_vec(compiler, range_checks, &y3, params);

    let mut x3_limbs = Limbs::new(n);
    let mut y3_limbs = Limbs::new(n);
    for i in 0..n {
        x3_limbs[i] = x3[i];
        y3_limbs[i] = y3[i];
    }
    (x3_limbs, y3_limbs)
}
