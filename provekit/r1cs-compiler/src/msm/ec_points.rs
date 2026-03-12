use {
    super::{curve::CurveParams, multi_limb_ops::MultiLimbOps, Limbs},
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::{Field, PrimeField},
    provekit_common::{
        witness::{SumTerm, WitnessBuilder},
        FieldElement,
    },
};

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
        let two_p = point_double(ops, px, py); // 2P
        for i in 1..half_table_size {
            let prev = table[i - 1];
            table.push(point_add(ops, prev.0, prev.1, two_p.0, two_p.1));
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
            doubled_acc = point_double(ops, doubled_acc.0, doubled_acc.1);
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
            cur = point_add(ops, cur.0, cur.1, looked_up_p.0, looked_up_p.1);

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
            cur = point_add(ops, cur.0, cur.1, looked_up_r.0, looked_up_r.1);
        }

        acc = cur;
    }

    // Skew corrections: subtract P (or R) if skew=1 for each point.
    // The signed decomposition gives: scalar = Σ d_i * 2^i - skew,
    // so the main loop computed (scalar + skew) * P. If skew=1, subtract P.
    for pt in points {
        // P branch skew
        let neg_py = ops.negate(pt.py);
        let (sub_px, sub_py) = point_add(ops, acc.0, acc.1, pt.px, neg_py);
        let new_x = ops.select_unchecked(pt.s1_skew, acc.0, sub_px);
        let new_y = ops.select_unchecked(pt.s1_skew, acc.1, sub_py);
        acc = (new_x, new_y);

        // R branch skew
        let neg_ry = ops.negate(pt.ry);
        let (sub_rx, sub_ry) = point_add(ops, acc.0, acc.1, pt.rx, neg_ry);
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
