use {
    super::{select_witness, FieldOps},
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    provekit_common::{witness::WitnessBuilder, FieldElement},
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
pub fn point_double<F: FieldOps>(ops: &mut F, x1: F::Elem, y1: F::Elem) -> (F::Elem, F::Elem) {
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
pub fn point_add<F: FieldOps>(
    ops: &mut F,
    x1: F::Elem,
    y1: F::Elem,
    x2: F::Elem,
    y2: F::Elem,
) -> (F::Elem, F::Elem) {
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
pub fn point_select_unchecked<F: FieldOps>(
    ops: &mut F,
    flag: usize,
    on_false: (F::Elem, F::Elem),
    on_true: (F::Elem, F::Elem),
) -> (F::Elem, F::Elem) {
    let x = ops.select_unchecked(flag, on_false.0, on_true.0);
    let y = ops.select_unchecked(flag, on_false.1, on_true.1);
    (x, y)
}

/// Builds a point table for windowed scalar multiplication.
///
/// T\[0\] = P (dummy entry, used when window digit = 0)
/// T\[1\] = P, T\[2\] = 2P, T\[i\] = T\[i-1\] + P for i >= 3.
fn build_point_table<F: FieldOps>(
    ops: &mut F,
    px: F::Elem,
    py: F::Elem,
    table_size: usize,
) -> Vec<(F::Elem, F::Elem)> {
    assert!(table_size >= 2);
    let mut table = Vec::with_capacity(table_size);
    table.push((px, py)); // T[0] = P (dummy)
    table.push((px, py)); // T[1] = P
    if table_size > 2 {
        table.push(point_double(ops, px, py)); // T[2] = 2P
        for i in 3..table_size {
            let prev = table[i - 1];
            table.push(point_add(ops, prev.0, prev.1, px, py));
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
fn table_lookup<F: FieldOps>(
    ops: &mut F,
    table: &[(F::Elem, F::Elem)],
    bits: &[usize],
) -> (F::Elem, F::Elem) {
    assert_eq!(table.len(), 1 << bits.len());
    let mut current: Vec<(F::Elem, F::Elem)> = table.to_vec();
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

/// Interleaved two-point scalar multiplication for FakeGLV.
///
/// Computes `[s1]P + [s2]R` using shared doublings, where s1 and s2 are
/// half-width scalars (typically ~128-bit for 256-bit curves). The
/// accumulator starts at an offset point and the caller checks equality
/// with the accumulated offset to verify the constraint `[s1]P + [s2]R = O`.
///
/// Structure per window (from MSB to LSB):
///   1. `w` shared doublings on accumulator
///   2. Table lookup in T_P\[d1\] for s1's window digit
///   3. point_add(acc, T_P\[d1\]) + is_zero(d1) + point_select
///   4. Table lookup in T_R\[d2\] for s2's window digit
///   5. point_add(acc, T_R\[d2\]) + is_zero(d2) + point_select
///
/// Returns the final accumulator (x, y).
pub fn scalar_mul_glv<F: FieldOps>(
    ops: &mut F,
    // Point P (table 1)
    px: F::Elem,
    py: F::Elem,
    s1_bits: &[usize], // 128 bit witnesses for |s1|
    // Point R (table 2) — the claimed output
    rx: F::Elem,
    ry: F::Elem,
    s2_bits: &[usize], // 128 bit witnesses for |s2|
    // Shared parameters
    window_size: usize,
    offset_x: F::Elem,
    offset_y: F::Elem,
) -> (F::Elem, F::Elem) {
    let n1 = s1_bits.len();
    let n2 = s2_bits.len();
    assert_eq!(n1, n2, "s1 and s2 must have the same number of bits");
    let n = n1;
    let w = window_size;
    let table_size = 1 << w;

    // TODO : implement lazy overflow as used in gnark.

    // Build point tables: T_P[i] = [i]P, T_R[i] = [i]R
    let table_p = build_point_table(ops, px, py, table_size);
    let table_r = build_point_table(ops, rx, ry, table_size);

    let num_windows = (n + w - 1) / w;

    // Initialize accumulator with the offset point
    let mut acc = (offset_x, offset_y);

    // Process all windows from MSB down to LSB
    for i in (0..num_windows).rev() {
        let bit_start = i * w;
        let bit_end = std::cmp::min(bit_start + w, n);
        let actual_w = bit_end - bit_start;

        // w shared doublings on the accumulator
        let mut doubled_acc = acc;
        for _ in 0..w {
            doubled_acc = point_double(ops, doubled_acc.0, doubled_acc.1);
        }

        // --- Process P's window digit (s1) ---
        let s1_window_bits = &s1_bits[bit_start..bit_end];
        let lookup_table_p = if actual_w < w {
            &table_p[..1 << actual_w]
        } else {
            &table_p[..]
        };
        let looked_up_p = table_lookup(ops, lookup_table_p, s1_window_bits);
        let added_p = point_add(
            ops,
            doubled_acc.0,
            doubled_acc.1,
            looked_up_p.0,
            looked_up_p.1,
        );
        let digit_p = ops.pack_bits(s1_window_bits);
        let digit_p_is_zero = ops.is_zero(digit_p);
        // is_zero already constrains its output boolean; skip redundant check
        let after_p = point_select_unchecked(ops, digit_p_is_zero, added_p, doubled_acc);

        // --- Process R's window digit (s2) ---
        let s2_window_bits = &s2_bits[bit_start..bit_end];
        let lookup_table_r = if actual_w < w {
            &table_r[..1 << actual_w]
        } else {
            &table_r[..]
        };
        let looked_up_r = table_lookup(ops, lookup_table_r, s2_window_bits);
        let added_r = point_add(ops, after_p.0, after_p.1, looked_up_r.0, looked_up_r.1);
        let digit_r = ops.pack_bits(s2_window_bits);
        let digit_r_is_zero = ops.is_zero(digit_r);
        // is_zero already constrains its output boolean; skip redundant check
        acc = point_select_unchecked(ops, digit_r_is_zero, added_r, after_p);
    }

    acc
}

// ===========================================================================
// Native-field hint-verified EC operations
// ===========================================================================
// These operate on single native field element witnesses (no multi-limb).
// Each EC op allocates a hint for (lambda, x3, y3) and verifies via raw
// R1CS constraints, eliminating expensive field inversions from the circuit.

use super::curve::CurveParams;
use ark_ff::{Field, PrimeField};

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
        output_start:    hint_start,
        px,
        py,
        curve_a:         curve.curve_a,
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
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, lambda)],
        &[(two, py)],
        &[(three, x_sq), (a_fe, compiler.witness_one())],
    );

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
        output_start:    hint_start,
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
        &[(FieldElement::ONE, x3), (FieldElement::ONE, x1), (FieldElement::ONE, x2)],
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
    compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, y)],
        &[(FieldElement::ONE, y)],
        &[
            (FieldElement::ONE, x_cu),
            (a_fe, x),
            (b_fe, compiler.witness_one()),
        ],
    );
}

