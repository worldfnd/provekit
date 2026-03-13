//! Generic point operations using `MultiLimbOps` field arithmetic.
//!
//! These work for any field (native or non-native) by going through the
//! `MultiLimbOps` abstraction layer.

use crate::msm::{multi_limb_ops::MultiLimbOps, Limbs};

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
