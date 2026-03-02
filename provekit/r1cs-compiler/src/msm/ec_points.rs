use super::FieldOps;

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

/// Conditional point select: returns `on_true` if `flag` is 1, `on_false` if
/// `flag` is 0.
///
/// Constrains `flag` to be boolean (`flag * flag = flag`).
pub fn point_select<F: FieldOps>(
    ops: &mut F,
    flag: usize,
    on_false: (F::Elem, F::Elem),
    on_true: (F::Elem, F::Elem),
) -> (F::Elem, F::Elem) {
    let x = ops.select(flag, on_false.0, on_true.0);
    let y = ops.select(flag, on_false.1, on_true.1);
    (x, y)
}

/// Point addition with safe denominator for the `x1 = x2` edge case.
///
/// When `x_eq = 1`, the denominator `(x2 - x1)` is zero and cannot be
/// inverted. This function replaces it with 1, producing a satisfiable
/// but meaningless result. The caller MUST discard this result via
/// `point_select` when `x_eq = 1`.
///
/// The `denom` parameter is the precomputed `x2 - x1`.
fn safe_point_add<F: FieldOps>(
    ops: &mut F,
    x1: F::Elem,
    y1: F::Elem,
    x2: F::Elem,
    y2: F::Elem,
    denom: F::Elem,
    x_eq: usize,
) -> (F::Elem, F::Elem) {
    let numerator = ops.sub(y2, y1);

    // When x_eq=1 (denom=0), substitute with 1 to keep inv satisfiable
    let one = ops.constant_one();
    let safe_denom = ops.select(x_eq, denom, one);

    let denom_inv = ops.inv(safe_denom);
    let lambda = ops.mul(numerator, denom_inv);

    let lambda_sq = ops.mul(lambda, lambda);
    let x1_plus_x2 = ops.add(x1, x2);
    let x3 = ops.sub(lambda_sq, x1_plus_x2);

    let x1_minus_x3 = ops.sub(x1, x3);
    let lambda_dx = ops.mul(lambda, x1_minus_x3);
    let y3 = ops.sub(lambda_dx, y1);

    (x3, y3)
}

/// Builds a point table for windowed scalar multiplication.
///
/// T[0] = P (dummy entry, used when window digit = 0)
/// T[1] = P, T[2] = 2P, T[i] = T[i-1] + P for i >= 3.
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

/// Selects T[d] from a point table using bit witnesses, where `d = Σ bits[i] * 2^i`.
///
/// Uses a binary tree of `point_select`s: processes bits from MSB to LSB,
/// halving the candidate set at each level. Total: `(2^w - 1)` point selects
/// for a table of `2^w` entries.
fn table_lookup<F: FieldOps>(
    ops: &mut F,
    table: &[(F::Elem, F::Elem)],
    bits: &[usize],
) -> (F::Elem, F::Elem) {
    assert_eq!(table.len(), 1 << bits.len());
    let mut current: Vec<(F::Elem, F::Elem)> = table.to_vec();
    // Process bits from MSB to LSB
    for &bit in bits.iter().rev() {
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            next.push(point_select(ops, bit, current[i], current[i + half]));
        }
        current = next;
    }
    current[0]
}

/// Windowed scalar multiplication: computes `[scalar] * P`.
///
/// Takes pre-decomposed scalar bits (LSB first, `scalar_bits[0]` is the
/// least significant bit) and a window size `w`. Precomputes a table of
/// `2^w` point multiples and processes the scalar in `w`-bit windows from
/// MSB to LSB.
///
/// Handles two edge cases:
/// 1. **MSB window digit = 0**: The accumulator is initialized from T[0]
///    (a dummy copy of P). An `acc_is_identity` flag tracks that no real
///    point has been accumulated yet. When the first non-zero window digit
///    is encountered, the looked-up point becomes the new accumulator.
/// 2. **x-coordinate collision** (`acc.x == looked_up.x`): Uses
///    `point_double` instead of `point_add`, with `safe_point_add`
///    guarding the zero denominator.
///
/// The inverse-point case (`acc = -looked_up`, result is infinity) cannot
/// be represented in affine coordinates and remains unsupported — this has
/// negligible probability (~2^{-256}) for random scalars.
pub fn scalar_mul<F: FieldOps>(
    ops: &mut F,
    px: F::Elem,
    py: F::Elem,
    scalar_bits: &[usize],
    window_size: usize,
) -> (F::Elem, F::Elem) {
    let n = scalar_bits.len();
    let w = window_size;
    let table_size = 1 << w;

    // Build point table: T[i] = [i]P, with T[0] = P as dummy
    let table = build_point_table(ops, px, py, table_size);

    // Number of windows (ceiling division)
    let num_windows = (n + w - 1) / w;

    // Process MSB window first (may be shorter than w bits if n % w != 0)
    let msb_start = (num_windows - 1) * w;
    let msb_bits = &scalar_bits[msb_start..n];
    let msb_table = &table[..1 << msb_bits.len()];
    let mut acc = table_lookup(ops, msb_table, msb_bits);

    // Track whether acc represents the identity (no real point yet).
    // When MSB digit = 0, T[0] = P is loaded as a dummy — we must not
    // double or add it until the first non-zero window digit appears.
    let msb_digit = ops.pack_bits(msb_bits);
    let mut acc_is_identity = ops.is_zero(msb_digit);

    // Process remaining windows from MSB-1 down to LSB
    for i in (0..num_windows - 1).rev() {
        // w doublings — only meaningful when acc is a real point.
        // When acc_is_identity=1, the doubling result is garbage but will
        // be discarded by the point_select below.
        let mut doubled_acc = acc;
        for _ in 0..w {
            doubled_acc = point_double(ops, doubled_acc.0, doubled_acc.1);
        }
        // If acc is identity, keep dummy; otherwise use doubled result
        acc = point_select(ops, acc_is_identity, doubled_acc, acc);

        // Table lookup for this window's digit
        let window_bits = &scalar_bits[i * w..(i + 1) * w];
        let digit = ops.pack_bits(window_bits);
        let digit_is_zero = ops.is_zero(digit);

        let looked_up = table_lookup(ops, &table, window_bits);

        // Detect x-coordinate collision: acc.x == looked_up.x
        let denom = ops.sub(looked_up.0, acc.0);
        let x_eq = ops.elem_is_zero(denom);

        // point_double handles the acc == looked_up case (same point)
        let doubled = point_double(ops, acc.0, acc.1);

        // Safe point_add (substitutes denominator when x_eq=1)
        let added = safe_point_add(
            ops, acc.0, acc.1, looked_up.0, looked_up.1, denom, x_eq,
        );

        // x_eq=0 => use add result, x_eq=1 => use double result
        let combined = point_select(ops, x_eq, added, doubled);

        // Four cases based on (acc_is_identity, digit_is_zero):
        //   (0, 0) => combined      — normal add/double
        //   (0, 1) => acc           — keep accumulator
        //   (1, 0) => looked_up     — first real point
        //   (1, 1) => acc           — still identity
        let normal_result = point_select(ops, digit_is_zero, combined, acc);
        let identity_result = point_select(ops, digit_is_zero, looked_up, acc);
        acc = point_select(ops, acc_is_identity, normal_result, identity_result);

        // Update: acc is identity only if it was identity AND digit is zero
        acc_is_identity = ops.bool_and(acc_is_identity, digit_is_zero);
    }

    acc
}
