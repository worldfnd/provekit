//! Analytical cost model for MSM parameter optimization.
//!
//! Follows the SHA256 pattern (`spread.rs:get_optimal_spread_width`):
//! `calculate_msm_witness_cost` estimates total cost, `get_optimal_msm_params`
//! searches the parameter space for the minimum.

use {
    super::{ceil_log2, SCALAR_HALF_BITS},
    std::collections::BTreeMap,
};

/// Per-point overhead witnesses shared across all MSM paths.
const DETECT_SKIP_WIT: usize = 8;
const GLV_HINT_WIT: usize = 4;

fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

/// Table building ops: (doubles, adds) for a signed-digit table.
fn table_build_ops(half_table_size: usize) -> (usize, usize) {
    if half_table_size >= 2 {
        (1, half_table_size - 1)
    } else {
        (0, 0)
    }
}

// ---------------------------------------------------------------------------
// Hint-verified EC cost primitives (non-native, num_limbs >= 2)
//
// Every hint-verified EC op follows the same pattern:
//   1. Allocate hint: result limb-vectors + per-equation (q_pos, q_neg,
//      carries)
//   2. Compute N×N schoolbook product grids
//   3. Pin constant limb-vectors (curve params)
//   4. Verify via schoolbook column equations
//   5. Range-check hint outputs (limb-bit) and carries (carry-bit)
//   6. less-than-p check on each result vector
//
// The helpers below decompose costs into these structural components.
// ---------------------------------------------------------------------------

/// Witnesses per limb from a less-than-p borrow chain: borrow + d_i.
const LTP_WIT_PER_LIMB: usize = 2;
/// Range checks per limb from a less-than-p check: borrow + d_i.
const LTP_RC_PER_LIMB: usize = 2;
/// Witnesses per limb from a multi-limb negate (p-y borrow chain): borrow + r.
const NEGATE_WIT_PER_LIMB: usize = 2;
/// Range checks per limb from a multi-limb negate: r.
const NEGATE_RC_PER_LIMB: usize = 1;

/// Hint output witnesses: result vectors + per-equation quotient/carry layout.
///
/// Each equation allocates q_pos(N) + q_neg(N) + carries(2N-2) = 4N-2
/// witnesses.
fn hint_output_witnesses(n: usize, result_vecs: usize, num_equations: usize) -> usize {
    result_vecs * n + num_equations * (4 * n - 2)
}

/// Witnesses from N×N schoolbook product grids.
fn schoolbook_product_witnesses(n: usize, product_pairs: usize) -> usize {
    product_pairs * n * n
}

/// Limb-bit range checks from hint outputs: result vecs + quotient pairs
/// (pos+neg).
fn hint_limb_range_checks(n: usize, result_vecs: usize, num_equations: usize) -> usize {
    (result_vecs + 2 * num_equations) * n
}

/// Carry range checks from schoolbook column equations: (2N-2) per equation.
fn hint_carry_range_checks(n: usize, num_equations: usize) -> usize {
    num_equations * (2 * n - 2)
}

/// Carry range check bit-width for schoolbook column equations.
pub(crate) fn hint_carry_bits(limb_bits: u32, max_coeff_sum: u64, n: usize) -> u32 {
    let extra_bits = ceil_log2(max_coeff_sum * n as u64) + 1;
    limb_bits + extra_bits + 1
}

/// Maximum bit-width of a merged column equation value.
pub(crate) fn column_equation_max_bits(limb_bits: u32, max_coeff_sum: u64, n: usize) -> u32 {
    let extra_bits = ceil_log2(max_coeff_sum * n as u64) + 1;
    2 * limb_bits + extra_bits + 1
}

/// Worst-case max coefficient sum across all hint-verified EC equations.
///
/// Point double Eq1 has the highest: 2(λy) + 3(x²) + 1(a) + N(q_pos·p) +
/// N(q_neg·p) = 6+2N.
fn worst_case_ec_max_coeff(n: usize) -> u64 {
    6 + 2 * n as u64
}

/// Witness and range check costs for a single hint-verified EC operation.
struct HintVerifiedEcCost {
    witnesses:  usize,
    rc_limb:    usize,
    rc_carry:   usize,
    carry_bits: u32,
}

impl HintVerifiedEcCost {
    /// Point doubling: λ·2y = 3x²+a, λ² = x3+2x, λ(x-x3) = y3+y.
    fn point_double(n: usize, limb_bits: u32) -> Self {
        let num_ltp = 3; // λ, x3, y3
        Self {
            witnesses:  hint_output_witnesses(n, 3, 3)     // λ,x3,y3 + 3 equations
                + schoolbook_product_witnesses(n, 5)       // λ×y, x×x, λ×λ, λ×x, λ×x3
                + n                                        // pinned curve_a limbs
                + num_ltp * LTP_WIT_PER_LIMB * n,
            rc_limb:    hint_limb_range_checks(n, 3, 3) + num_ltp * LTP_RC_PER_LIMB * n,
            rc_carry:   hint_carry_range_checks(n, 3),
            carry_bits: hint_carry_bits(limb_bits, worst_case_ec_max_coeff(n), n),
        }
    }

    /// Point addition: λ(x2-x1) = y2-y1, λ² = x3+x1+x2, λ(x1-x3) = y3+y1.
    fn point_add(n: usize, limb_bits: u32) -> Self {
        let num_ltp = 3; // λ, x3, y3
        Self {
            witnesses:  hint_output_witnesses(n, 3, 3)     // λ,x3,y3 + 3 equations
                + schoolbook_product_witnesses(n, 4)       // λ×x2, λ×x1, λ×λ, λ×x3
                + num_ltp * LTP_WIT_PER_LIMB * n,
            rc_limb:    hint_limb_range_checks(n, 3, 3) + num_ltp * LTP_RC_PER_LIMB * n,
            rc_carry:   hint_carry_range_checks(n, 3),
            carry_bits: hint_carry_bits(limb_bits, 4 + 2 * n as u64, n),
        }
    }

    /// On-curve check: x² mod p, then y² = x³ + ax + b mod p.
    fn on_curve(n: usize, limb_bits: u32) -> Self {
        let num_ltp = 1; // x_sq
        Self {
            witnesses:  hint_output_witnesses(n, 1, 2)     // x_sq + 2 equations
                + schoolbook_product_witnesses(n, 4)       // x×x, y×y, xsq×x, a×x
                + 2 * n                                    // pinned curve_a + curve_b limbs
                + num_ltp * LTP_WIT_PER_LIMB * n,
            rc_limb:    hint_limb_range_checks(n, 1, 2) + num_ltp * LTP_RC_PER_LIMB * n,
            rc_carry:   hint_carry_range_checks(n, 2),
            carry_bits: hint_carry_bits(limb_bits, 5 + 2 * n as u64, n),
        }
    }

    /// Accumulate `count` of this op's range checks into `rc_map`.
    fn add_range_checks(&self, count: usize, limb_bits: u32, rc_map: &mut BTreeMap<u32, usize>) {
        *rc_map.entry(limb_bits).or_default() += count * self.rc_limb;
        *rc_map.entry(self.carry_bits).or_default() += count * self.rc_carry;
    }
}

// ---------------------------------------------------------------------------
// Scalar relation cost
// ---------------------------------------------------------------------------

/// Witnesses and range checks for scalar relation verification.
fn scalar_relation_cost(
    native_field_bits: u32,
    scalar_bits: usize,
) -> (usize, BTreeMap<u32, usize>) {
    let limb_bits = scalar_relation_limb_bits(native_field_bits, scalar_bits);
    let n = ceil_div(scalar_bits, limb_bits as usize);
    let half_bits = (scalar_bits + 1) / 2;
    let half_limbs = ceil_div(half_bits, limb_bits as usize);
    let scalar_half_limbs = ceil_div(SCALAR_HALF_BITS, limb_bits as usize);

    // Field op witnesses for 1 add + 1 sub + 1 mul (no inv), always multi-limb
    // (N≥2 enforced by scalar_relation_limb_bits)
    let field_ops_wit = n * n + 14 * n; // 2 × add/sub(1+4N) + 1 × mul(N²+6N-2)

    let has_cross = n > 1 && SCALAR_HALF_BITS % limb_bits as usize != 0;
    let witnesses = 2 * scalar_half_limbs                    // s1, s2 digit decomposition
        + has_cross as usize                                 // cross-limb carry
        + 2 * n                                              // sign-extended recomposition
        + field_ops_wit                                      // add + sub + mul
        + 2                                                  // neg1, neg2 flag constants
        + n                                                  // constrain_to_constant limbs
        + 3; // compute_is_zero(s2): inv + product + is_zero

    // Only n limbs worth of scalar DD digits get range checks; unused digits
    // are zero-constrained instead (soundness fix for small curves).
    let scalar_dd_rcs = n.min(2 * scalar_half_limbs);
    let mut rc_map = BTreeMap::new();
    *rc_map.entry(limb_bits).or_default() += scalar_dd_rcs + 2 * half_limbs;

    // Field op range checks for 1 add + 1 sub + 1 mul (always multi-limb)
    // add/sub: 2N each (×2 ops), mul: 3N
    *rc_map.entry(limb_bits).or_default() += 7 * n;
    let carry_bits = limb_bits + ceil_log2(n as u64) + 2;
    *rc_map.entry(carry_bits).or_default() += 2 * n - 2; // mul carry chain

    (witnesses, rc_map)
}

// ---------------------------------------------------------------------------
// MSM cost entry point
// ---------------------------------------------------------------------------

/// Total estimated witness cost for an MSM.
pub fn calculate_msm_witness_cost(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    window_size: usize,
    limb_bits: u32,
    is_native: bool,
) -> usize {
    if is_native {
        return calculate_msm_witness_cost_native(native_field_bits, n_points, scalar_bits);
    }

    // --- Derived parameters ---

    let n = ceil_div(curve_modulus_bits as usize, limb_bits as usize);
    assert!(
        n >= 2,
        "non-native MSM requires num_limbs >= 2, got {n} (limb_bits={limb_bits}, \
         curve_modulus_bits={curve_modulus_bits})"
    );
    let half_bits = (scalar_bits + 1) / 2;
    let w = window_size;
    let half_table_size = 1usize << (w - 1);
    let num_windows = ceil_div(half_bits, w);

    // --- Atomic op costs ---

    let ec_double = HintVerifiedEcCost::point_double(n, limb_bits);
    let ec_add = HintVerifiedEcCost::point_add(n, limb_bits);
    let ec_oncurve = HintVerifiedEcCost::on_curve(n, limb_bits);
    let (sr_witnesses, sr_range_checks) = scalar_relation_cost(native_field_bits, scalar_bits);
    let (tbl_d, tbl_a) = table_build_ops(half_table_size);

    let negate_wit = NEGATE_WIT_PER_LIMB * n;
    // negate N y-limbs + N select_witness to pick y vs -y
    let negate_and_select = negate_wit + n;

    // --- Per-point witnesses (grouped by pipeline phase) ---

    // Phase 1: preprocessing — sanitize, decompose, on-curve, y preparation
    let preprocess = 2 * (half_bits + 1)          // scalar bit decomposition
        + DETECT_SKIP_WIT                         // degenerate-case detection
        + (2 * n + 2)                             // sanitize selects (px, py, s_lo, s_hi)
        + 4 * n                                   // ec hint (2N outputs + 2N selects)
        + GLV_HINT_WIT                            // FakeGLV hint
        + 4 * n                                   // point decomposition (always N≥2 here)
        + 2 * ec_oncurve.witnesses                // on-curve checks for P and R
        + 2 * negate_and_select; // y pre-negate per half-scalar

    // Phase 2: table building — construct [P, 3P, 5P, ...] + mux selects
    let table = 2 * (tbl_d * ec_double.witnesses + tbl_a * ec_add.witnesses)
        + num_windows * 2 * half_table_size.saturating_sub(1) * 2 * n;

    // Phase 3: EC loop — doublings shared across windows, per-window adds
    let doublings = num_windows * w * ec_double.witnesses;
    let loop_body =
        num_windows * 2 * (ec_add.witnesses + negate_and_select + 2 * w.saturating_sub(1));
    // per window × 2 half-scalars × (add + negate+select + XOR bits)

    // Phase 4: skew correction — per half-scalar: add + negate + point_select
    let skew = 2 * (ec_add.witnesses + negate_wit + 2 * n);

    let per_point = preprocess + table + doublings + loop_body + skew + sr_witnesses;

    // --- Accumulation witnesses ---

    let shared_constants = 3 + 2 * n; // gen_x, gen_y, zero + offset(x,y) limbs

    // Per-point: add to accumulator + point_select(2N) for skip handling
    let accum_per_point = ec_add.witnesses + 2 * n;
    // Boolean product chain tracking all_skipped
    let accum_skip_chain = n_points.saturating_sub(1);
    // Offset subtraction: add + gen constants(3N, offset_x reused) +
    // mask selects(2N) + init(2) + flags(2)
    let accum_offset = ec_add.witnesses + 3 * n + 2 * n + 2 + 2;
    let accum = n_points * accum_per_point + accum_skip_chain + accum_offset;

    // --- Range checks ---

    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();

    // EC op range checks (per-point doubles + table doubles, adds, on-curve)
    let doubles_count = num_windows * w + 2 * tbl_d;
    let adds_count = 2 * tbl_a + num_windows * 2 + 2;
    ec_double.add_range_checks(n_points * doubles_count, limb_bits, &mut rc_map);
    ec_add.add_range_checks(n_points * adds_count, limb_bits, &mut rc_map);
    ec_oncurve.add_range_checks(n_points * 2, limb_bits, &mut rc_map);

    // Accumulation adds
    ec_add.add_range_checks(n_points + 1, limb_bits, &mut rc_map);

    // Negates per point: 2 y_eff + 2/window signed_lookup + 2 skew
    let negate_count_pp = 2 + num_windows * 2 + 2;
    *rc_map.entry(limb_bits).or_default() += n_points * negate_count_pp * NEGATE_RC_PER_LIMB * n;
    // Point decomp limb RCs (2N) + scalar mul hint output limb RCs (2N)
    *rc_map.entry(limb_bits).or_default() += n_points * 4 * n;

    // Scalar relation range checks
    for (&bits, &count) in &sr_range_checks {
        *rc_map.entry(bits).or_default() += n_points * count;
    }

    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);
    shared_constants + n_points * per_point + accum + range_check_cost
}

// ---------------------------------------------------------------------------
// Native-field cost
// ---------------------------------------------------------------------------

// Native-field hint-verified EC witness costs.
const NATIVE_DOUBLE: usize = 4; // hint(λ,x3,y3) + x_sq product
const NATIVE_ADD: usize = 3; // hint(λ,x3,y3)
const NATIVE_ON_CURVE: usize = 2; // x_sq + x_cu products
const NATIVE_NEGATE: usize = 1; // linear combination
const NATIVE_SELECT: usize = 1; // select_witness
const NATIVE_POINT_SELECT: usize = 2; // x + y select_witness

/// Native-field MSM cost.
fn calculate_msm_witness_cost_native(
    native_field_bits: u32,
    n_points: usize,
    scalar_bits: usize,
) -> usize {
    let half_bits = (scalar_bits + 1) / 2;
    let (sr_wit, sr_rc) = scalar_relation_cost(native_field_bits, scalar_bits);

    // Per-bit: double + 2 × (negate y_eff + signed select + add)
    let per_bit = NATIVE_DOUBLE + 2 * (NATIVE_NEGATE + NATIVE_SELECT + NATIVE_ADD);
    // Per half-scalar skew: negate + add + point_select
    let per_skew = NATIVE_NEGATE + NATIVE_ADD + NATIVE_POINT_SELECT;

    let per_point = 2 * NATIVE_ON_CURVE // on-curve checks (2 points)
        + 2 * (NATIVE_NEGATE + 2 * NATIVE_SELECT) // y pre-negate per half-scalar
        + 2 * (half_bits + 1)           // scalar bit decomposition
        + DETECT_SKIP_WIT + 4 + 4 + GLV_HINT_WIT // sanitize + ec_hint + glv
        + sr_wit
        + half_bits * per_bit
        + 2 * per_skew;

    let shared_constants = 3 + 2; // gen_x, gen_y, zero + offset(x,y)

    let accum_per_point = NATIVE_ADD + NATIVE_POINT_SELECT;
    let accum = n_points * accum_per_point
        + n_points.saturating_sub(1)     // all_skipped products
        + NATIVE_ADD + 2 + 2 + 2; // offset sub: add + 2 const + 2 sel + 2 mask

    // Range checks (only from scalar relation for native)
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();
    for (&bits, &count) in &sr_rc {
        *rc_map.entry(bits).or_default() += n_points * count;
    }
    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);

    n_points * per_point + shared_constants + accum + range_check_cost
}

// ---------------------------------------------------------------------------
// Parameter search
// ---------------------------------------------------------------------------

/// Picks the widest limb size for scalar-relation arithmetic that fits the
/// native field.
pub(super) fn scalar_relation_limb_bits(native_field_bits: u32, order_bits: usize) -> u32 {
    for n in 2..=super::MAX_LIMBS {
        let lb = ((order_bits + n - 1) / n) as u32;
        if column_equation_fits_native_field(native_field_bits, lb, n) {
            return lb;
        }
    }

    panic!("native field too small for scalar relation verification");
}

/// Check whether schoolbook column equation values fit in the native field.
pub fn column_equation_fits_native_field(
    native_field_bits: u32,
    limb_bits: u32,
    num_limbs: usize,
) -> bool {
    if num_limbs <= 1 {
        return true;
    }
    let max_coeff_sum = worst_case_ec_max_coeff(num_limbs);
    column_equation_max_bits(limb_bits, max_coeff_sum, num_limbs) < native_field_bits
}

/// Search for optimal `(limb_bits, window_size, num_limbs)` minimizing
/// witness cost.
pub fn get_optimal_msm_params(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    is_native: bool,
) -> (u32, usize, usize) {
    if is_native {
        return (native_field_bits, 1, 1);
    }

    let max_limb_bits = (native_field_bits.saturating_sub(4)) / 2;
    let mut best_cost = usize::MAX;
    let mut best_limb_bits = max_limb_bits.min(86);
    let mut best_window = 4;
    let mut best_num_limbs = ceil_div(curve_modulus_bits as usize, best_limb_bits as usize);

    for lb in 8..=max_limb_bits {
        let num_limbs = ceil_div(curve_modulus_bits as usize, lb as usize);
        // Non-native path requires num_limbs >= 2 (hint-verified EC ops)
        if num_limbs < 2 {
            continue;
        }
        if !column_equation_fits_native_field(native_field_bits, lb, num_limbs) {
            continue;
        }
        for ws in 2..=8usize {
            let cost = calculate_msm_witness_cost(
                native_field_bits,
                curve_modulus_bits,
                n_points,
                scalar_bits,
                ws,
                lb,
                false,
            );
            if cost < best_cost {
                best_cost = cost;
                best_limb_bits = lb;
                best_window = ws;
                best_num_limbs = num_limbs;
            }
        }
    }

    (best_limb_bits, best_window, best_num_limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimal_params_bn254_native() {
        let (limb_bits, window_size, num_limbs) = get_optimal_msm_params(254, 254, 1, 256, true);
        assert_eq!(limb_bits, 254);
        assert_eq!(window_size, 1, "native path uses signed-bit wNAF (w=1)");
        assert_eq!(num_limbs, 1, "native path uses 1 limb");
    }

    #[test]
    fn test_optimal_params_secp256r1() {
        let (limb_bits, window_size, num_limbs) = get_optimal_msm_params(254, 256, 1, 256, false);
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "optimizer selected unsound limb_bits={limb_bits} (N={num_limbs})"
        );
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_optimal_params_goldilocks() {
        let (limb_bits, window_size, num_limbs) = get_optimal_msm_params(254, 64, 1, 64, false);
        assert!(
            num_limbs >= 2,
            "non-native path requires num_limbs >= 2, got {num_limbs}"
        );
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "optimizer selected unsound limb_bits={limb_bits} (N={num_limbs})"
        );
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_column_equation_soundness_boundary() {
        // With N=3, max_coeff_sum = 6+2*3 = 12, extra_bits = ceil(log2(36))+1 = 7
        // Need: 2*W + 7 + 1 < 254 → W < 123
        assert!(column_equation_fits_native_field(254, 122, 3));
        assert!(!column_equation_fits_native_field(254, 123, 3));
        assert!(!column_equation_fits_native_field(254, 124, 3));
    }

    #[test]
    fn test_secp256r1_limb_bits_not_unsound() {
        let (limb_bits, _, num_limbs) = get_optimal_msm_params(254, 256, 1, 256, false);
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "secp256r1 limb_bits={limb_bits} (N={num_limbs}) doesn't fit native field"
        );
    }

    #[test]
    fn test_scalar_relation_cost_grumpkin() {
        let (sr, rc) = scalar_relation_cost(254, 256);
        assert_eq!(sr, 70, "grumpkin scalar_relation witnesses changed: {sr}");
        let total_rc: usize = rc.values().sum();
        assert_eq!(
            total_rc, 32,
            "grumpkin scalar_relation range checks changed: {total_rc}"
        );
    }

    #[test]
    fn test_scalar_relation_cost_small_curve() {
        let (sr, _) = scalar_relation_cost(254, 64);
        assert_eq!(
            sr, 51,
            "64-bit curve scalar_relation witnesses changed: {sr}"
        );
    }

    #[test]
    fn test_estimate_range_check_cost_basic() {
        use crate::range_check::estimate_range_check_cost;

        assert_eq!(estimate_range_check_cost(&BTreeMap::new()), 0);

        let mut checks = BTreeMap::new();
        checks.insert(8u32, 100usize);
        let cost = estimate_range_check_cost(&checks);
        assert!(cost > 0, "expected nonzero cost for 100 8-bit checks");
    }
}
