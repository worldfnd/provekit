//! Analytical cost model for MSM parameter optimization.
//!
//! Follows the SHA256 pattern (`spread.rs:get_optimal_spread_width`):
//! `calculate_msm_witness_cost` estimates total cost, `get_optimal_msm_params`
//! searches the parameter space for the minimum.

use {super::SCALAR_HALF_BITS, std::collections::BTreeMap};

/// Per-point overhead witnesses shared across all MSM paths.
/// - detect_skip: 2×is_zero(3W) + product(1W) + or(1W) = 8W
/// - glv_hint: s1, s2, neg1, neg2 = 4W
///
/// Limb-dependent overheads (sanitize, ec_hint) are computed inline since
/// they scale with num_limbs: sanitize = 2N+2, ec_hint = 4N.
const DETECT_SKIP_WIT: usize = 8;
const GLV_HINT_WIT: usize = 4;

fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

/// Table building ops: (doubles, adds) for constructing a signed-digit table.
/// Each table has `half_table_size` entries of odd multiples.
fn table_build_ops(half_table_size: usize) -> (usize, usize) {
    if half_table_size >= 2 {
        (1, half_table_size - 1)
    } else {
        (0, 0)
    }
}

/// Per-point overhead witnesses common to all MSM paths.
///
/// Sanitize: N selects for px + N for py + 1 for s_lo + 1 for s_hi = 2N+2.
/// EC hint: 2N hint outputs + N selects for rx + N for ry = 4N.
fn per_point_overhead(half_bits: usize, num_limbs: usize, sr_witnesses: usize) -> usize {
    let scalar_bit_decomp = 2 * (half_bits + 1);
    let point_decomp = if num_limbs > 1 { 4 * num_limbs } else { 0 };
    let sanitize_wit = 2 * num_limbs + 2; // N px selects + N py selects + s_lo + s_hi
    let ec_hint_wit = 4 * num_limbs; // 2N hint outputs + N rx selects + N ry selects
    scalar_bit_decomp
        + DETECT_SKIP_WIT
        + sanitize_wit
        + ec_hint_wit
        + GLV_HINT_WIT
        + point_decomp
        + sr_witnesses
}

// ---------------------------------------------------------------------------
// Field op cost helpers (used by generic single-limb path + scalar relation)
// ---------------------------------------------------------------------------

/// Total witnesses produced by N-limb field operations.
///
/// Per-op witness counts by configuration:
/// - Native (N=1, same field): 1 per op (direct R1CS)
/// - Single-limb non-native (N=1): 5 per add/sub/mul, 6 per inv (reduce_mod_p
///   pattern)
/// - Multi-limb (N>1): add/sub = 1+6N, mul = N²+7N-2, inv = N²+8N-2 (schoolbook
///   multiplication + quotient/remainder)
fn field_op_witnesses(
    n_add: usize,
    n_sub: usize,
    n_mul: usize,
    n_inv: usize,
    num_limbs: usize,
    is_native: bool,
) -> usize {
    if is_native {
        n_add + n_sub + n_mul + n_inv
    } else if num_limbs == 1 {
        (n_add + n_sub + n_mul) * 5 + n_inv * 6
    } else {
        let n = num_limbs;
        let w_as = 1 + 6 * n;
        let w_m = n * n + 7 * n - 2;
        let w_i = n * n + 8 * n - 2;
        (n_add + n_sub) * w_as + n_mul * w_m + n_inv * w_i
    }
}

/// Aggregate range checks from field ops into a map.
///
/// - Native: no range checks
/// - Single-limb non-native: 1 check at `modulus_bits` per add/sub/mul, 2 per
///   inv
/// - Multi-limb: `limb_bits`-wide checks from less_than_p, plus
///   `carry_bits`-wide checks from schoolbook column carries
fn add_field_op_range_checks(
    n_add: usize,
    n_sub: usize,
    n_mul: usize,
    n_inv: usize,
    num_limbs: usize,
    limb_bits: u32,
    modulus_bits: u32,
    is_native: bool,
    rc_map: &mut BTreeMap<u32, usize>,
) {
    if is_native {
        return;
    }
    if num_limbs == 1 {
        *rc_map.entry(modulus_bits).or_default() += n_add + n_sub + n_mul + 2 * n_inv;
    } else {
        let n = num_limbs;
        let ceil_log2_n = (n as f64).log2().ceil() as u32;
        let carry_bits = limb_bits + ceil_log2_n + 2;
        *rc_map.entry(limb_bits).or_default() +=
            (n_add + n_sub) * 2 * n + n_mul * 3 * n + n_inv * 4 * n;
        *rc_map.entry(carry_bits).or_default() += (n_mul + n_inv) * (2 * n - 2);
    }
}

// ---------------------------------------------------------------------------
// Hint-verified EC op cost model (non-native, num_limbs >= 2)
// ---------------------------------------------------------------------------

/// Witness and range check costs for a single hint-verified EC operation.
struct HintVerifiedEcCost {
    witnesses:  usize,
    rc_limb:    usize,
    rc_carry:   usize,
    carry_bits: u32,
}

impl HintVerifiedEcCost {
    /// point_double: (15N-6)W hint + 5N² products + N constants + 3×3N ltp
    fn point_double(n: usize, limb_bits: u32) -> Self {
        let wit = (15 * n - 6) + 5 * n * n + n + 9 * n;
        Self {
            witnesses:  wit,
            rc_limb:    9 * n + 6 * n, // 9N hint limbs (3+6 q_pos/q_neg) + 3×2N ltp limbs
            rc_carry:   3 * (2 * n - 2), // 3 equations × (2N-2) carries
            carry_bits: hint_carry_bits(limb_bits, 6 + 2 * n as u64, n),
        }
    }

    /// point_add: (15N-6)W hint + 4N² products + 3×3N ltp
    fn point_add(n: usize, limb_bits: u32) -> Self {
        let wit = (15 * n - 6) + 4 * n * n + 9 * n;
        Self {
            witnesses:  wit,
            rc_limb:    9 * n + 6 * n,
            rc_carry:   3 * (2 * n - 2),
            carry_bits: hint_carry_bits(limb_bits, 4 + 2 * n as u64, n),
        }
    }

    /// on_curve (worst case, a != 0): (9N-4)W hint + 4N² products + 2N
    /// constants + 3N ltp
    fn on_curve(n: usize, limb_bits: u32) -> Self {
        let wit = (9 * n - 4) + 4 * n * n + 2 * n + 3 * n;
        Self {
            witnesses:  wit,
            rc_limb:    5 * n + 2 * n, // 5N hint limbs (1+4 q_pos/q_neg) + 2N ltp limbs
            rc_carry:   2 * (2 * n - 2), // 2 equations × (2N-2) carries
            carry_bits: hint_carry_bits(limb_bits, 5 + 2 * n as u64, n),
        }
    }

    /// Accumulate `count` of this op's range checks into `rc_map`.
    fn add_range_checks(&self, count: usize, limb_bits: u32, rc_map: &mut BTreeMap<u32, usize>) {
        *rc_map.entry(limb_bits).or_default() += count * self.rc_limb;
        *rc_map.entry(self.carry_bits).or_default() += count * self.rc_carry;
    }
}

/// Carry range check bits for hint-verified EC column equations.
fn hint_carry_bits(limb_bits: u32, max_coeff_sum: u64, n: usize) -> u32 {
    let extra_bits = ((max_coeff_sum as f64 * n as f64).log2().ceil() as u32) + 1;
    limb_bits + extra_bits + 1
}

// ---------------------------------------------------------------------------
// Scalar relation cost
// ---------------------------------------------------------------------------

/// Witnesses and range checks for scalar relation verification.
///
/// Verifies `(-1)^neg1*|s1| + (-1)^neg2*|s2|*s ≡ 0 (mod n)` using multi-limb
/// arithmetic with the curve order as modulus. Components:
/// - Scalar decomposition (DD digits for s_lo, s_hi)
/// - Half-scalar decomposition (DD digits for s1, s2)
/// - One mul + one add + one sub for sign handling
/// - XOR witnesses (2) + select (num_limbs)
/// - s2 non-zero check: compute_is_zero(3W) + constrain_zero
fn scalar_relation_cost(
    native_field_bits: u32,
    scalar_bits: usize,
) -> (usize, BTreeMap<u32, usize>) {
    let limb_bits = scalar_relation_limb_bits(native_field_bits, scalar_bits);
    let n = ceil_div(scalar_bits, limb_bits as usize);
    let half_bits = (scalar_bits + 1) / 2;
    let half_limbs = ceil_div(half_bits, limb_bits as usize);
    let scalar_half_limbs = ceil_div(SCALAR_HALF_BITS, limb_bits as usize);

    let has_cross = n > 1 && SCALAR_HALF_BITS % limb_bits as usize != 0;
    let witnesses = 2 * scalar_half_limbs
        + has_cross as usize
        + 2 * n
        + field_op_witnesses(1, 1, 1, 0, n, false)
        + 2
        + n
        + 3; // compute_is_zero(s2): inv + product + is_zero

    // Only n limbs worth of scalar DD digits get range checks; unused digits
    // are zero-constrained instead (soundness fix for small curves).
    let scalar_dd_rcs = n.min(2 * scalar_half_limbs);
    let mut rc_map = BTreeMap::new();
    *rc_map.entry(limb_bits).or_default() += scalar_dd_rcs + 2 * half_limbs;
    add_field_op_range_checks(
        1,
        1,
        1,
        0,
        n,
        limb_bits,
        scalar_bits as u32,
        false,
        &mut rc_map,
    );

    (witnesses, rc_map)
}

// ---------------------------------------------------------------------------
// MSM cost entry point
// ---------------------------------------------------------------------------

/// Total estimated witness cost for an MSM.
///
/// Accounts for three categories of witnesses:
/// 1. **Inline witnesses** — field ops, selects, is_zero, hints, DDs
/// 2. **Range check resolution** — LogUp/naive cost for all range checks
/// 3. **Per-point overhead** — detect_skip, sanitization, point decomposition
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

    calculate_msm_witness_cost_hint_verified(
        native_field_bits,
        n_points,
        scalar_bits,
        w,
        limb_bits,
        n,
        half_bits,
        half_table_size,
        num_windows,
    )
}

// ---------------------------------------------------------------------------
// Hint-verified (multi-limb) non-native cost
// ---------------------------------------------------------------------------

/// Hint-verified non-native MSM cost (num_limbs >= 2).
#[allow(clippy::too_many_arguments)]
fn calculate_msm_witness_cost_hint_verified(
    native_field_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    w: usize,
    limb_bits: u32,
    n: usize,
    half_bits: usize,
    half_table_size: usize,
    num_windows: usize,
) -> usize {
    let ec_double = HintVerifiedEcCost::point_double(n, limb_bits);
    let ec_add = HintVerifiedEcCost::point_add(n, limb_bits);
    let ec_oncurve = HintVerifiedEcCost::on_curve(n, limb_bits);
    let (sr_witnesses, sr_range_checks) = scalar_relation_cost(native_field_bits, scalar_bits);
    let (tbl_d, tbl_a) = table_build_ops(half_table_size);

    // negate_mod_p_multi: 3N witnesses, N range checks (no less_than_p)
    let negate_wit = 3 * n;

    // --- Per-point EC witnesses (each point has its own doubling chain) ---
    let pp_doubles = num_windows * w; // per-point doublings (no longer shared)
    let pp_doubles_ec = pp_doubles * ec_double.witnesses;
    let pp_offset_constants = 2 * n; // offset limbs per point
    let pp_table_ec = 2 * (tbl_d * ec_double.witnesses + tbl_a * ec_add.witnesses);
    let pp_loop_ec = num_windows * 2 * ec_add.witnesses;
    let pp_skew_ec = 2 * ec_add.witnesses;
    let pp_oncurve = 2 * ec_oncurve.witnesses;
    let pp_y_negate = 2 * (negate_wit + n); // 2 × (negate + select)
    let pp_signed_lookup_negate = num_windows * 2 * (negate_wit + n);
    let pp_skew_negate = 2 * negate_wit;
    let pp_skew_selects = 2 * 2 * n; // 2 branches × 2N
    let pp_table_selects = num_windows * 2 * half_table_size.saturating_sub(1) * 2 * n;
    let pp_xor = num_windows * 2 * 2 * w.saturating_sub(1);

    let per_point = pp_doubles_ec
        + pp_offset_constants
        + pp_table_ec
        + pp_loop_ec
        + pp_skew_ec
        + pp_oncurve
        + pp_y_negate
        + pp_signed_lookup_negate
        + pp_skew_negate
        + pp_skew_selects
        + pp_table_selects
        + pp_xor
        + per_point_overhead(half_bits, n, sr_witnesses);

    // --- Shared constants ---
    let shared_constants = 3; // gen_x, gen_y, zero

    // --- Point accumulation ---
    let accum = n_points * (ec_add.witnesses + 2 * n)  // per-point add + skip select
        + n_points.saturating_sub(1)                    // all_skipped products
        + ec_add.witnesses + 4 * n + 2 * n             // offset sub + constants + selects
        + 2 + 2; // mask + recompose

    // --- Range checks ---
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();

    // Per-point: loop doublings + table doubles + table/loop/skew adds + on-curve
    let pp_doubles_count = pp_doubles + 2 * tbl_d;
    let pp_adds_count = 2 * tbl_a + num_windows * 2 + 2;
    ec_double.add_range_checks(n_points * pp_doubles_count, limb_bits, &mut rc_map);
    ec_add.add_range_checks(n_points * pp_adds_count, limb_bits, &mut rc_map);
    ec_oncurve.add_range_checks(n_points * 2, limb_bits, &mut rc_map);

    // Accumulation adds
    ec_add.add_range_checks(n_points + 1, limb_bits, &mut rc_map);

    // Negate range checks: N limb checks per negate
    let negate_count_pp = 2 + num_windows * 2 + 2; // y-negate + signed_lookup + skew
    *rc_map.entry(limb_bits).or_default() += n_points * negate_count_pp * n;

    // Point decomposition
    *rc_map.entry(limb_bits).or_default() += n_points * 4 * n;

    // Scalar relation
    for (&bits, &count) in &sr_range_checks {
        *rc_map.entry(bits).or_default() += n_points * count;
    }

    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);
    shared_constants + n_points * per_point + accum + range_check_cost
}

// ---------------------------------------------------------------------------
// Native-field cost
// ---------------------------------------------------------------------------

/// Native-field MSM cost: hint-verified EC ops with signed-bit wNAF (w=1).
///
/// The native path uses prover hints verified via raw R1CS constraints:
/// - `point_double_verified_native`: 4W (3 hint + 1 product)
/// - `point_add_verified_native`: 3W (3 hint)
/// - `verify_on_curve_native`: 2W (2 products)
/// - No multi-limb arithmetic → zero EC-related range checks
///
/// Uses per-point accumulators: each point has its own doubling chain and
/// identity check for soundness.
fn calculate_msm_witness_cost_native(
    native_field_bits: u32,
    n_points: usize,
    scalar_bits: usize,
) -> usize {
    let half_bits = (scalar_bits + 1) / 2;

    let on_curve = 4; // 2 × verify_on_curve_native (2W each)
    let y_negate = 6; // 2 × 3W (neg_y, y_eff, neg_y_eff)
    let (sr_wit, sr_rc) = scalar_relation_cost(native_field_bits, scalar_bits);

    // Per point per bit: 4W (double) + 2×(2W signed_lookup + 3W add) = 14W
    // signed_lookup with w=1: negate(1W) + select_unchecked(1W) = 2W
    let ec_loop_pp = half_bits * 14;
    // Skew correction: 2 branches × (1W negate + 3W add + 2W select) = 12W
    let skew_pp = 12;
    // Offset constants per point
    let offset_pp = 2;
    // Sanitize(N=1): 2 px/py selects + s_lo + s_hi = 4W
    // EC hint(N=1): 2 hint outputs + 2 selects = 4W
    let sanitize_wit = 4;
    let ec_hint_wit = 4;

    let per_point = on_curve + y_negate
        + 2 * (half_bits + 1)   // scalar bit decomposition
        + DETECT_SKIP_WIT + sanitize_wit + ec_hint_wit + GLV_HINT_WIT
        + sr_wit
        + ec_loop_pp + skew_pp + offset_pp;

    let shared_constants = 3; // gen_x, gen_y, zero

    let accum = 2                           // initial acc constants
        + n_points * 5                      // add(3W) + skip_select(2W)
        + n_points.saturating_sub(1)        // all_skipped products
        + 10; // offset sub: 3 const + 2 sel + 3 add + 2 mask

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

/// Picks the widest limb size for scalar-relation multi-limb arithmetic that
/// fits inside the native field without overflow.
///
/// For BN254 (254-bit native field, ~254-bit order): N=3 @ 85-bit limbs.
/// For small curves where half_scalar × full_scalar fits natively: N=1.
pub(super) fn scalar_relation_limb_bits(native_field_bits: u32, order_bits: usize) -> u32 {
    let half_bits = (order_bits + 1) / 2;

    // N=1 is valid only if mul product fits in the native field.
    if half_bits + order_bits < native_field_bits as usize {
        return order_bits as u32;
    }

    for n in 2..=super::MAX_LIMBS {
        let lb = ((order_bits + n - 1) / n) as u32;
        if column_equation_fits_native_field(native_field_bits, lb, n) {
            return lb;
        }
    }

    panic!("native field too small for scalar relation verification");
}

/// Check whether schoolbook column equation values fit in the native field.
///
/// The worst-case column equation is EC double Eq1 with
/// `max_coeff_sum = 6 + 2N` (λy(2) + xx(3) + a(1) + pq(2N)).
/// The carry offset needs `extra_bits = ceil(log2(max_coeff_sum * N)) + 1`,
/// and the full column value fits in `2W + extra_bits + 1` bits, which must
/// be less than the native field modulus (~`2^native_field_bits`).
///
/// Must match `check_column_equation_fits` in `hints_non_native.rs`.
pub fn column_equation_fits_native_field(
    native_field_bits: u32,
    limb_bits: u32,
    num_limbs: usize,
) -> bool {
    if num_limbs <= 1 {
        return true;
    }
    // Worst-case max_coeff_sum across all EC equations: 6 + 2N (double Eq1)
    let max_coeff_sum = 6 + 2 * num_limbs as u64;
    let extra_bits = ((max_coeff_sum as f64 * num_limbs as f64).log2().ceil() as u32) + 1;
    2 * limb_bits + extra_bits + 1 < native_field_bits
}

/// Search for optimal (limb_bits, window_size, num_limbs) minimizing witness
/// cost.
///
/// Returns `(limb_bits, window_size, num_limbs)`.
/// Searches limb_bits ∈ \[8..max\] and window_size ∈ \[2..8\].
/// Each candidate is checked for column equation soundness.
pub fn get_optimal_msm_params(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    is_native: bool,
) -> (u32, usize, usize) {
    if is_native {
        // Native path: num_limbs=1, signed-bit wNAF with window_size=1.
        // The unified pipeline with w=1 produces equivalent circuits to the
        // dedicated native path (each bit is a window, signed table has 1
        // entry, lookup = conditional y-negation).
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
        assert!(sr > 50 && sr < 200, "unexpected scalar_relation={sr}");
        let total_rc: usize = rc.values().sum();
        assert!(total_rc > 30, "too few range checks: {total_rc}");
        assert!(total_rc < 200, "too many range checks: {total_rc}");
    }

    #[test]
    fn test_scalar_relation_cost_small_curve() {
        let (sr, _) = scalar_relation_cost(254, 64);
        assert!(
            sr < 100,
            "64-bit curve scalar_relation={sr} should be < 100"
        );
    }

    #[test]
    fn test_field_op_witnesses_single_limb() {
        // inv_mod_p_single: a_inv(1) + mul_mod_p_single(5) = 6
        assert_eq!(field_op_witnesses(0, 0, 0, 1, 1, false), 6);
        // add_mod_p_single: 5
        assert_eq!(field_op_witnesses(1, 0, 0, 0, 1, false), 5);
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
