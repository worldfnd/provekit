//! Analytical cost model for MSM parameter optimization.
//!
//! Follows the SHA256 pattern (`spread.rs:get_optimal_spread_width`):
//! `calculate_msm_witness_cost` estimates total cost, `get_optimal_msm_params`
//! searches the parameter space for the minimum.

use std::collections::BTreeMap;

/// The 256-bit scalar is split into two halves (s_lo, s_hi) because it doesn't
/// fit in the native field.
const SCALAR_HALF_BITS: usize = 128;

fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

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

/// Witnesses and range checks for scalar relation verification.
///
/// Verifies `(-1)^neg1*|s1| + (-1)^neg2*|s2|*s ≡ 0 (mod n)` using multi-limb
/// arithmetic with the curve order as modulus. Components:
/// - Scalar decomposition (DD digits for s_lo, s_hi)
/// - Half-scalar decomposition (DD digits for s1, s2)
/// - One mul + one add + one sub for sign handling
/// - XOR witnesses (2) + select (num_limbs)
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
        + n;

    let mut rc_map = BTreeMap::new();
    *rc_map.entry(limb_bits).or_default() += 2 * scalar_half_limbs + 2 * half_limbs;
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
    let half_bits = (scalar_bits + 1) / 2;
    let w = window_size;
    let table_size = 1usize << w;
    let num_windows = ceil_div(half_bits, w);

    // === GLV scalar mul field op counts ===
    // point_double: (5 add, 3 sub, 4 mul, 1 inv) + N constant witnesses (curve_a)
    // point_add:    (1 add, 5 sub, 3 mul, 1 inv)

    // Table building (2 tables for P and R)
    let (tbl_d, tbl_a) = if table_size > 2 {
        (1, table_size - 3)
    } else {
        (0, 0)
    };
    let mut n_add = 2 * (tbl_d * 5 + tbl_a * 1);
    let mut n_sub = 2 * (tbl_d * 3 + tbl_a * 5);
    let mut n_mul = 2 * (tbl_d * 4 + tbl_a * 3);
    let mut n_inv = 2 * (tbl_d + tbl_a);

    // Main loop: w shared doublings + 2 point_adds per window
    n_add += num_windows * (w * 5 + 2 * 1);
    n_sub += num_windows * (w * 3 + 2 * 5);
    n_mul += num_windows * (w * 4 + 2 * 3);
    n_inv += num_windows * (w + 2);

    // On-curve checks (P and R): 2 × (4 mul + 2 add)
    n_mul += 8;
    n_add += 4;

    // Y-negation: 2 negate = 2 sub (negate calls sub(zero, value))
    n_sub += 2;

    let glv_field_ops = field_op_witnesses(n_add, n_sub, n_mul, n_inv, n, false);

    // Constant witness allocations not captured by field ops:
    // - curve_a() in each point_double: N per call
    // - on-curve: 2 × (curve_a + curve_b) = 4N
    // - negate: 2 × constant_limbs(zero) = 2N
    // - offset point in verify_point_fakeglv: 2N
    let n_doubles = 2 * tbl_d + num_windows * w;
    let glv_constants = n_doubles * n + 4 * n + 2 * n + 2 * n;

    // Selects + is_zero (not field ops, priced separately)
    let table_selects = num_windows * 2 * ((1 << w) - 1) * 2 * n;
    let skip_selects = num_windows * 2 * 2 * n;
    let y_negate_selects = 2 * n;
    let is_zero_cost = num_windows * 2 * 3; // 3 native witnesses each

    let glv_cost = glv_field_ops
        + glv_constants
        + table_selects
        + skip_selects
        + y_negate_selects
        + is_zero_cost;

    // === Per-point overhead ===
    let scalar_bit_decomp = 2 * half_bits;
    let detect_skip = 8; // 2×is_zero(3W) + product(1W) + or(1W)
    let sanitize = 4; // 4 select_witness
    let ec_hint = 4; // 2W hint + 2W selects
    let point_decomp = if n > 1 { 4 * n } else { 0 };
    let glv_hint = 4; // s1, s2, neg1, neg2
    let (sr_witnesses, sr_range_checks) = scalar_relation_cost(native_field_bits, scalar_bits);

    let per_point = glv_cost
        + scalar_bit_decomp
        + detect_skip
        + sanitize
        + ec_hint
        + point_decomp
        + glv_hint
        + sr_witnesses;

    // === Shared constants (allocated once) ===
    // gen_x, gen_y, zero (3W) + offset_{x,y} (2×num_limbs W via constant_limbs)
    let shared_constants = 3 + 2 * n;

    // === Point accumulation ===
    let pa_cost = field_op_witnesses(1, 5, 3, 1, n, false); // point_add
    let accum = n_points * (pa_cost + 2 * n) // per-point add + skip select
        + n_points.saturating_sub(1)          // all_skipped products
        + pa_cost + 4 * n + 2 * n            // offset subtraction + constants + selects
        + 2 + if n > 1 { 2 } else { 0 }; // mask + recompose

    // === Range check resolution ===
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();

    // GLV field ops (per point)
    add_field_op_range_checks(
        n_points * n_add,
        n_points * n_sub,
        n_points * n_mul,
        n_points * n_inv,
        n,
        limb_bits,
        curve_modulus_bits,
        false,
        &mut rc_map,
    );

    // Point decomposition (per point, N>1 only)
    if n > 1 {
        *rc_map.entry(limb_bits).or_default() += n_points * 4 * n;
    }

    // Scalar relation (per point)
    for (bits, count) in &sr_range_checks {
        *rc_map.entry(*bits).or_default() += n_points * count;
    }

    // Accumulation: (n_points + 1) point_adds (1 add, 5 sub, 3 mul, 1 inv each)
    add_field_op_range_checks(
        (n_points + 1) * 1,
        (n_points + 1) * 5,
        (n_points + 1) * 3,
        (n_points + 1) * 1,
        n,
        limb_bits,
        curve_modulus_bits,
        false,
        &mut rc_map,
    );

    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);

    n_points * per_point + shared_constants + accum + range_check_cost
}

/// Native-field MSM cost: hint-verified EC ops with signed-bit wNAF (w=1).
///
/// The native path uses prover hints verified via raw R1CS constraints:
/// - `point_double_verified_native`: 4W (3 hint + 1 product)
/// - `point_add_verified_native`: 3W (3 hint)
/// - `verify_on_curve_native`: 2W (2 products)
/// - No multi-limb arithmetic → zero EC-related range checks
///
/// Uses merged-loop optimization: all points share a single doubling per bit.
fn calculate_msm_witness_cost_native(
    native_field_bits: u32,
    n_points: usize,
    scalar_bits: usize,
) -> usize {
    let half_bits = (scalar_bits + 1) / 2;

    // === Per-point fixed costs ===
    let on_curve = 4; // 2 × verify_on_curve_native (2W each)
    let glv_hint = 4; // s1, s2, neg1, neg2
    let scalar_bits_cost = 2 * (half_bits + 1); // 2 × (half_bits + skew)
    let y_negate = 6; // 2 × 3W (neg_y, y_eff, neg_y_eff)
    let detect_skip = 8; // 2×is_zero(3W) + product(1W) + or(1W)
    let sanitize = 4; // 4 select_witness
    let ec_hint = 4; // 2W hint + 2W selects
    let (sr_wit, sr_rc) = scalar_relation_cost(native_field_bits, scalar_bits);

    let per_point = on_curve
        + glv_hint
        + scalar_bits_cost
        + y_negate
        + detect_skip
        + sanitize
        + ec_hint
        + sr_wit;

    // === Shared constants ===
    let shared_constants = 5; // gen_x, gen_y, zero, offset_x, offset_y

    // === EC verification loop (merged, shared doubling) ===
    // Per bit: 4W (shared double) + n_points × 8W (2×(1W select + 3W add))
    let ec_loop = half_bits * (4 + 8 * n_points);
    // Skew correction: 2 branches × (3W add + 2W select) = 10W per point
    let skew = n_points * 10;

    // === Point accumulation ===
    let accum = 2 // initial acc constants
        + n_points * 5                  // add(3W) + skip_select(2W)
        + n_points.saturating_sub(1)    // all_skipped products
        + 10; // offset sub: 3 const + 2 sel + 3 add + 2 mask

    // === Range checks (only from scalar relation for native) ===
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();
    for (bits, count) in &sr_rc {
        *rc_map.entry(*bits).or_default() += n_points * count;
    }
    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);

    n_points * per_point + shared_constants + ec_loop + skew + accum + range_check_cost
}

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
/// The maximum integer value in any column equation is bounded by
/// `2^(2W + ceil(log2(N)) + 3)` where W = limb_bits, N = num_limbs.
/// This must be less than the native field modulus (~`2^native_field_bits`).
pub fn column_equation_fits_native_field(
    native_field_bits: u32,
    limb_bits: u32,
    num_limbs: usize,
) -> bool {
    if num_limbs <= 1 {
        return true;
    }
    let ceil_log2_n = (num_limbs as f64).log2().ceil() as u32;
    2 * limb_bits + ceil_log2_n + 3 < native_field_bits
}

/// Search for optimal (limb_bits, window_size) minimizing witness cost.
///
/// Searches limb_bits ∈ \[8..max\] and window_size ∈ \[2..8\].
/// Each candidate is checked for column equation soundness.
pub fn get_optimal_msm_params(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    is_native: bool,
) -> (u32, usize) {
    if is_native {
        // Native path uses signed-bit wNAF (w=1), no limb decomposition.
        // Window size is unused; return a default.
        let cost = calculate_msm_witness_cost_native(native_field_bits, n_points, scalar_bits);
        let _ = cost; // cost is the same regardless of window_size
        return (native_field_bits, 4);
    }

    let max_limb_bits = (native_field_bits.saturating_sub(4)) / 2;
    let mut best_cost = usize::MAX;
    let mut best_limb_bits = max_limb_bits.min(86);
    let mut best_window = 4;

    for lb in 8..=max_limb_bits {
        let num_limbs = ceil_div(curve_modulus_bits as usize, lb as usize);
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
            }
        }
    }

    (best_limb_bits, best_window)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimal_params_bn254_native() {
        let (limb_bits, window_size) = get_optimal_msm_params(254, 254, 1, 256, true);
        assert_eq!(limb_bits, 254);
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_optimal_params_secp256r1() {
        let (limb_bits, window_size) = get_optimal_msm_params(254, 256, 1, 256, false);
        let num_limbs = ceil_div(256, limb_bits as usize);
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "optimizer selected unsound limb_bits={limb_bits} (N={num_limbs})"
        );
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_optimal_params_goldilocks() {
        let (limb_bits, window_size) = get_optimal_msm_params(254, 64, 1, 64, false);
        let num_limbs = ceil_div(64, limb_bits as usize);
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "optimizer selected unsound limb_bits={limb_bits} (N={num_limbs})"
        );
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_column_equation_soundness_boundary() {
        assert!(column_equation_fits_native_field(254, 124, 3));
        assert!(!column_equation_fits_native_field(254, 125, 3));
        assert!(!column_equation_fits_native_field(254, 126, 3));
    }

    #[test]
    fn test_secp256r1_limb_bits_not_126() {
        let (limb_bits, _) = get_optimal_msm_params(254, 256, 1, 256, false);
        assert!(
            limb_bits <= 124,
            "secp256r1 limb_bits={limb_bits} exceeds safe maximum 124"
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
