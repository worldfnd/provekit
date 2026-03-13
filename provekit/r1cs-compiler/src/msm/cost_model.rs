//! Analytical cost model for MSM parameter optimization.
//!
//! Follows the SHA256 pattern (`spread.rs:get_optimal_spread_width`):
//! `calculate_msm_witness_cost` estimates total cost, `get_optimal_msm_params`
//! searches the parameter space for the minimum.

use std::collections::BTreeMap;

/// The 256-bit scalar is split into two halves (s_lo, s_hi) because it doesn't
/// fit in the native field.
const SCALAR_HALF_BITS: usize = 128;

/// Per-point overhead witnesses shared across all non-native paths.
/// - detect_skip: 2×is_zero(3W) + product(1W) + or(1W) = 8W
/// - sanitize: 4 select_witness = 4W
/// - ec_hint: EcScalarMulHint(2W) + 2W selects = 4W
/// - glv_hint: s1, s2, neg1, neg2 = 4W
const DETECT_SKIP_WIT: usize = 8;
const SANITIZE_WIT: usize = 4;
const EC_HINT_WIT: usize = 4;
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

/// Per-point overhead witnesses common to all non-native paths.
fn per_point_overhead(half_bits: usize, num_limbs: usize, sr_witnesses: usize) -> usize {
    let scalar_bit_decomp = 2 * (half_bits + 1);
    let point_decomp = if num_limbs > 1 { 4 * num_limbs } else { 0 };
    scalar_bit_decomp
        + DETECT_SKIP_WIT
        + SANITIZE_WIT
        + EC_HINT_WIT
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
    /// point_double: (12N-6)W hint + 5N² products + N constants + 3×3N ltp
    fn point_double(n: usize, limb_bits: u32) -> Self {
        let wit = (12 * n - 6) + 5 * n * n + n + 9 * n;
        Self {
            witnesses:  wit,
            rc_limb:    6 * n + 6 * n,   // 6N hint limbs + 3×2N ltp limbs
            rc_carry:   3 * (2 * n - 2), // 3 equations × (2N-2) carries
            carry_bits: hint_carry_bits(limb_bits, 6 + n as u64, n),
        }
    }

    /// point_add: (12N-6)W hint + 4N² products + 3×3N ltp
    fn point_add(n: usize, limb_bits: u32) -> Self {
        let wit = (12 * n - 6) + 4 * n * n + 9 * n;
        Self {
            witnesses:  wit,
            rc_limb:    6 * n + 6 * n,
            rc_carry:   3 * (2 * n - 2),
            carry_bits: hint_carry_bits(limb_bits, 4 + n as u64, n),
        }
    }

    /// on_curve (worst case, a != 0): (7N-4)W hint + 4N² products + 2N
    /// constants + 3N ltp
    fn on_curve(n: usize, limb_bits: u32) -> Self {
        let wit = (7 * n - 4) + 4 * n * n + 2 * n + 3 * n;
        Self {
            witnesses:  wit,
            rc_limb:    3 * n + 2 * n,   // 3N hint limbs + 2N ltp limbs
            rc_carry:   2 * (2 * n - 2), // 2 equations × (2N-2) carries
            carry_bits: hint_carry_bits(limb_bits, 5 + n as u64, n),
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
    limb_bits + extra_bits
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
    let half_bits = (scalar_bits + 1) / 2;
    let w = window_size;
    let half_table_size = 1usize << (w - 1);
    let num_windows = ceil_div(half_bits, w);

    if n >= 2 {
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
    } else {
        calculate_msm_witness_cost_generic(
            native_field_bits,
            curve_modulus_bits,
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

    // --- Shared costs (one doubling chain for all points) ---
    let shared_doubles = num_windows * w;
    let shared_ec_wit = shared_doubles * ec_double.witnesses;
    let shared_offset_constants = 2 * n;

    // --- Per-point EC witnesses ---
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

    let per_point = pp_table_ec
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
    let shared_constants = 3 + shared_offset_constants; // gen_x, gen_y, zero + offset

    // --- Point accumulation ---
    let accum = n_points * (ec_add.witnesses + 2 * n)  // per-point add + skip select
        + n_points.saturating_sub(1)                    // all_skipped products
        + ec_add.witnesses + 4 * n + 2 * n             // offset sub + constants + selects
        + 2 + 2; // mask + recompose

    // --- Range checks ---
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();

    // Shared doublings
    ec_double.add_range_checks(shared_doubles, limb_bits, &mut rc_map);

    // Per-point: table doubles + table/loop/skew adds + on-curve
    let pp_doubles_count = 2 * tbl_d;
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
    shared_ec_wit + shared_constants + n_points * per_point + accum + range_check_cost
}

// ---------------------------------------------------------------------------
// Generic (single-limb) non-native cost
// ---------------------------------------------------------------------------

/// Generic (single-limb) non-native MSM cost using MultiLimbOps field op
/// chains.
#[allow(clippy::too_many_arguments)]
fn calculate_msm_witness_cost_generic(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    w: usize,
    limb_bits: u32,
    n: usize,
    half_bits: usize,
    half_table_size: usize,
    num_windows: usize,
) -> usize {
    // point_double: (5 add, 3 sub, 4 mul, 1 inv)
    // point_add:    (1 add, 5 sub, 3 mul, 1 inv)
    let (tbl_d, tbl_a) = table_build_ops(half_table_size);
    let shared_doubles = num_windows * w;

    // --- Shared doubling field ops ---
    let shared_add = shared_doubles * 5;
    let shared_sub = shared_doubles * 3;
    let shared_mul = shared_doubles * 4;
    let shared_inv = shared_doubles;

    // --- Per-point field ops: tables + loop adds + skew + on-curve + y-negate ---
    let mut pp_add = 2 * (tbl_d * 5 + tbl_a) + num_windows * 2 + 2 + 4;
    let mut pp_sub = 2 * (tbl_d * 3 + tbl_a * 5) + num_windows * (2 * 5 + 2) + 2 * 6 + 2;
    let mut pp_mul = 2 * (tbl_d * 4 + tbl_a * 3) + num_windows * 2 * 3 + 2 * 3 + 8;
    let mut pp_inv = 2 * (tbl_d + tbl_a) + num_windows * 2 + 2;

    let shared_field_ops =
        field_op_witnesses(shared_add, shared_sub, shared_mul, shared_inv, n, false);
    let pp_field_ops = field_op_witnesses(pp_add, pp_sub, pp_mul, pp_inv, n, false);

    let pp_doubles = 2 * tbl_d;
    let pp_negate_zeros = (4 + 2 * num_windows) * n;
    let shared_constants_glv = shared_doubles * n + 2 * n;
    let pp_constants = pp_doubles * n + 4 * n + pp_negate_zeros;

    let pp_table_selects = num_windows * 2 * half_table_size.saturating_sub(1) * 2 * n;
    let pp_xor = num_windows * 2 * 2 * w.saturating_sub(1);
    let pp_signed_y_selects = num_windows * 2 * n;
    let pp_y_negate_selects = 2 * n;
    let pp_skew_selects = 2 * 2 * n;
    let pp_selects =
        pp_table_selects + pp_xor + pp_signed_y_selects + pp_y_negate_selects + pp_skew_selects;

    let (sr_witnesses, sr_range_checks) = scalar_relation_cost(native_field_bits, scalar_bits);

    let per_point =
        pp_field_ops + pp_constants + pp_selects + per_point_overhead(half_bits, n, sr_witnesses);

    let shared_constants = 3 + 2 * n;

    // --- Point accumulation ---
    let pa_cost = field_op_witnesses(1, 5, 3, 1, n, false);
    let accum = n_points * (pa_cost + 2 * n)
        + n_points.saturating_sub(1)
        + pa_cost
        + 4 * n
        + 2 * n
        + 2
        + if n > 1 { 2 } else { 0 };

    // --- Range checks ---
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();
    add_field_op_range_checks(
        shared_add,
        shared_sub,
        shared_mul,
        shared_inv,
        n,
        limb_bits,
        curve_modulus_bits,
        false,
        &mut rc_map,
    );
    add_field_op_range_checks(
        n_points * pp_add,
        n_points * pp_sub,
        n_points * pp_mul,
        n_points * pp_inv,
        n,
        limb_bits,
        curve_modulus_bits,
        false,
        &mut rc_map,
    );
    if n > 1 {
        *rc_map.entry(limb_bits).or_default() += n_points * 4 * n;
    }
    for (&bits, &count) in &sr_range_checks {
        *rc_map.entry(bits).or_default() += n_points * count;
    }
    add_field_op_range_checks(
        n_points + 1,
        (n_points + 1) * 5,
        (n_points + 1) * 3,
        n_points + 1,
        n,
        limb_bits,
        curve_modulus_bits,
        false,
        &mut rc_map,
    );

    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);

    shared_field_ops
        + shared_constants_glv
        + n_points * per_point
        + shared_constants
        + accum
        + range_check_cost
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
/// Uses merged-loop optimization: all points share a single doubling per bit.
fn calculate_msm_witness_cost_native(
    native_field_bits: u32,
    n_points: usize,
    scalar_bits: usize,
) -> usize {
    let half_bits = (scalar_bits + 1) / 2;

    let on_curve = 4; // 2 × verify_on_curve_native (2W each)
    let y_negate = 6; // 2 × 3W (neg_y, y_eff, neg_y_eff)
    let (sr_wit, sr_rc) = scalar_relation_cost(native_field_bits, scalar_bits);

    let per_point = on_curve + y_negate
        + 2 * (half_bits + 1)   // scalar bit decomposition
        + DETECT_SKIP_WIT + SANITIZE_WIT + EC_HINT_WIT + GLV_HINT_WIT
        + sr_wit;

    let shared_constants = 5; // gen_x, gen_y, zero, offset_x, offset_y

    // Per bit: 4W (shared double) + n_points × 8W (2×(1W select + 3W add))
    let ec_loop = half_bits * (4 + 8 * n_points);
    // Skew correction: 2 branches × (3W add + 2W select) = 10W per point
    let skew = n_points * 10;

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

    n_points * per_point + shared_constants + ec_loop + skew + accum + range_check_cost
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
