//! Analytical cost model for MSM parameter optimization.
//!
//! Follows the SHA256 pattern (`spread.rs:get_optimal_spread_width`):
//! pure analytical estimator → exhaustive search → pick optimal (limb_bits,
//! window_size).

use std::collections::BTreeMap;

/// The 256-bit scalar is split into two halves (s_lo, s_hi) because it doesn't
/// fit in the native field. This constant is used throughout the scalar relation
/// cost model.
const SCALAR_HALF_BITS: usize = 128;

/// Type of field operation for cost estimation.
#[derive(Clone, Copy)]
pub enum FieldOpType {
    Add,
    Sub,
    Mul,
    Inv,
}

/// Count field ops and selects in scalar_mul_glv for given parameters.
///
/// Returns `(n_add, n_sub, n_mul, n_inv, n_is_zero, n_point_selects,
/// n_coord_selects)`.
///
/// Field ops (add/sub/mul/inv) come from point_double, point_add, and
/// on-curve checks. Selects are counted separately because they create
/// `num_limbs` witnesses per coordinate (via `select_witness`), not
/// multi-limb field op witnesses.
///
/// - `n_point_selects`: selects on EcPoint (2 coordinates), from table
///   lookups and conditional skip after point_add.
/// - `n_coord_selects`: selects on single Limbs coordinate, from
///   y-negation.
/// - `n_is_zero`: `compute_is_zero` calls, each creating exactly 3 native
///   witnesses regardless of num_limbs.
fn count_glv_field_ops(
    scalar_bits: usize, // half_bits = ceil(order_bits / 2)
    window_size: usize,
) -> (usize, usize, usize, usize, usize, usize, usize) {
    let w = window_size;
    let table_size = 1 << w;
    let num_windows = (scalar_bits + w - 1) / w;

    // Field ops per primitive EC operation (add, sub, mul, inv):
    let double_ops = (4usize, 2usize, 5usize, 1usize);
    let add_ops = (2usize, 2usize, 3usize, 1usize);

    // Two tables (one for P, one for R)
    let table_doubles = if table_size > 2 { 1 } else { 0 };
    let table_adds = if table_size > 2 { table_size - 3 } else { 0 };

    let mut total_add = 2 * (table_doubles * double_ops.0 + table_adds * add_ops.0);
    let mut total_sub = 2 * (table_doubles * double_ops.1 + table_adds * add_ops.1);
    let mut total_mul = 2 * (table_doubles * double_ops.2 + table_adds * add_ops.2);
    let mut total_inv = 2 * (table_doubles * double_ops.3 + table_adds * add_ops.3);
    let mut total_is_zero = 0usize;
    let mut total_point_selects = 0usize;

    for win_idx in (0..num_windows).rev() {
        let bit_start = win_idx * w;
        let bit_end = std::cmp::min(bit_start + w, scalar_bits);
        let actual_w = bit_end - bit_start;
        let actual_table_selects = (1 << actual_w) - 1;

        // w shared doublings
        total_add += w * double_ops.0;
        total_sub += w * double_ops.1;
        total_mul += w * double_ops.2;
        total_inv += w * double_ops.3;

        // Two table lookups + two point_adds + two is_zeros + two conditional
        // skips
        for _ in 0..2 {
            // Table lookup: (2^actual_w - 1) point selects
            total_point_selects += actual_table_selects;

            // Point add
            total_add += add_ops.0;
            total_sub += add_ops.1;
            total_mul += add_ops.2;
            total_inv += add_ops.3;

            // is_zero: 3 fixed native witnesses each
            total_is_zero += 1;

            // Conditional skip: 1 point select
            total_point_selects += 1;
        }
    }

    // On-curve checks for P and R: each needs mul(y²), mul(x²), mul(x³),
    // mul(a·x), add(x³+ax), add(x³+ax+b) = 4 mul + 2 add per point
    total_mul += 8;
    total_add += 4;

    // Conditional y-negation: 2 negate (= 2 sub) + 2 Limbs selects (1 coord
    // each)
    total_sub += 2;
    let total_coord_selects = 2usize;

    (
        total_add,
        total_sub,
        total_mul,
        total_inv,
        total_is_zero,
        total_point_selects,
        total_coord_selects,
    )
}

/// Count only range-check-producing field ops in scalar_mul_glv.
///
/// Returns `(n_add, n_sub, n_mul, n_inv)` excluding selects and is_zero,
/// which generate 0 range checks (selects are native `select_witness` calls,
/// is_zero operates on `pack_bits` results).
fn count_glv_real_field_ops(
    scalar_bits: usize,
    window_size: usize,
) -> (usize, usize, usize, usize) {
    let (n_add, n_sub, n_mul, n_inv, _, _, _) =
        count_glv_field_ops(scalar_bits, window_size);
    (n_add, n_sub, n_mul, n_inv)
}

/// Witnesses per single N-limb field operation.
fn witnesses_per_op(num_limbs: usize, op: FieldOpType, is_native: bool) -> usize {
    if is_native {
        match op {
            FieldOpType::Add => 1,
            FieldOpType::Sub => 1,
            FieldOpType::Mul => 1,
            FieldOpType::Inv => 1,
        }
    } else if num_limbs == 1 {
        // Single-limb non-native: reduce_mod_p pattern
        match op {
            FieldOpType::Add => 5, // a+b, m const, k, k*m, result
            FieldOpType::Sub => 5,
            FieldOpType::Mul => 5, // a*b, m const, k, k*m, result
            FieldOpType::Inv => 6, // a_inv(1) + mul_mod_p_single(5)
        }
    } else {
        let n = num_limbs;
        match op {
            // add/sub: q + N*(v_offset, carry, r_limb) + N*(v_diff, borrow,
            // d_limb)
            FieldOpType::Add | FieldOpType::Sub => 1 + 3 * n + 3 * n,
            // mul: hint(4N-2) + N² products + 2N-1 column constraints +
            // lt_check(3N)
            FieldOpType::Mul => (4 * n - 2) + n * n + 3 * n,
            // inv: hint(N) + mul costs
            FieldOpType::Inv => n + (4 * n - 2) + n * n + 3 * n,
        }
    }
}

/// Count witnesses for scalar relation verification.
///
/// The scalar relation verifies `(-1)^neg1*|s1| + (-1)^neg2*|s2|*s ≡ 0 (mod
/// n)` using multi-limb arithmetic with the curve order as modulus.
fn count_scalar_relation_witnesses(native_field_bits: u32, scalar_bits: usize) -> usize {
    let limb_bits = scalar_relation_limb_bits(native_field_bits, scalar_bits);
    let num_limbs = (scalar_bits + limb_bits as usize - 1) / limb_bits as usize;
    let scalar_half_limbs =
        (SCALAR_HALF_BITS + limb_bits as usize - 1) / limb_bits as usize;

    let wit_add = witnesses_per_op(num_limbs, FieldOpType::Add, false);
    let wit_sub = witnesses_per_op(num_limbs, FieldOpType::Sub, false);
    let wit_mul = witnesses_per_op(num_limbs, FieldOpType::Mul, false);

    // Scalar decomposition: DD digits for s_lo + s_hi, plus cross-boundary
    // witness when limb boundaries don't align with the 128-bit split
    let has_cross_boundary =
        num_limbs > 1 && SCALAR_HALF_BITS % limb_bits as usize != 0;
    let scalar_decomp = 2 * scalar_half_limbs + has_cross_boundary as usize;

    // Half-scalar decomposition: DD digits + zero-pad constants for s1, s2
    let half_scalar_decomp = 2 * num_limbs;

    // Sign handling: sum + diff + XOR (2 native witnesses) + select
    let sign_handling = wit_add + wit_sub + 2 + num_limbs;

    scalar_decomp + half_scalar_decomp + wit_mul + sign_handling
}

/// Range checks generated by a single N-limb field operation.
///
/// Returns entries as `(bit_width, count)` pairs. Native ops produce no
/// range checks. Single-limb non-native uses `reduce_mod_p` (1 check at
/// `curve_modulus_bits`). Multi-limb ops produce checks at `limb_bits`
/// and `carry_bits = limb_bits + ceil(log2(N)) + 2`.
fn range_checks_per_op(
    num_limbs: usize,
    op: FieldOpType,
    is_native: bool,
    limb_bits: u32,
    curve_modulus_bits: u32,
) -> Vec<(u32, usize)> {
    if is_native {
        return vec![];
    }
    if num_limbs == 1 {
        let bits = curve_modulus_bits;
        return match op {
            FieldOpType::Add | FieldOpType::Sub | FieldOpType::Mul => vec![(bits, 1)],
            FieldOpType::Inv => vec![(bits, 2)],
        };
    }
    let n = num_limbs;
    let ceil_log2_n = if n <= 1 {
        0u32
    } else {
        (n as f64).log2().ceil() as u32
    };
    let carry_bits = limb_bits + ceil_log2_n + 2;
    match op {
        // add/sub: 2N from less_than_p_check_multi
        FieldOpType::Add | FieldOpType::Sub => vec![(limb_bits, 2 * n)],
        // mul: N q-limbs + 2N from less_than_p at limb_bits, (2N-2) carries
        // at carry_bits
        FieldOpType::Mul => vec![(limb_bits, 3 * n), (carry_bits, 2 * n - 2)],
        // inv: N inv-limbs + mul's checks
        FieldOpType::Inv => vec![(limb_bits, 4 * n), (carry_bits, 2 * n - 2)],
    }
}

/// Count range checks for scalar relation verification.
///
/// Sources: DD digits (scalar + half-scalar decompositions) and multi-limb
/// field ops (1 mul + 1 add + 1 sub for XOR-based sign handling).
fn count_scalar_relation_range_checks(
    native_field_bits: u32,
    scalar_bits: usize,
) -> BTreeMap<u32, usize> {
    let limb_bits = scalar_relation_limb_bits(native_field_bits, scalar_bits);
    let num_limbs = (scalar_bits + limb_bits as usize - 1) / limb_bits as usize;
    let half_bits = (scalar_bits + 1) / 2;
    let half_limbs = (half_bits + limb_bits as usize - 1) / limb_bits as usize;
    let scalar_half_limbs =
        (SCALAR_HALF_BITS + limb_bits as usize - 1) / limb_bits as usize;

    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();

    // DD digits: s_lo + s_hi (2 × scalar_half_limbs) + s1 + s2 (2 × half_limbs)
    *rc_map.entry(limb_bits).or_default() += 2 * scalar_half_limbs + 2 * half_limbs;

    // Multi-limb field ops: mul + add + sub
    let modulus_bits = scalar_bits as u32;
    for op in [FieldOpType::Mul, FieldOpType::Add, FieldOpType::Sub] {
        for (bits, count) in range_checks_per_op(num_limbs, op, false, limb_bits, modulus_bits) {
            *rc_map.entry(bits).or_default() += count;
        }
    }

    rc_map
}

/// Total estimated witness cost for an MSM.
///
/// Accounts for three categories of witnesses:
/// 1. **Inline witnesses** — field ops, selects, is_zero, hints, DDs
/// 2. **Range check resolution** — LogUp/naive cost for all range checks
/// 3. **Per-point overhead** — detect_skip, sanitization, point
///    decomposition
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
        return calculate_msm_witness_cost_native(
            native_field_bits,
            n_points,
            scalar_bits,
            window_size,
        );
    }

    let num_limbs =
        ((curve_modulus_bits as usize) + (limb_bits as usize) - 1) / (limb_bits as usize);

    let wit_add = witnesses_per_op(num_limbs, FieldOpType::Add, false);
    let wit_sub = witnesses_per_op(num_limbs, FieldOpType::Sub, false);
    let wit_mul = witnesses_per_op(num_limbs, FieldOpType::Mul, false);
    let wit_inv = witnesses_per_op(num_limbs, FieldOpType::Inv, false);

    // === GLV scalar mul witnesses ===
    let half_bits = (scalar_bits + 1) / 2;
    let (n_add, n_sub, n_mul, n_inv, n_is_zero, n_point_selects, n_coord_selects) =
        count_glv_field_ops(half_bits, window_size);

    // Field ops: priced at full multi-limb cost
    let field_op_cost =
        n_add * wit_add + n_sub * wit_sub + n_mul * wit_mul + n_inv * wit_inv;

    // Selects: each select_witness creates 1 witness per limb (inlined).
    // Point select = 2 coords × num_limbs × 1.
    // Coord select = 1 coord × num_limbs × 1.
    let select_cost =
        n_point_selects * 2 * num_limbs + n_coord_selects * num_limbs;

    // is_zero: 3 fixed native witnesses each (SafeInverse + Product + Sum)
    let is_zero_cost = n_is_zero * 3;

    let glv_scalarmul = field_op_cost + select_cost + is_zero_cost;

    // === Per-point overhead ===
    // Scalar bit decomposition: 2 DDs of half_bits 1-bit digits
    let scalar_bit_decomp = 2 * half_bits;

    // detect_skip: 2×is_zero(3) + product(1) + boolean_or(1) = 8
    let detect_skip_cost = 8;

    // Sanitization: 3 constants (gen_x, gen_y, zero) + 6 select_witness × 1
    // For multi-point, constants are shared but impact is negligible.
    let sanitize_cost = 3 + 6;

    // Point decomposition digit witnesses (add_digital_decomposition creates
    // num_limbs digit witnesses per coordinate; 2 coords × 2 points = 4).
    // Only applies when num_limbs > 1 (decompose_point_to_limbs is a no-op
    // for num_limbs == 1).
    let point_decomp_digits = if num_limbs > 1 { 4 * num_limbs } else { 0 };

    // Scalar relation (analytical)
    let scalar_relation = count_scalar_relation_witnesses(native_field_bits, scalar_bits);

    // FakeGLVHint: 4 witnesses (s1, s2, neg1, neg2)
    let glv_hint = 4;

    // EcScalarMulHint: 2 witnesses per point (only for n_points > 1)
    let ec_hint = if n_points > 1 { 2 } else { 0 };

    let per_point = glv_scalarmul
        + scalar_bit_decomp
        + detect_skip_cost
        + sanitize_cost
        + point_decomp_digits
        + scalar_relation
        + glv_hint
        + ec_hint;

    // === Point accumulation (multi-point only) ===
    // Each point gets: point_add(acc, R_i) + point_select_unchecked(skip).
    // Plus final offset subtraction: 1 point_add + constants + 2 Limbs
    // selects.
    let point_add_cost = 2 * wit_add + 2 * wit_sub + 3 * wit_mul + wit_inv;
    let accum = if n_points > 1 {
        let accum_point_adds = n_points * point_add_cost;
        let accum_point_selects = n_points * 2 * num_limbs;
        // all_skipped tracking: (n_points - 1) product witnesses
        let all_skipped_products = n_points - 1;
        // Offset subtraction: point_add + 4×constant_limbs + 2 Limbs selects
        // + 2×constant_limbs for initial acc
        let offset_sub = point_add_cost + 6 * num_limbs + 2 * num_limbs;

        accum_point_adds + accum_point_selects + all_skipped_products + offset_sub
    } else {
        0
    };

    // === Range check resolution cost ===
    // All points' range checks share the same LogUp tables, so we aggregate
    // across n_points before computing resolution cost (table amortizes).
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();

    // 1. Range checks from GLV field ops (selects generate 0 range checks)
    let (rc_n_add, rc_n_sub, rc_n_mul, rc_n_inv) =
        count_glv_real_field_ops(half_bits, window_size);
    for &(op, n_ops) in &[
        (FieldOpType::Add, rc_n_add),
        (FieldOpType::Sub, rc_n_sub),
        (FieldOpType::Mul, rc_n_mul),
        (FieldOpType::Inv, rc_n_inv),
    ] {
        for (bits, count) in
            range_checks_per_op(num_limbs, op, false, limb_bits, curve_modulus_bits)
        {
            *rc_map.entry(bits).or_default() += n_points * n_ops * count;
        }
    }

    // 2. Point decomposition range checks (num_limbs > 1 only).
    // 4 coordinates: px, py, rx, ry.
    if num_limbs > 1 {
        *rc_map.entry(limb_bits).or_default() += n_points * 4 * num_limbs;
    }

    // 3. Scalar relation range checks (always non-native, per point)
    let sr_checks = count_scalar_relation_range_checks(native_field_bits, scalar_bits);
    for (bits, count) in &sr_checks {
        *rc_map.entry(*bits).or_default() += n_points * count;
    }

    // 4. Accumulation range checks: n_points point_adds + 1 offset
    //    subtraction point_add (multi-point only)
    if n_points > 1 {
        let accum_point_adds = n_points + 1; // loop + offset subtraction
        for &(op, n_ops) in &[
            (FieldOpType::Add, 2usize),
            (FieldOpType::Sub, 2usize),
            (FieldOpType::Mul, 3usize),
            (FieldOpType::Inv, 1usize),
        ] {
            for (bits, count) in
                range_checks_per_op(num_limbs, op, false, limb_bits, curve_modulus_bits)
            {
                *rc_map.entry(bits).or_default() += accum_point_adds * n_ops * count;
            }
        }
    }

    // 5. Compute resolution cost
    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);

    n_points * per_point + accum + range_check_cost
}

/// Total estimated witness cost for a native-field MSM using hint-verified EC
/// ops with signed-bit wNAF (w=1).
///
/// The native path replaces expensive field inversions with prover hints
/// verified via raw R1CS constraints:
/// - `point_double_verified_native`: 4W (3 hint + 1 product) vs 12W generic
/// - `point_add_verified_native`: 3W (3 hint) vs 8W generic
/// - `verify_on_curve_native`: 2W (2 products) vs 6W generic
/// - No multi-limb arithmetic for EC ops → zero EC-related range checks
///
/// Uses signed-bit wNAF (w=1): every digit is non-zero (±1), so we always
/// add — no conditional skip selects.
///
/// For n_points >= 2, uses merged-loop optimization: all points share a
/// single doubling per bit, saving 4W × (n-1) per bit.
/// Per bit (merged): 4W (shared double) + n × 8W (2×(1W select + 3W add)).
/// Skew correction: n × 10W.
fn calculate_msm_witness_cost_native(
    native_field_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    _window_size: usize,
) -> usize {
    let half_bits = (scalar_bits + 1) / 2;

    // === Costs that are always per-point ===
    let on_curve = 2 * 2; // 2 × verify_on_curve_native (2W each)
    let glv_hint = 4; // FakeGLVHint (s1, s2, neg1, neg2)
    let scalar_bit_decomp = 2 * (half_bits + 1); // signed-bit hint witnesses
    let y_negate = 2 + 2 + 2; // 2 neg_y + 2 py_eff + 2 neg_py_eff
    let detect_skip_cost = 8; // 2×is_zero(3) + product(1) + boolean_or(1)
    let sanitize_cost = 3 + 6; // 3 constants + 6 selects
    let ec_hint = if n_points > 1 { 2 } else { 0 }; // EcScalarMulHint
    let scalar_relation = count_scalar_relation_witnesses(native_field_bits, scalar_bits);

    let per_point_fixed = on_curve
        + glv_hint
        + scalar_bit_decomp
        + y_negate
        + detect_skip_cost
        + sanitize_cost
        + scalar_relation
        + ec_hint;

    // === EC loop + skew + constants ===
    let inline_total = if n_points == 1 {
        // Single-point: separate loop (unchanged path)
        let ec_wit = half_bits * 12;
        let skew_correction = 10;
        let offset_const = 2;
        let identity_const = 2;
        per_point_fixed + ec_wit + skew_correction + offset_const + identity_const
    } else {
        // Multi-point: merged loop with shared doubling
        // Per bit: 4W (shared double) + n_points × 8W (2×(1W select + 3W add))
        let ec_wit = half_bits * (4 + 8 * n_points);
        // Skew correction: 10W per point
        let skew_correction = n_points * 10;
        // Offset and identity constants are shared (not per-point)
        let offset_const = 2;
        let identity_const = 2;
        n_points * per_point_fixed + ec_wit + skew_correction + offset_const + identity_const
    };

    // === Point accumulation (multi-point only) ===
    let accum = if n_points > 1 {
        // Initial accumulator: 2W (constant witnesses for offset x,y)
        let acc_init = 2;
        // Per point: point_add_verified_native (3W) + 2 skip selects (2W)
        let per_point_accum = n_points * (3 + 2);
        // all_skipped tracking: (n_points - 1) product witnesses
        let all_skipped = n_points - 1;
        // Offset subtraction: 3 constants + 2 selects + point_add (3W) + 2 mask selects
        let offset_sub = 3 + 2 + 3 + 2;

        acc_init + per_point_accum + all_skipped + offset_sub
    } else {
        0
    };

    // === Range check cost ===
    // Native EC ops produce NO range checks (no multi-limb arithmetic).
    // Only scalar relation produces range checks.
    let mut rc_map: BTreeMap<u32, usize> = BTreeMap::new();
    let sr_checks = count_scalar_relation_range_checks(native_field_bits, scalar_bits);
    for (bits, count) in &sr_checks {
        *rc_map.entry(*bits).or_default() += n_points * count;
    }
    let range_check_cost = crate::range_check::estimate_range_check_cost(&rc_map);

    inline_total + accum + range_check_cost
}

/// Picks the widest limb size for scalar-relation multi-limb arithmetic that
/// fits inside the native field without overflow.
///
/// Searches for the minimum number of limbs N (starting from 1) such that
/// the schoolbook column equations don't overflow the native field. Fewer
/// limbs means wider limbs, which means fewer witnesses and range checks.
///
/// For BN254 (254-bit native field, ~254-bit order): N=3 @ 85-bit limbs.
/// For small curves where half_scalar × full_scalar fits natively: N=1.
pub(super) fn scalar_relation_limb_bits(native_field_bits: u32, order_bits: usize) -> u32 {
    let half_bits = (order_bits + 1) / 2;

    // N=1 is valid only if the mul product (half_scalar * full_scalar)
    // fits in the native field without wrapping.
    if half_bits + order_bits < native_field_bits as usize {
        return order_bits as u32;
    }

    // For N>=2: find minimum N where schoolbook column equations fit.
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
/// In `mul_mod_p_multi`, the schoolbook multiplication verifies `a·b = p·q + r`
/// via column equations that include product sums, carry offsets, and outgoing
/// carries. Both sides of each column equation must evaluate to less than the
/// native field modulus as **integers** — if they overflow, the field's modular
/// reduction makes `LHS ≡ RHS (mod p)` weaker than `LHS = RHS`, breaking
/// soundness.
///
/// The maximum integer value across either side of any column equation is
/// bounded by:
///
///   `2^(2W + ceil(log2(N)) + 3)`
///
/// where `W = limb_bits` and `N = num_limbs`. This accounts for:
/// - Up to N cross-products per column, each < `2^(2W)`
/// - The carry offset `2^(2W + ceil(log2(N)) + 1)` (dominant term)
/// - Outgoing carry term `2^W * offset_carry` on the RHS
///
/// Since the native field modulus satisfies `p >= 2^(native_field_bits - 1)`,
/// the conservative soundness condition is:
///
///   `2 * limb_bits + ceil(log2(num_limbs)) + 3 < native_field_bits`
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
/// Searches limb_bits ∈ [8..max] and window_size ∈ [2..8].
/// Each candidate is checked for column equation soundness: the schoolbook
/// multiplication's intermediate values must fit in the native field without
/// modular wraparound (see [`column_equation_fits_native_field`]).
///
/// `is_native` should come from `CurveParams::is_native_field()` which
/// compares actual modulus values, not just bit widths.
pub fn get_optimal_msm_params(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    is_native: bool,
) -> (u32, usize) {
    if is_native {
        let mut best_cost = usize::MAX;
        let mut best_window = 4;
        for ws in 2..=8 {
            let cost = calculate_msm_witness_cost(
                native_field_bits,
                curve_modulus_bits,
                n_points,
                scalar_bits,
                ws,
                native_field_bits,
                true,
            );
            if cost < best_cost {
                best_cost = cost;
                best_window = ws;
            }
        }
        return (native_field_bits, best_window);
    }

    let max_limb_bits = (native_field_bits.saturating_sub(4)) / 2;
    let mut best_cost = usize::MAX;
    let mut best_limb_bits = max_limb_bits.min(86);
    let mut best_window = 4;

    for lb in 8..=max_limb_bits {
        let num_limbs = ((curve_modulus_bits as usize) + (lb as usize) - 1) / (lb as usize);
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
        let num_limbs = ((256 + limb_bits - 1) / limb_bits) as usize;
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "optimizer selected unsound limb_bits={limb_bits} (N={num_limbs})"
        );
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_optimal_params_goldilocks() {
        let (limb_bits, window_size) = get_optimal_msm_params(254, 64, 1, 64, false);
        let num_limbs = ((64 + limb_bits - 1) / limb_bits) as usize;
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
    fn test_scalar_relation_witnesses_grumpkin() {
        let sr = count_scalar_relation_witnesses(254, 256);
        assert!(sr > 50 && sr < 200, "unexpected scalar_relation={sr}");
    }

    #[test]
    fn test_scalar_relation_witnesses_small_curve() {
        let sr = count_scalar_relation_witnesses(254, 64);
        assert!(sr < 100, "64-bit curve scalar_relation={sr} should be < 100");
    }

    #[test]
    fn test_is_zero_cost_independent_of_num_limbs() {
        let (_, _, _, _, n_is_zero_w4, _, _) = count_glv_field_ops(128, 4);
        let (_, _, _, _, n_is_zero_w3, _, _) = count_glv_field_ops(128, 3);
        assert!(n_is_zero_w4 > 0);
        assert!(n_is_zero_w3 > 0);
    }

    #[test]
    fn test_inv_single_limb_witness_count() {
        // inv_mod_p_single: a_inv(1) + mul_mod_p_single(5) = 6
        assert_eq!(witnesses_per_op(1, FieldOpType::Inv, false), 6);
    }

    #[test]
    fn test_selects_counted_separately() {
        // Verify selects are returned as separate counts, not mixed into
        // field ops.
        let (_, _, _, _, _, pt_sel, coord_sel) = count_glv_field_ops(128, 4);
        assert!(pt_sel > 0, "expected point selects > 0");
        assert_eq!(coord_sel, 2, "expected 2 coord selects (y-negation)");
    }

    #[test]
    fn test_select_cost_scales_with_num_limbs() {
        // For N=3, select cost should be 2*N per point select (1 witness
        // per limb per coordinate, inlined select_witness).
        let half_bits = 129;
        let (_, _, _, _, _, n_pt_sel, n_coord_sel) = count_glv_field_ops(half_bits, 4);
        let select_cost_n1 = n_pt_sel * 2 * 1 + n_coord_sel * 1;
        let select_cost_n3 = n_pt_sel * 2 * 3 + n_coord_sel * 3;
        // N=3 should be exactly 3× N=1 for selects (linear in num_limbs)
        assert_eq!(select_cost_n3, select_cost_n1 * 3);
    }

    #[test]
    fn test_range_checks_per_op_native() {
        assert!(range_checks_per_op(1, FieldOpType::Add, true, 254, 254).is_empty());
        assert!(range_checks_per_op(1, FieldOpType::Mul, true, 254, 254).is_empty());
        assert!(range_checks_per_op(1, FieldOpType::Inv, true, 254, 254).is_empty());
    }

    #[test]
    fn test_range_checks_per_op_single_limb() {
        let rc = range_checks_per_op(1, FieldOpType::Add, false, 64, 64);
        assert_eq!(rc, vec![(64, 1)]);
        let rc = range_checks_per_op(1, FieldOpType::Inv, false, 64, 64);
        assert_eq!(rc, vec![(64, 2)]);
    }

    #[test]
    fn test_range_checks_per_op_multi_limb() {
        // N=3, limb_bits=86: carry_bits = 86 + ceil(log2(3)) + 2 = 90
        let rc = range_checks_per_op(3, FieldOpType::Add, false, 86, 256);
        assert_eq!(rc, vec![(86, 6)]);
        let rc = range_checks_per_op(3, FieldOpType::Mul, false, 86, 256);
        assert_eq!(rc, vec![(86, 9), (90, 4)]);
        let rc = range_checks_per_op(3, FieldOpType::Inv, false, 86, 256);
        assert_eq!(rc, vec![(86, 12), (90, 4)]);
    }

    #[test]
    fn test_scalar_relation_range_checks_256bit() {
        let rc = count_scalar_relation_range_checks(254, 256);
        let total: usize = rc.values().sum();
        assert!(total > 30, "too few range checks: {total}");
        assert!(total < 200, "too many range checks: {total}");
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
