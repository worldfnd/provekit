//! Analytical cost model for MSM parameter optimization.
//!
//! Follows the SHA256 pattern (`spread.rs:get_optimal_spread_width`):
//! pure analytical estimator → exhaustive search → pick optimal (limb_bits,
//! window_size).

/// Type of field operation for cost estimation.
#[derive(Clone, Copy)]
pub enum FieldOpType {
    Add,
    Sub,
    Mul,
    Inv,
}

/// Count field ops in scalar_mul_glv for given parameters.
///
/// The GLV approach does interleaved two-point scalar mul with half-width
/// scalars. Per window: w shared doubles + 2 table lookups + 2 point_adds + 2
/// is_zero + 2 point_selects Plus: 2 table builds, on-curve check, scalar
/// relation overhead.
fn count_glv_field_ops(
    scalar_bits: usize, // half_bits = ceil(order_bits / 2)
    window_size: usize,
) -> (usize, usize, usize, usize) {
    let w = window_size;
    let table_size = 1 << w;
    let num_windows = (scalar_bits + w - 1) / w;

    let double_ops = (4usize, 2usize, 5usize, 1usize);
    let add_ops = (2usize, 2usize, 3usize, 1usize);
    let select_ops_per_point = (2usize, 2usize, 2usize, 0usize);

    // Two tables (one for P, one for R)
    let table_doubles = if table_size > 2 { 1 } else { 0 };
    let table_adds = if table_size > 2 { table_size - 3 } else { 0 };

    let mut total_add = 2 * (table_doubles * double_ops.0 + table_adds * add_ops.0);
    let mut total_sub = 2 * (table_doubles * double_ops.1 + table_adds * add_ops.1);
    let mut total_mul = 2 * (table_doubles * double_ops.2 + table_adds * add_ops.2);
    let mut total_inv = 2 * (table_doubles * double_ops.3 + table_adds * add_ops.3);

    for win_idx in (0..num_windows).rev() {
        let bit_start = win_idx * w;
        let bit_end = std::cmp::min(bit_start + w, scalar_bits);
        let actual_w = bit_end - bit_start;
        let actual_selects = (1 << actual_w) - 1;

        // w shared doublings
        total_add += w * double_ops.0;
        total_sub += w * double_ops.1;
        total_mul += w * double_ops.2;
        total_inv += w * double_ops.3;

        // Two table lookups + two point_adds + two is_zeros + two point_selects
        for _ in 0..2 {
            total_add += actual_selects * select_ops_per_point.0;
            total_sub += actual_selects * select_ops_per_point.1;
            total_mul += actual_selects * select_ops_per_point.2;

            total_add += add_ops.0;
            total_sub += add_ops.1;
            total_mul += add_ops.2;
            total_inv += add_ops.3;

            total_inv += 1; // is_zero
            total_add += 1;
            total_mul += 1;

            total_add += select_ops_per_point.0;
            total_sub += select_ops_per_point.1;
            total_mul += select_ops_per_point.2;
        }
    }

    // On-curve checks for P and R: each needs 1 mul (y^2), 2 mul (x^2, x^3), 1 mul
    // (a*x), 2 add
    total_mul += 8;
    total_add += 4;

    // Conditional y-negation: 2 sub + 2 select (for P.y and R.y)
    total_sub += 2;
    total_add += 2 * select_ops_per_point.0;
    total_sub += 2 * select_ops_per_point.1;
    total_mul += 2 * select_ops_per_point.2;

    (total_add, total_sub, total_mul, total_inv)
}

/// Witnesses per single N-limb field operation.
fn witnesses_per_op(num_limbs: usize, op: FieldOpType, is_native: bool) -> usize {
    if is_native {
        // Native: no range checks, just standard R1CS witnesses
        match op {
            FieldOpType::Add => 1, // sum witness
            FieldOpType::Sub => 1, // sum witness
            FieldOpType::Mul => 1, // product witness
            FieldOpType::Inv => 1, // inverse witness
        }
    } else if num_limbs == 1 {
        // Single-limb non-native: reduce_mod_p pattern
        match op {
            FieldOpType::Add => 5, // a+b, m const, k, k*m, result
            FieldOpType::Sub => 5, // same
            FieldOpType::Mul => 5, // a*b, m const, k, k*m, result
            FieldOpType::Inv => 7, // a_inv + mul_mod_p(5) + range_check
        }
    } else {
        // Multi-limb: N-limb operations
        let n = num_limbs;
        match op {
            // add/sub: q + N*(v_offset, carry, r_limb) + N*(v_diff, borrow, d_limb)
            FieldOpType::Add | FieldOpType::Sub => 1 + 3 * n + 3 * n,
            // mul: hint(4N-2) + N² products + 2N-1 column constraints + lt_check
            FieldOpType::Mul => (4 * n - 2) + n * n + 3 * n,
            // inv: hint(N) + mul costs
            FieldOpType::Inv => n + (4 * n - 2) + n * n + 3 * n,
        }
    }
}

/// Total estimated witness cost for one scalar_mul.
pub fn calculate_msm_witness_cost(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
    window_size: usize,
    limb_bits: u32,
) -> usize {
    let is_native = curve_modulus_bits == native_field_bits;
    let num_limbs = if is_native {
        1
    } else {
        ((curve_modulus_bits as usize) + (limb_bits as usize) - 1) / (limb_bits as usize)
    };

    let wit_add = witnesses_per_op(num_limbs, FieldOpType::Add, is_native);
    let wit_sub = witnesses_per_op(num_limbs, FieldOpType::Sub, is_native);
    let wit_mul = witnesses_per_op(num_limbs, FieldOpType::Mul, is_native);
    let wit_inv = witnesses_per_op(num_limbs, FieldOpType::Inv, is_native);

    // FakeGLV path for ALL points: half-width interleaved scalar mul
    let half_bits = (scalar_bits + 1) / 2;
    let (n_add, n_sub, n_mul, n_inv) = count_glv_field_ops(half_bits, window_size);
    let glv_scalarmul = n_add * wit_add + n_sub * wit_sub + n_mul * wit_mul + n_inv * wit_inv;

    // Per-point overhead: scalar decomposition (2 × half_bits for s1, s2) +
    // scalar relation (~150 witnesses) + FakeGLVHint (4 witnesses)
    let scalar_decomp = 2 * half_bits + 10;
    let scalar_relation = 150;
    let glv_hint = 4;

    // EcScalarMulHint: 2 witnesses per point (only for n_points > 1)
    let ec_hint = if n_points > 1 { 2 } else { 0 };

    let per_point = glv_scalarmul + scalar_decomp + scalar_relation + glv_hint + ec_hint;

    // Point accumulation: (n_points - 1) point_adds
    let accum = if n_points > 1 {
        let accum_adds = n_points - 1;
        accum_adds
            * (witnesses_per_op(num_limbs, FieldOpType::Add, is_native) * 2
                + witnesses_per_op(num_limbs, FieldOpType::Sub, is_native) * 2
                + witnesses_per_op(num_limbs, FieldOpType::Mul, is_native) * 3
                + witnesses_per_op(num_limbs, FieldOpType::Inv, is_native))
    } else {
        0
    };

    n_points * per_point + accum
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
        return true; // Single-limb path has no column equations.
    }
    let ceil_log2_n = (num_limbs as f64).log2().ceil() as u32;
    // Max column value < 2^(2*limb_bits + ceil_log2_n + 3).
    // Need this < p_native >= 2^(native_field_bits - 1).
    2 * limb_bits + ceil_log2_n + 3 < native_field_bits
}

/// Search for optimal (limb_bits, window_size) minimizing witness cost.
///
/// Searches limb_bits ∈ [8..max] and window_size ∈ [2..8].
/// Each candidate is checked for column equation soundness: the schoolbook
/// multiplication's intermediate values must fit in the native field without
/// modular wraparound (see [`column_equation_fits_native_field`]).
pub fn get_optimal_msm_params(
    native_field_bits: u32,
    curve_modulus_bits: u32,
    n_points: usize,
    scalar_bits: usize,
) -> (u32, usize) {
    let is_native = curve_modulus_bits == native_field_bits;
    if is_native {
        // For native field, limb_bits doesn't matter (no multi-limb decomposition).
        // Just optimize window_size.
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
            );
            if cost < best_cost {
                best_cost = cost;
                best_window = ws;
            }
        }
        return (native_field_bits, best_window);
    }

    // Upper bound on search: even with N=2 (best case), we need
    // 2*lb + ceil(log2(2)) + 3 < native_field_bits => lb < (native_field_bits - 4)
    // / 2. The per-candidate soundness check below is the actual gate.
    let max_limb_bits = (native_field_bits.saturating_sub(4)) / 2;
    let mut best_cost = usize::MAX;
    let mut best_limb_bits = max_limb_bits.min(86);
    let mut best_window = 4;

    // Search space
    for lb in (8..=max_limb_bits).step_by(2) {
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
        // Grumpkin over BN254: native field
        let (limb_bits, window_size) = get_optimal_msm_params(254, 254, 1, 256);
        assert_eq!(limb_bits, 254);
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_optimal_params_secp256r1() {
        // secp256r1 over BN254: 256-bit modulus, non-native
        let (limb_bits, window_size) = get_optimal_msm_params(254, 256, 1, 256);
        let num_limbs = ((256 + limb_bits - 1) / limb_bits) as usize;
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "optimizer selected unsound limb_bits={limb_bits} (N={num_limbs})"
        );
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_optimal_params_goldilocks() {
        // Hypothetical 64-bit field over BN254
        let (limb_bits, window_size) = get_optimal_msm_params(254, 64, 1, 64);
        let num_limbs = ((64 + limb_bits - 1) / limb_bits) as usize;
        assert!(
            column_equation_fits_native_field(254, limb_bits, num_limbs),
            "optimizer selected unsound limb_bits={limb_bits} (N={num_limbs})"
        );
        assert!(window_size >= 2 && window_size <= 8);
    }

    #[test]
    fn test_column_equation_soundness_boundary() {
        // For BN254 (254 bits) with N=3: max safe limb_bits is 124.
        // 2*124 + ceil(log2(3)) + 3 = 248 + 2 + 3 = 253 < 254 ✓
        assert!(column_equation_fits_native_field(254, 124, 3));
        // 2*125 + ceil(log2(3)) + 3 = 250 + 2 + 3 = 255 ≥ 254 ✗
        assert!(!column_equation_fits_native_field(254, 125, 3));
        // 2*126 + ceil(log2(3)) + 3 = 252 + 2 + 3 = 257 ≥ 254 ✗
        assert!(!column_equation_fits_native_field(254, 126, 3));
    }

    #[test]
    fn test_secp256r1_limb_bits_not_126() {
        // Regression: limb_bits=126 with N=3 causes offset_w = 2^255 > p_BN254,
        // making the schoolbook column equations unsound.
        let (limb_bits, _) = get_optimal_msm_params(254, 256, 1, 256);
        assert!(
            limb_bits <= 124,
            "secp256r1 limb_bits={limb_bits} exceeds safe maximum 124"
        );
    }
}
