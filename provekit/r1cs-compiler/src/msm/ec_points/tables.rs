//! Point table construction and lookup for windowed scalar multiplication.
//!
//! Builds tables of point multiples and performs lookups using bit witnesses
//! for both unsigned and signed-digit windowed approaches.

use {
    super::EcOps,
    crate::msm::{
        multi_limb_ops::{EcFieldParams, MultiLimbOps},
        EcPoint,
    },
    ark_ff::Field,
    provekit_common::{witness::SumTerm, FieldElement},
};

/// Builds a signed point table of odd multiples:
/// T\[0\] = P, T\[1\] = 3P, T\[2\] = 5P, ..., T\[k-1\] = (2k-1)P
/// where k = `half_table_size`.
fn build_signed_point_table<E: EcOps>(
    ops: &mut MultiLimbOps<'_, '_, E::Field, E, EcFieldParams>,
    p: EcPoint,
    half_table_size: usize,
) -> Vec<EcPoint> {
    assert!(half_table_size >= 1);
    let mut table = Vec::with_capacity(half_table_size);
    table.push(p); // T[0] = 1*P
    if half_table_size >= 2 {
        let two_p = ops.point_double(p); // 2P
        for i in 1..half_table_size {
            table.push(ops.point_add(table[i - 1], two_p));
        }
    }
    table
}

/// Selects T\[d\] from a point table using bit witnesses, where `d = Σ
/// bits\[i\] * 2^i`, via binary tree of point selects.
///
/// When `constrain_bits` is true, each bit is boolean-constrained. When
/// false, bits are assumed already constrained.
fn table_lookup<E: EcOps>(
    ops: &mut MultiLimbOps<'_, '_, E::Field, E, EcFieldParams>,
    table: &[EcPoint],
    bits: &[usize],
    constrain_bits: bool,
) -> EcPoint {
    assert_eq!(table.len(), 1 << bits.len());
    let mut current: Vec<EcPoint> = table.to_vec();
    // Process bits from MSB to LSB
    for &bit in bits.iter().rev() {
        if constrain_bits {
            ops.constrain_flag(bit);
        }
        let half = current.len() / 2;
        let mut next = Vec::with_capacity(half);
        for i in 0..half {
            next.push(ops.point_select_unchecked(bit, current[i], current[i + half]));
        }
        current = next;
    }
    current[0]
}

/// Signed-digit table lookup: selects from a table of odd multiples,
/// conditionally negating y based on the sign bit.
///
/// `sign_bit` must be boolean-constrained by the caller.
fn signed_table_lookup<E: EcOps>(
    ops: &mut MultiLimbOps<'_, '_, E::Field, E, EcFieldParams>,
    table: &[EcPoint],
    index_bits: &[usize],
    sign_bit: usize,
) -> EcPoint {
    let pt = if index_bits.is_empty() {
        // w=1: single entry, no lookup needed
        assert_eq!(table.len(), 1);
        table[0]
    } else {
        // Compute XOR'd index bits: idx_i = 1 - b_i - MSB + 2*b_i*MSB
        let one_w = ops.witness_one();
        let two = FieldElement::from(2u64);
        let xor_bits: Vec<usize> = index_bits
            .iter()
            .map(|&bit| {
                let prod = ops.product(bit, sign_bit);
                ops.sum(vec![
                    SumTerm(Some(FieldElement::ONE), one_w),
                    SumTerm(Some(-FieldElement::ONE), bit),
                    SumTerm(Some(-FieldElement::ONE), sign_bit),
                    SumTerm(Some(two), prod),
                ])
            })
            .collect();

        // XOR'd bits are boolean by construction, skip redundant constraints
        table_lookup(ops, table, &xor_bits, false)
    };

    let neg_y = ops.negate(pt.y);
    let eff_y = ops.select_unchecked(sign_bit, neg_y, pt.y);

    EcPoint { x: pt.x, y: eff_y }
}

/// Per-point data for merged multi-point GLV scalar multiplication.
pub(in crate::msm) struct MergedGlvPoint {
    /// Point P (effective, post-negation)
    pub p:       EcPoint,
    /// Signed-bit decomposition of |s1| (half-scalar for P), LSB first
    pub s1_bits: Vec<usize>,
    /// Skew correction witness for s1 branch (boolean)
    pub s1_skew: usize,
    /// Point R (effective, post-negation)
    pub r:       EcPoint,
    /// Signed-bit decomposition of |s2| (half-scalar for R), LSB first
    pub s2_bits: Vec<usize>,
    /// Skew correction witness for s2 branch (boolean)
    pub s2_skew: usize,
}

/// Merged multi-point GLV scalar multiplication with shared doublings
/// and signed-digit windows.
pub(in crate::msm) fn scalar_mul_merged_glv<E: EcOps>(
    ops: &mut MultiLimbOps<'_, '_, E::Field, E, EcFieldParams>,
    points: &[MergedGlvPoint],
    window_size: usize,
    offset: EcPoint,
) -> EcPoint {
    assert!(!points.is_empty());
    let n = points[0].s1_bits.len();
    let w = window_size;
    let half_table_size = 1usize << (w - 1);

    // Build signed point tables (odd multiples) for all points upfront
    let tables: Vec<(Vec<EcPoint>, Vec<EcPoint>)> = points
        .iter()
        .map(|pt| {
            let tp = build_signed_point_table(ops, pt.p, half_table_size);
            let tr = build_signed_point_table(ops, pt.r, half_table_size);
            (tp, tr)
        })
        .collect();

    let num_windows = (n + w - 1) / w;
    let mut acc = offset;

    // Process all windows from MSB down to LSB
    for i in (0..num_windows).rev() {
        let bit_start = i * w;
        let bit_end = std::cmp::min(bit_start + w, n);
        let actual_w = bit_end - bit_start;

        // w shared doublings on the accumulator (shared across ALL points)
        let mut doubled_acc = acc;
        for _ in 0..w {
            doubled_acc = ops.point_double(doubled_acc);
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
            cur = ops.point_add(cur, looked_up_p);

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
            cur = ops.point_add(cur, looked_up_r);
        }

        acc = cur;
    }

    // Skew corrections
    for pt in points {
        // P branch skew
        let neg_py = ops.negate(pt.p.y);
        let sub_p = ops.point_add(acc, EcPoint {
            x: pt.p.x,
            y: neg_py,
        });
        acc = ops.point_select_unchecked(pt.s1_skew, acc, sub_p);

        // R branch skew
        let neg_ry = ops.negate(pt.r.y);
        let sub_r = ops.point_add(acc, EcPoint {
            x: pt.r.x,
            y: neg_ry,
        });
        acc = ops.point_select_unchecked(pt.s2_skew, acc, sub_r);
    }

    acc
}
