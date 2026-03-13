pub mod cost_model;
pub mod curve;
pub(crate) mod ec_points;
mod limbs;
pub(crate) mod multi_limb_arith;
pub(crate) mod multi_limb_ops;
mod native;
mod non_native;
mod sanitize;
mod scalar_relation;
#[cfg(test)]
mod tests;

pub use limbs::{Limbs, MAX_LIMBS};
use {
    crate::{
        constraint_helpers::{add_constant_witness, constrain_boolean},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field, PrimeField},
    curve::CurveParams,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

// ---------------------------------------------------------------------------
// MSM entry point
// ---------------------------------------------------------------------------

/// Processes all deferred MSM operations.
///
/// Internally selects the optimal (limb_bits, window_size) via cost model
/// and uses Grumpkin curve parameters.
///
/// Each entry is `(points, scalars, (out_x, out_y, out_inf))` where:
/// - `points` has layout `[x1, y1, inf1, x2, y2, inf2, ...]` (3 per point)
/// - `scalars` has layout `[s1_lo, s1_hi, s2_lo, s2_hi, ...]` (2 per scalar)
/// - outputs are the R1CS witness indices for the result point
/// Grumpkin-specific MSM entry point (used by the Noir `MultiScalarMul` black
/// box).
pub fn add_msm(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        (usize, usize, usize),
    )>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
) {
    let curve = curve::grumpkin_params();
    add_msm_with_curve(compiler, msm_ops, range_checks, &curve);
}

/// Curve-agnostic MSM: compiles MSM operations for any curve described by
/// `curve`.
pub fn add_msm_with_curve(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        (usize, usize, usize),
    )>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    if msm_ops.is_empty() {
        return;
    }

    let native_bits = provekit_common::FieldElement::MODULUS_BIT_SIZE;
    let curve_bits = curve.modulus_bits();
    let is_native = curve.is_native_field();
    let n_points: usize = msm_ops.iter().map(|(pts, ..)| pts.len() / 3).sum();
    let (limb_bits, window_size) =
        cost_model::get_optimal_msm_params(native_bits, curve_bits, n_points, 256, is_native);

    for (points, scalars, outputs) in msm_ops {
        add_single_msm(
            compiler,
            &points,
            &scalars,
            outputs,
            limb_bits,
            window_size,
            range_checks,
            curve,
        );
    }
}

/// Processes a single MSM operation.
fn add_single_msm(
    compiler: &mut NoirToR1CSCompiler,
    points: &[ConstantOrR1CSWitness],
    scalars: &[ConstantOrR1CSWitness],
    outputs: (usize, usize, usize),
    limb_bits: u32,
    window_size: usize,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
) {
    assert!(
        points.len() % 3 == 0,
        "points length must be a multiple of 3"
    );
    let n = points.len() / 3;
    assert_eq!(
        scalars.len(),
        2 * n,
        "scalars length must be 2x the number of points"
    );

    // Resolve all inputs to witness indices
    let point_wits: Vec<usize> = points.iter().map(|p| resolve_input(compiler, p)).collect();
    let scalar_wits: Vec<usize> = scalars.iter().map(|s| resolve_input(compiler, s)).collect();

    let is_native = curve.is_native_field();
    let num_limbs = if is_native {
        1
    } else {
        (curve.modulus_bits() as usize + limb_bits as usize - 1) / limb_bits as usize
    };

    let n_points = point_wits.len() / 3;
    if curve.is_native_field() {
        native::process_multi_point_native(
            compiler,
            &point_wits,
            &scalar_wits,
            outputs,
            n_points,
            range_checks,
            curve,
        );
    } else {
        non_native::process_multi_point_non_native(
            compiler,
            &point_wits,
            &scalar_wits,
            outputs,
            n_points,
            num_limbs,
            limb_bits,
            window_size,
            range_checks,
            curve,
        );
    }
}

/// Resolves a `ConstantOrR1CSWitness` to a witness index.
fn resolve_input(compiler: &mut NoirToR1CSCompiler, input: &ConstantOrR1CSWitness) -> usize {
    match input {
        ConstantOrR1CSWitness::Witness(idx) => *idx,
        ConstantOrR1CSWitness::Constant(value) => {
            let w = compiler.num_witnesses();
            compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(w, *value)));
            w
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-limb MSM interface (for non-native curves with coords > BN254_Fr)
// ---------------------------------------------------------------------------

/// MSM outputs when coordinates are in multi-limb form.
pub struct MsmLimbedOutputs {
    pub out_x_limbs: Vec<usize>,
    pub out_y_limbs: Vec<usize>,
    pub out_inf:     usize,
}

/// Multi-limb MSM entry point for non-native curves.
///
/// Point coordinates are provided as limbs, avoiding truncation when
/// values exceed BN254_Fr. Each point uses stride `2*num_limbs + 1`:
/// `[px_l0..px_lN-1, py_l0..py_lN-1, inf]`.
///
/// Scalars remain as `[s_lo, s_hi]` pairs (128-bit halves fit in BN254_Fr).
/// Outputs are per-limb: `MsmLimbedOutputs` with N limbs for each coordinate.
pub fn add_msm_with_curve_limbed(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        MsmLimbedOutputs,
    )>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &CurveParams,
    num_limbs: usize,
) {
    assert!(
        !curve.is_native_field(),
        "limbed MSM is only for non-native curves"
    );
    if msm_ops.is_empty() {
        return;
    }

    let native_bits = provekit_common::FieldElement::MODULUS_BIT_SIZE;
    let curve_bits = curve.modulus_bits();
    let stride = 2 * num_limbs + 1;
    let n_points: usize = msm_ops.iter().map(|(pts, ..)| pts.len() / stride).sum();
    let (limb_bits, window_size) =
        cost_model::get_optimal_msm_params(native_bits, curve_bits, n_points, 256, false);

    // Verify num_limbs matches what cost model produces
    let expected_num_limbs = (curve_bits as usize + limb_bits as usize - 1) / limb_bits as usize;
    assert_eq!(
        num_limbs, expected_num_limbs,
        "num_limbs mismatch: caller passed {num_limbs}, cost model expects {expected_num_limbs}"
    );

    for (points, scalars, outputs) in msm_ops {
        assert!(
            points.len() % stride == 0,
            "points length must be a multiple of {stride} (2*{num_limbs}+1)"
        );
        let n = points.len() / stride;
        assert_eq!(scalars.len(), 2 * n, "scalars length must be 2x n_points");
        assert_eq!(outputs.out_x_limbs.len(), num_limbs);
        assert_eq!(outputs.out_y_limbs.len(), num_limbs);

        let point_wits: Vec<usize> = points.iter().map(|p| resolve_input(compiler, p)).collect();
        let scalar_wits: Vec<usize> = scalars.iter().map(|s| resolve_input(compiler, s)).collect();

        non_native::process_multi_point_non_native_limbed(
            compiler,
            &point_wits,
            &scalar_wits,
            &outputs,
            n,
            num_limbs,
            limb_bits,
            window_size,
            range_checks,
            curve,
        );
    }
}

// ---------------------------------------------------------------------------
// Signed-bit decomposition (shared by native and non-native paths)
// ---------------------------------------------------------------------------

/// Signed-bit decomposition for wNAF scalar multiplication.
///
/// Decomposes `scalar` into `num_bits` sign-bits b_i ∈ {0,1} and a skew ∈ {0,1}
/// such that the signed digits d_i = 2*b_i - 1 ∈ {-1, +1} satisfy:
///   scalar = Σ d_i * 2^i - skew
///
/// Reconstruction constraint (1 linear R1CS):
///   scalar + skew + (2^n - 1) = Σ b_i * 2^{i+1}
///
/// All bits and skew are boolean-constrained.
///
/// # Limitation
/// The prover's `SignedBitHint` solver reads the scalar as a `u128` (lower
/// 128 bits of the field element). This is correct for FakeGLV half-scalars
/// (≤128 bits for 256-bit curves) but would silently truncate if `num_bits`
/// exceeds 128. The R1CS reconstruction constraint would then fail.
pub(crate) fn decompose_signed_bits(
    compiler: &mut NoirToR1CSCompiler,
    scalar: usize,
    num_bits: usize,
) -> (Vec<usize>, usize) {
    let start = compiler.num_witnesses();
    compiler.add_witness_builder(WitnessBuilder::SignedBitHint {
        output_start: start,
        scalar,
        num_bits,
    });
    let bits: Vec<usize> = (start..start + num_bits).collect();
    let skew = start + num_bits;

    // Boolean-constrain each bit and skew
    for &b in &bits {
        constrain_boolean(compiler, b);
    }
    constrain_boolean(compiler, skew);

    // Reconstruction: scalar + skew + (2^n - 1) = Σ b_i * 2^{i+1}
    // Rearranged as: scalar + skew + (2^n - 1) - Σ b_i * 2^{i+1} = 0
    let one = compiler.witness_one();
    let two = FieldElement::from(2u64);
    let constant = two.pow([num_bits as u64]) - FieldElement::ONE;
    let mut b_terms: Vec<(FieldElement, usize)> = bits
        .iter()
        .enumerate()
        .map(|(i, &b)| (-two.pow([(i + 1) as u64]), b))
        .collect();
    b_terms.push((FieldElement::ONE, scalar));
    b_terms.push((FieldElement::ONE, skew));
    b_terms.push((constant, one));
    compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, one)], &b_terms, &[(
            FieldElement::ZERO,
            one,
        )]);

    (bits, skew)
}
