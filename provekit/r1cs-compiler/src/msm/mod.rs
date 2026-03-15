pub mod cost_model;
pub mod curve;
pub(crate) mod ec_points;
mod limbs;
pub(crate) mod multi_limb_arith;
pub(crate) mod multi_limb_ops;
mod pipeline;
mod sanitize;
mod scalar_relation;
#[cfg(test)]
mod tests;

pub use limbs::{EcPoint, Limbs, MAX_LIMBS};
use {
    crate::{
        constraint_helpers::{add_constant_witness, constrain_boolean},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field, PrimeField},
    curve::Curve,
    ec_points::{NativeEcOps, NonNativeEcOps},
    provekit_common::{
        witness::{ConstantOrR1CSWitness, WitnessBuilder},
        FieldElement,
    },
    std::collections::BTreeMap,
};

/// Scalar inputs are split into two 128-bit halves (s_lo, s_hi).
pub(crate) const SCALAR_HALF_BITS: usize = 128;

/// Integer ceiling of log2.
/// ceil_log2(1) = 0, ceil_log2(2) = 1, ceil_log2(3) = 2, ceil_log2(4) = 2.
pub(crate) fn ceil_log2(n: u64) -> u32 {
    assert!(n > 0, "ceil_log2(0) is undefined");
    u64::BITS - (n - 1).leading_zeros()
}

// ---------------------------------------------------------------------------
// MSM entry point
// ---------------------------------------------------------------------------

/// MSM outputs in multi-limb form.
pub struct MsmLimbedOutputs {
    pub out_x_limbs: Vec<usize>,
    pub out_y_limbs: Vec<usize>,
    pub out_inf:     usize,
}

/// MSM circuit configuration parameters.
pub(crate) struct MsmConfig {
    pub num_limbs:   usize,
    pub limb_bits:   u32,
    pub window_size: usize,
}

/// Compiles MSM operations for any curve implementing the `Curve` trait.
pub fn add_msm_with_curve<C: Curve>(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        MsmLimbedOutputs,
    )>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &C,
) {
    if msm_ops.is_empty() {
        return;
    }

    let native_bits = provekit_common::FieldElement::MODULUS_BIT_SIZE;
    let curve_bits = curve.modulus_bits();
    let is_native = curve.is_native_field();
    let scalar_bits = curve.curve_order_bits() as usize;

    // Use first op's output limbs to estimate n_points for cost model
    let first_num_limbs = msm_ops[0].2.out_x_limbs.len();
    let stride = 2 * first_num_limbs + 1;
    let n_points: usize = msm_ops.iter().map(|(pts, ..)| pts.len() / stride).sum();

    let (limb_bits, window_size, num_limbs) = cost_model::get_optimal_msm_params(
        native_bits,
        curve_bits,
        n_points,
        scalar_bits,
        is_native,
    );

    assert_eq!(
        first_num_limbs, num_limbs,
        "output limb count ({first_num_limbs}) doesn't match cost model num_limbs ({num_limbs})"
    );

    let config = MsmConfig {
        num_limbs,
        limb_bits,
        window_size,
    };

    // Dispatch once — the entire pipeline is monomorphized for the chosen strategy.
    if is_native {
        add_msm_inner::<C, NativeEcOps>(compiler, msm_ops, range_checks, curve, &config);
    } else {
        add_msm_inner::<C, NonNativeEcOps>(compiler, msm_ops, range_checks, curve, &config);
    }
}

/// Inner MSM loop, monomorphized for a specific EC strategy `E`.
fn add_msm_inner<C: Curve, E: ec_points::EcOps>(
    compiler: &mut NoirToR1CSCompiler,
    msm_ops: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        MsmLimbedOutputs,
    )>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    curve: &C,
    config: &MsmConfig,
) {
    let stride = 2 * config.num_limbs + 1;

    for (points, scalars, outputs) in msm_ops {
        assert!(
            points.len() % stride == 0,
            "points length must be a multiple of {stride} (2*{}+1)",
            config.num_limbs
        );
        let n = points.len() / stride;
        assert_eq!(scalars.len(), 2 * n, "scalars length must be 2x n_points");
        assert_eq!(outputs.out_x_limbs.len(), config.num_limbs);
        assert_eq!(outputs.out_y_limbs.len(), config.num_limbs);

        let point_wits: Vec<usize> = points.iter().map(|p| resolve_input(compiler, p)).collect();
        let scalar_wits: Vec<usize> = scalars.iter().map(|s| resolve_input(compiler, s)).collect();

        pipeline::process_multi_point::<E>(
            compiler,
            &point_wits,
            &scalar_wits,
            &outputs,
            n,
            config,
            range_checks,
            curve,
        );
    }
}

/// Resolves a `ConstantOrR1CSWitness` to a witness index.
#[must_use]
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
// Signed-bit decomposition (shared by native and non-native paths)
// ---------------------------------------------------------------------------

/// Signed-bit decomposition for wNAF scalar multiplication.
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
