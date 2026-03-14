//! Elliptic curve point operations for MSM.
//!
//! EC operations are dispatched via the [`EcOps`] trait, with two
//! implementations selected at the MSM entry point based on whether
//! the curve's base field matches the prover's native field:
//!
//! - [`NativeEcOps`] (num_limbs=1, native field): raw R1CS constraints
//! - [`NonNativeEcOps`] (num_limbs≥2): schoolbook column equations
//!
//! Submodules:
//! - `hints_native` — native-field hint-verified EC ops
//! - `hints_non_native` — non-native hint-verified EC ops (schoolbook)
//! - `tables` — point table construction, lookup, and merged GLV loop

mod hints_native;
mod hints_non_native;
mod tables;

pub(super) use tables::{scalar_mul_merged_glv, MergedGlvPoint};
use {
    super::{multi_limb_ops::MultiLimbParams, Limbs},
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    std::collections::BTreeMap,
};

// ---------------------------------------------------------------------------
// EcOps trait — strategy interface for EC point arithmetic
// ---------------------------------------------------------------------------

/// Strategy for constraining elliptic curve operations in the circuit.
///
/// Implementations provide hint-verified point arithmetic tailored to
/// how coordinates are represented (single native field element vs.
/// multi-limb). The strategy is selected once at the MSM entry point
/// and flows through the entire pipeline via monomorphization.
pub trait EcOps {
    /// Point doubling: computes 2P.
    fn point_double(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x: Limbs,
        y: Limbs,
    ) -> (Limbs, Limbs);

    /// Point addition: computes P1 + P2 (requires P1 ≠ ±P2).
    fn point_add(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x1: Limbs,
        y1: Limbs,
        x2: Limbs,
        y2: Limbs,
    ) -> (Limbs, Limbs);

    /// On-curve verification: constrains y² = x³ + ax + b.
    fn verify_on_curve(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x: Limbs,
        y: Limbs,
    );
}

// ---------------------------------------------------------------------------
// NativeEcOps — hint-verified via raw R1CS (num_limbs=1)
// ---------------------------------------------------------------------------

/// Native-field EC operations: each coordinate is a single field element.
///
/// Uses prover hints verified via direct R1CS constraints, avoiding
/// expensive field inversions. Cost: 4W+4C double, 3W+3C add, 2W+3C
/// on-curve.
pub(crate) struct NativeEcOps;

impl EcOps for NativeEcOps {
    fn point_double(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x: Limbs,
        y: Limbs,
    ) -> (Limbs, Limbs) {
        let (x3, y3) = hints_native::point_double_verified_native(compiler, x[0], y[0], params);
        (Limbs::single(x3), Limbs::single(y3))
    }

    fn point_add(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x1: Limbs,
        y1: Limbs,
        x2: Limbs,
        y2: Limbs,
    ) -> (Limbs, Limbs) {
        let (x3, y3) =
            hints_native::point_add_verified_native(compiler, x1[0], y1[0], x2[0], y2[0], params);
        (Limbs::single(x3), Limbs::single(y3))
    }

    fn verify_on_curve(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x: Limbs,
        y: Limbs,
    ) {
        hints_native::verify_on_curve_native(compiler, x[0], y[0], params);
    }
}

// ---------------------------------------------------------------------------
// NonNativeEcOps — hint-verified via schoolbook column equations (num_limbs≥2)
// ---------------------------------------------------------------------------

/// Non-native EC operations: coordinates are split into multiple limbs.
///
/// Uses prover hints verified via schoolbook column equations with
/// unsigned-offset carry chains. Cost scales with N² (limb count).
pub(crate) struct NonNativeEcOps;

impl EcOps for NonNativeEcOps {
    fn point_double(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x: Limbs,
        y: Limbs,
    ) -> (Limbs, Limbs) {
        hints_non_native::point_double_verified_non_native(compiler, range_checks, x, y, params)
    }

    fn point_add(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x1: Limbs,
        y1: Limbs,
        x2: Limbs,
        y2: Limbs,
    ) -> (Limbs, Limbs) {
        hints_non_native::point_add_verified_non_native(
            compiler,
            range_checks,
            x1,
            y1,
            x2,
            y2,
            params,
        )
    }

    fn verify_on_curve(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &MultiLimbParams,
        x: Limbs,
        y: Limbs,
    ) {
        hints_non_native::verify_on_curve_non_native(compiler, range_checks, x, y, params);
    }
}
