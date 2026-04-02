//! Elliptic curve point operations for MSM, dispatched via [`EcOps`].

mod hints_native;
mod hints_non_native;
mod tables;

pub(super) use tables::{scalar_mul_merged_glv, MergedGlvPoint};
use {
    super::{
        multi_limb_ops::{EcFieldParams, FieldArith, MultiLimbField, NativeSingleField},
        EcPoint, Limbs,
    },
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    std::collections::BTreeMap,
};

// ---------------------------------------------------------------------------
// EcOps trait — strategy interface for EC point arithmetic
// ---------------------------------------------------------------------------

/// Strategy for constraining elliptic curve operations in the circuit.
///
/// Each impl specifies its associated `Field: FieldArith` type, so
/// `MultiLimbOps<E::Field, E, EcFieldParams>` gets both field and EC ops
/// without EC types needing to re-implement field arithmetic.
pub trait EcOps {
    /// The field arithmetic strategy paired with this EC strategy.
    type Field: FieldArith;

    /// Point doubling: computes 2P.
    fn point_double(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p: EcPoint,
    ) -> EcPoint;

    /// Point addition: computes P1 + P2 (requires P1 ≠ ±P2).
    fn point_add(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p1: EcPoint,
        p2: EcPoint,
    ) -> EcPoint;

    /// On-curve verification: constrains y² = x³ + ax + b.
    fn verify_on_curve(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p: EcPoint,
    );
}

// ---------------------------------------------------------------------------
// NativeEcOps — hint-verified via raw R1CS (num_limbs=1)
// ---------------------------------------------------------------------------

/// Native-field EC operations via hint-verified R1CS constraints.
pub(crate) struct NativeEcOps;

impl EcOps for NativeEcOps {
    type Field = NativeSingleField;

    fn point_double(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p: EcPoint,
    ) -> EcPoint {
        let (x3, y3) = hints_native::point_double_verified_native(compiler, p.x[0], p.y[0], params);
        EcPoint {
            x: Limbs::single(x3),
            y: Limbs::single(y3),
        }
    }

    fn point_add(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p1: EcPoint,
        p2: EcPoint,
    ) -> EcPoint {
        let (x3, y3) = hints_native::point_add_verified_native(
            compiler, p1.x[0], p1.y[0], p2.x[0], p2.y[0], params,
        );
        EcPoint {
            x: Limbs::single(x3),
            y: Limbs::single(y3),
        }
    }

    fn verify_on_curve(
        compiler: &mut NoirToR1CSCompiler,
        _range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p: EcPoint,
    ) {
        hints_native::verify_on_curve_native(compiler, p.x[0], p.y[0], params);
    }
}

// ---------------------------------------------------------------------------
// NonNativeEcOps — hint-verified via schoolbook column equations (num_limbs≥2)
// ---------------------------------------------------------------------------

/// Non-native EC operations via hint-verified schoolbook column equations.
pub(crate) struct NonNativeEcOps;

impl EcOps for NonNativeEcOps {
    type Field = MultiLimbField;

    fn point_double(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p: EcPoint,
    ) -> EcPoint {
        let (x3, y3) = hints_non_native::point_double_verified_non_native(
            compiler,
            range_checks,
            p.x,
            p.y,
            params,
        );
        EcPoint { x: x3, y: y3 }
    }

    fn point_add(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p1: EcPoint,
        p2: EcPoint,
    ) -> EcPoint {
        let (x3, y3) = hints_non_native::point_add_verified_non_native(
            compiler,
            range_checks,
            p1.x,
            p1.y,
            p2.x,
            p2.y,
            params,
        );
        EcPoint { x: x3, y: y3 }
    }

    fn verify_on_curve(
        compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        params: &EcFieldParams,
        p: EcPoint,
    ) {
        hints_non_native::verify_on_curve_non_native(compiler, range_checks, p.x, p.y, params);
    }
}
