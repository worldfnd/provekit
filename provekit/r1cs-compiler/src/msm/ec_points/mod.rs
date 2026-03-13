//! Elliptic curve point operations for MSM.
//!
//! Submodules:
//! - `generic` — generic EC ops via `MultiLimbOps` abstraction
//! - `tables` — point table construction, lookup, and merged GLV loop
//! - `hints_native` — native-field hint-verified EC ops
//! - `hints_non_native` — non-native hint-verified EC ops (schoolbook)

mod generic;
mod hints_native;
mod hints_non_native;
mod tables;

// Re-exports
use super::{multi_limb_ops::MultiLimbOps, Limbs};
pub use {
    generic::{point_add, point_double, point_select_unchecked},
    hints_native::{
        point_add_verified_native, point_double_verified_native, verify_on_curve_native,
    },
    hints_non_native::{
        point_add_verified_non_native, point_double_verified_non_native, verify_on_curve_non_native,
    },
    tables::{scalar_mul_merged_glv, MergedGlvPoint},
};

/// Dispatching point doubling: uses hint-verified for multi-limb non-native,
/// generic field-ops otherwise.
pub fn point_double_dispatch(ops: &mut MultiLimbOps, x1: Limbs, y1: Limbs) -> (Limbs, Limbs) {
    if ops.params.num_limbs >= 2 && !ops.params.is_native {
        point_double_verified_non_native(ops.compiler, ops.range_checks, x1, y1, ops.params)
    } else {
        point_double(ops, x1, y1)
    }
}

/// Dispatching point addition: uses hint-verified for multi-limb non-native,
/// generic field-ops otherwise.
pub fn point_add_dispatch(
    ops: &mut MultiLimbOps,
    x1: Limbs,
    y1: Limbs,
    x2: Limbs,
    y2: Limbs,
) -> (Limbs, Limbs) {
    if ops.params.num_limbs >= 2 && !ops.params.is_native {
        point_add_verified_non_native(ops.compiler, ops.range_checks, x1, y1, x2, y2, ops.params)
    } else {
        point_add(ops, x1, y1, x2, y2)
    }
}
