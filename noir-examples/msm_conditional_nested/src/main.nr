use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

// Grumpkin generator point
global GEN: EmbeddedCurvePoint = EmbeddedCurvePoint {
    x: 1,
    y: 17631683881184975370165255887551781615748388533673675138860,
    is_infinite: false,
};

/// Exercises MSM with a compound predicate (outer AND inner).
///
/// When both `outer` and `inner` are true, the MSM runs and the result
/// must be non-infinite. When either is false, the MSM is in an inactive
/// branch and the circuit is still satisfiable (no assertion fires).
///
/// This exercises provekit's conditional MSM support with a Witness
/// predicate that is the product of two boolean witnesses.
fn main(outer: bool, inner: bool, scalar_lo: Field, scalar_hi: Field) {
    if outer {
        if inner {
            // predicate = outer * inner -- tests compound/nested predicate
            let s = EmbeddedCurveScalar { lo: scalar_lo, hi: scalar_hi };
            let r = multi_scalar_mul([GEN], [s]);
            assert(!r.is_infinite);
        }
    }
}
