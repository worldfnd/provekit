use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

// Grumpkin generator point
global GEN: EmbeddedCurvePoint = EmbeddedCurvePoint {
    x: 1,
    y: 17631683881184975370165255887551781615748388533673675138860,
    is_infinite: false,
};

/// Exercises MultiScalarMul with a Witness predicate.
///
/// When `condition = true`, the MSM runs and the result must be non-infinite.
/// When `condition = false`, the MSM is in an inactive branch (predicate=0 in
/// ACIR), and ACVM outputs the identity point (0, 0, true). This exercises
/// provekit's conditional MSM support.
fn main(condition: bool, scalar_lo: Field, scalar_hi: Field, expected_infinite: bool) {
    let scalar = EmbeddedCurveScalar { lo: scalar_lo, hi: scalar_hi };

    // The if/else forces ACIR to emit MultiScalarMul with a Witness predicate.
    let result: EmbeddedCurvePoint = if condition {
        multi_scalar_mul([GEN], [scalar])
    } else {
        // When predicate=0, ACVM assigns identity (0, 0, true) to result.
        EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true }
    };

    assert_eq(result.is_infinite, expected_infinite);
}
