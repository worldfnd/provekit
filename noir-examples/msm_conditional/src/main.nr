use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

// Grumpkin generator point
global GEN: EmbeddedCurvePoint = EmbeddedCurvePoint {
    x: 1,
    y: 17631683881184975370165255887551781615748388533673675138860,
    is_infinite: false,
};

/// Exercises MultiScalarMul with a Witness predicate.
///
/// When `condition = true`, the MSM runs and `result` must equal the expected point.
/// When `condition = false`, the MSM is in an inactive branch (predicate=0 in
/// ACIR), and ACVM outputs the identity point (0, 0, true). This exercises
/// provekit's conditional MSM support.
fn main(condition: bool, scalar_lo: Field, scalar_hi: Field, expected_x: Field, expected_y: Field) {
    let scalar = EmbeddedCurveScalar { lo: scalar_lo, hi: scalar_hi };

    // The if/else forces ACIR to emit MultiScalarMul with a Witness predicate.
    let result: EmbeddedCurvePoint = if condition {
        multi_scalar_mul([GEN], [scalar])
    } else {
        // When predicate=0, ACVM assigns identity (0, 0, true) to result.
        EmbeddedCurvePoint { x: 0, y: 0, is_infinite: true }
    };

    if condition {
        assert(!result.is_infinite);
        assert_eq(result.x, expected_x);
        assert_eq(result.y, expected_y);
    } else {
        assert(result.x == 0);
        assert(result.y == 0);
        assert(result.is_infinite);
    }
}
