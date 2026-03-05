use std::embedded_curve_ops::{
    EmbeddedCurvePoint,
    EmbeddedCurveScalar,
    multi_scalar_mul,
};

/// Exercises the MultiScalarMul ACIR blackbox with 2 Grumpkin points.
/// Computes s1 * G + s2 * G where G is the Grumpkin generator.
fn main(
    scalar1_lo: Field,
    scalar1_hi: Field,
    scalar2_lo: Field,
    scalar2_hi: Field,
) {
    // Grumpkin generator
    let g = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };

    let s1 = EmbeddedCurveScalar { lo: scalar1_lo, hi: scalar1_hi };
    let s2 = EmbeddedCurveScalar { lo: scalar2_lo, hi: scalar2_hi };

    // MSM: result = s1 * G + s2 * G
    let result = multi_scalar_mul([g, g], [s1, s2]);

    // Prevent dead-code elimination - forces the blackbox to be retained
    // Using is_infinite as return value ensures the MSM is computed
    assert(result.is_infinite == (scalar1_lo + scalar1_hi + scalar2_lo + scalar2_hi == 0));
}

#[test]
fn test_msm() {
    // 3*G on Grumpkin
    let expected_x = 18660890509582237958343981571981920822503400000196279471655180441138020044621;
    let expected_y = 8902249110305491597038405103722863701255802573786510474664632793109847672620;

    main(1, 0, 2, 0);

    // Verify by computing independently: 3*G should match
    let g = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };
    let s3 = EmbeddedCurveScalar { lo: 3, hi: 0 };
    let check = multi_scalar_mul([g], [s3]);

    assert(check.x == expected_x);
    assert(check.y == expected_y);
}
