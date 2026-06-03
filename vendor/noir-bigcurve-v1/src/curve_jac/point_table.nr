use crate::bigcurve::BigCurve;
use crate::curve_jac::types::{CurveJ, JTranscript};
use dep::bignum::BigNum;

/// A lookup table used for scalar multiplications using windowed non-adjacent form (WNAF).
///
/// The scalar multiplier is sliced into 4-bit chunks, each represented in WNAF (values in the range [-15, -13, ..., 15]).
/// A table `T` is computed containing point multiples corresponding to these 4-bit WNAF values: `T = ([-15[P], -13[P], ..., 15[P]])`.
///
/// The accumulator is initialized with `T[most significant WNAF slice]`.
/// For each remaining slice (starting from the most significant), the accumulator is doubled 4 times,
/// then `T[slice[i]]` is added to the accumulator.
///
/// For small multiscalar multiplications (fewer than 512 points), this approach minimizes the number of addition operations.
pub struct PointTable<B> {
    x: [B; 16],
    y: [B; 16],
    z: [B; 16],
    pub(crate) transcript: [JTranscript<B>; 8],
}

impl<B> PointTable<B>
where
    B: BigNum,
{
    pub(crate) fn empty() -> Self {
        PointTable {
            x: [B::zero(); 16],
            y: [B::zero(); 16],
            z: [B::zero(); 16],
            transcript: [unsafe { JTranscript::new() }; 8],
        }
    }
    /**
     * @brief make a new PointTable from an input point
     * @description we use "windowed non-adjacent form" representation 
     * to reduce the number of group operations required for the table
     * [-15P, -13P, ..., 15P] requires 8 group operations
     * [0, P, ..., 15P] requires 14 group operations.
     * group operations are expensive!
     **/
    pub(crate) unconstrained fn new<Curve>(P: CurveJ<B, Curve>) -> Self
    where
        Curve: BigCurve<B>,
    {
        let mut result = PointTable {
            x: [B::zero(); 16],
            y: [B::zero(); 16],
            z: [B::zero(); 16],
            transcript: [JTranscript::new(); 8],
        };
        let op = P.dbl();
        let D2 = op.0;

        result.transcript[0] = op.1;
        result.x[7] = P.x;
        result.y[7] = P.y.__neg();
        result.z[7] = P.z;
        result.x[8] = P.x;
        result.y[8] = P.y;
        result.z[8] = P.z;
        let mut A = P;
        for i in 1..8 {
            let op = D2.incomplete_add(A);
            A = op.0;
            result.transcript[i] = op.1;
            result.x[8 + i] = A.x;
            result.y[8 + i] = A.y;
            result.z[8 + i] = A.z;
            result.x[7 - i] = A.x;
            result.y[7 - i] = A.y.__neg();
            result.z[7 - i] = A.z;
        }

        result
    }

    /**
     * @brief get a value out of the lookup table
     **/
    pub(crate) unconstrained fn get<Curve>(self, idx: u32) -> CurveJ<B, Curve> {
        CurveJ { x: self.x[idx], y: self.y[idx], z: self.z[idx], is_infinity: false }
    }
}
