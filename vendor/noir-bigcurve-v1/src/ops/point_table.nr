use crate::bigcurve::BigCurve;
use crate::curve_jac::types::AffineTranscript;
use crate::ops::affine::{double_with_hint, incomplete_add_with_hint};
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

pub(crate) struct PointTable<B> {
    x: [B; 16],
    y: [B; 16],
}

impl<B: BigNum> PointTable<B> {
    pub(crate) fn empty() -> Self {
        PointTable { x: [B::zero(); 16], y: [B::zero(); 16] }
    }

    /// Constructs a `PointTable` from an input point and an `AffineTranscript` containing the required modular inverses.
    ///
    /// # Arguments
    ///
    /// * `point` - The input point to be used for constructing the table.
    /// * `transcript` - An `AffineTranscript` object that holds the necessary modular inverses.
    ///
    /// # Details
    ///
    /// See [`CurveJ::mul`] for an example of how `AffineTranscript` objects are generated and used.
    pub(crate) fn new_with_hint<P: BigCurve<B>>(
        point: P,
        transcript: [AffineTranscript<B>; 8],
    ) -> Self {
        let mut result = PointTable { x: [B::zero(); 16], y: [B::zero(); 16] };

        let D2: P = double_with_hint::<B, P>(point, transcript[0]);

        result.x[8] = point.x();
        result.y[8] = point.y();
        result.x[7] = point.x();
        result.y[7] = point.y().neg();

        let mut A = point;
        for i in 1..8 {
            A = incomplete_add_with_hint::<B, P>(A, D2, transcript[i]);
            result.x[8 + i] = A.x();
            result.y[8 + i] = A.y();
            result.x[7 - i] = A.x();
            result.y[7 - i] = A.y().neg();
        }
        result
    }

    /// Retrieves a value from the lookup table.
    ///
    /// If the backend supports efficient memory lookups, this operation can be highly efficient.
    /// For example, using the barretenberg backend, lookups on 256-bit curves may require only
    /// around 12 constraints.
    pub(crate) fn get<P: BigCurve<B>>(self, idx: u32) -> P {
        P::from_coordinates(self.x[idx], self.y[idx], false)
    }
}
