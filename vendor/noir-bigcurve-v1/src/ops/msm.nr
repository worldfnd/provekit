use crate::bigcurve::BigCurve;
use crate::curve_jac::types::{AffineTranscript, CurveJ};
use crate::ops::affine::{
    conditional_incomplete_add_with_hint, conditional_incomplete_subtract_with_hint,
    double_with_hint, incomplete_add_with_hint, sub_with_hint,
};
use crate::ops::point_table::PointTable;
use crate::scalar_field::ScalarField;
use dep::bignum::BigNum;

/// Multiplies a point by a scalar field value, returning the resulting point.
pub fn msm<P: BigCurve<B>, B: BigNum, let NScalarSlices: u32, let NMuls: u32>(
    mul_points: [P; NMuls],
    mul_scalars: [ScalarField<NScalarSlices>; NMuls],
) -> P {
    let add_points: [P; 0] = [];
    P::evaluate_linear_expression(mul_points, mul_scalars, add_points)
}

// TODO: offset generators
//       conditional subtract, conditional add
//
/**
    * @brief Perform an ecc scalar multiplication, given an [AffineTranscript] generated via unconstrained functions
    **/
fn msm_with_hint_internal<let Size: u32, let NScalarSlices: u32, let NTranscriptSlices: u32, B: BigNum, P: BigCurve<B>>(
    mut points: [P; Size],
    mut scalars: [ScalarField<NScalarSlices>; Size],
    transcript: [AffineTranscript<B>; NTranscriptSlices],
) -> P {
    // Compute a 4-bit lookup table of multiples of P
    let mut _inputs: [P; Size] = [P::one(); Size];
    let mut _scalars: [ScalarField<NScalarSlices>; Size] = [ScalarField::zero(); Size];
    for i in 0..Size {
        let (input, scalar) = if points[i].is_infinity() {
            (P::one(), ScalarField::zero())
        } else {
            (points[i], scalars[i])
        };
        _inputs[i] = input;
        _scalars[i] = scalar;
    }
    points = _inputs;
    scalars = _scalars;

    let mut tables: [PointTable<B>; Size] = [PointTable::empty(); Size];
    for i in 0..Size {
        let mut table_transcript: [AffineTranscript<B>; 8] = [AffineTranscript::new(); 8];
        for j in 0..8 {
            table_transcript[j] = transcript[i * 8 + j];
        }
        tables[i] = PointTable::new_with_hint::<P>(points[i], table_transcript);
    }

    // Init the accumulator from the most significant scalar slice
    let mut accumulator: P = P::offset_generator();
    let mut accumulator = incomplete_add_with_hint::<B, P>(
        accumulator,
        tables[0].get::<P>(scalars[0].base4_slices[0] as u32),
        transcript[8 * Size],
    );

    for i in 1..Size {
        accumulator = incomplete_add_with_hint::<B, P>(
            accumulator,
            tables[i].get::<P>(scalars[i].base4_slices[0] as u32),
            transcript[8 * Size + i],
        );
    }

    // Perform the "double and add" algorithm but in steps of 4 bits, using the lookup table T to extract 4-bit multiples of P
    for i in 1..NScalarSlices {
        accumulator =
            double_with_hint::<B, P>(accumulator, transcript[9 * Size + (4 + Size) * (i - 1)]);
        accumulator =
            double_with_hint::<B, P>(accumulator, transcript[9 * Size + (4 + Size) * (i - 1) + 1]);
        accumulator =
            double_with_hint::<B, P>(accumulator, transcript[9 * Size + (4 + Size) * (i - 1) + 2]);
        accumulator =
            double_with_hint::<B, P>(accumulator, transcript[9 * Size + (4 + Size) * (i - 1) + 3]);

        for j in 0..Size {
            accumulator = incomplete_add_with_hint::<B, P>(
                accumulator,
                tables[j].get::<P>(scalars[j].base4_slices[i] as u32),
                transcript[9 * Size + (4 + Size) * (i - 1) + 4 + j],
            );
        }
    }

    // 9 * Size + (4 + Size) * (NScalarSlices - 1) - 1
    // 9 + 5 * NScalarSlices - 6
    // windowed non-adjacent form can only represent odd scalar values.
    // if value is even, the result will be off by one and we need to subtract the input point
    for i in 0..Size {
        accumulator = conditional_incomplete_subtract_with_hint::<B, P>(
            accumulator,
            points[i],
            scalars[i].skew,
            transcript[9 * Size + (4 + Size) * (NScalarSlices - 1) + i],
        );
    }

    accumulator
}

/// Performs an ECC scalar multiplication using an [AffineTranscript] generated via unconstrained functions.
///
/// # Arguments
///
/// * `transcript` - The affine transcript used for the operation.
/// * `scalar` - The scalar value to multiply with the elliptic curve point.
///
/// # Returns
///
/// The result of the scalar multiplication as an elliptic curve point.
///
/// # Note
///
/// This function assumes the transcript is generated using unconstrained functions.
pub fn mul_with_hint<let NScalarSlices: u32, let NTranscriptSlices: u32, B: BigNum, P: BigCurve<B>>(
    point: P,
    scalar: ScalarField<NScalarSlices>,
    transcript: [AffineTranscript<B>; NTranscriptSlices],
) -> P {
    // Compute a 4-bit lookup table of multiples of P
    let (input, scalar) = if point.is_infinity() {
        (P::one(), ScalarField::zero())
    } else {
        (point, scalar)
    };
    let T: PointTable<B> = PointTable::new_with_hint::<P>(
        input,
        [
            transcript[0],
            transcript[1],
            transcript[2],
            transcript[3],
            transcript[4],
            transcript[5],
            transcript[6],
            transcript[7],
        ],
    );

    // Init the accumulator from the most significant scalar slice
    let mut accumulator: P = P::offset_generator();
    let mut accumulator = incomplete_add_with_hint::<B, P>(
        accumulator,
        T.get::<P>(scalar.base4_slices[0] as u32),
        transcript[3 + 5],
    );

    // Perform the "double and add" algorithm but in steps of 4 bits, using the lookup table T to extract 4-bit multiples of P
    for i in 1..NScalarSlices {
        accumulator = double_with_hint::<B, P>(accumulator, transcript[4 + 5 * i]);
        accumulator = double_with_hint::<B, P>(accumulator, transcript[5 + 5 * i]);
        accumulator = double_with_hint::<B, P>(accumulator, transcript[6 + 5 * i]);
        accumulator = double_with_hint::<B, P>(accumulator, transcript[7 + 5 * i]);
        accumulator = incomplete_add_with_hint::<B, P>(
            accumulator,
            T.get::<P>(scalar.base4_slices[i] as u32),
            transcript[8 + 5 * i],
        );
    }

    // windowed non-adjacent form can only represent odd scalar values.
    // if value is even, the result will be off by one and we need to subtract the input point
    accumulator = conditional_incomplete_subtract_with_hint::<B, P>(
        accumulator,
        input,
        scalar.skew,
        transcript[4 + 5 * NScalarSlices],
    );

    accumulator = sub_with_hint::<B, P>(
        accumulator,
        P::offset_generator_final(),
        transcript[5 + 5 * NScalarSlices],
    );
    accumulator
}

fn msm_with_hint<let Size: u32, let NScalarSlices: u32, let NTranscriptSlices: u32, B: BigNum, P: BigCurve<B>>(
    mut points: [P; Size],
    mut scalars: [ScalarField<NScalarSlices>; Size],
    transcript: [AffineTranscript<B>; NTranscriptSlices],
) -> P {
    let mut accumulator = msm_with_hint_internal::<Size, NScalarSlices, NTranscriptSlices, B, P>(
        points,
        scalars,
        transcript,
    );
    accumulator = sub_with_hint::<B, P>(
        P::offset_generator_final(),
        accumulator,
        transcript[10 * Size + (4 + Size) * (NScalarSlices - 1)],
    );
    accumulator
}

pub unconstrained fn get_mul_transcript<let NScalarSlices: u32, B: BigNum, P: BigCurve<B>>(
    point: P,
    scalar: ScalarField<NScalarSlices>,
) -> [AffineTranscript<B>; 6 + NScalarSlices * 5] {
    let tmp: CurveJ<B, P> = CurveJ::from(point);
    let (_, transcript) = tmp.mul(scalar);
    transcript
}

pub fn evaluate_linear_expression<F: BigNum, Curve: BigCurve<F>, let NScalarSlices: u32, let NMuls: u32, let NAdds: u32>(
    mul_points: [Curve; NMuls],
    mul_scalars: [ScalarField<NScalarSlices>; NMuls],
    add_points: [Curve; NAdds],
) -> Curve {
    let transcript: [AffineTranscript<F>; NScalarSlices * NMuls + NScalarSlices * 4 + NMuls * 9 + NAdds - 3] = unsafe {
        CurveJ::<F, Curve>::compute_linear_expression_transcript(
            mul_points,
            mul_scalars,
            add_points,
        )
            .1
    };
    let mut _inputs: [Curve; NMuls] = [BigCurve::one(); NMuls];
    let mut _scalars: [ScalarField<NScalarSlices>; NMuls] = [ScalarField::zero(); NMuls];
    for i in 0..NMuls {
        let (input, scalar) = if mul_points[i].is_infinity() {
            (BigCurve::one(), ScalarField::zero())
        } else {
            (mul_points[i], mul_scalars[i])
        };
        _inputs[i] = input;
        _scalars[i] = scalar;
    }
    let msm_points = _inputs;
    let scalars = _scalars;

    let mut tables: [PointTable<F>; NMuls] = [PointTable::empty(); NMuls];
    for i in 0..NMuls {
        let mut table_transcript: [AffineTranscript<F>; 8] = [AffineTranscript::new(); 8];
        for j in 0..8 {
            table_transcript[j] = transcript[i * 8 + j];
        }
        tables[i] = PointTable::<F>::new_with_hint::<Curve>(msm_points[i], table_transcript);
    }

    // Init the accumulator from the most significant scalar slice
    let mut accumulator: Curve = BigCurve::offset_generator();
    let mut accumulator = incomplete_add_with_hint::<F, Curve>(
        accumulator,
        tables[0].get::<Curve>(scalars[0].base4_slices[0] as u32),
        transcript[8 * NMuls],
    );
    for i in 1..NMuls {
        accumulator = incomplete_add_with_hint::<F, Curve>(
            accumulator,
            tables[i].get::<Curve>(scalars[i].base4_slices[0] as u32),
            transcript[8 * NMuls + i],
        );
    }

    // Perform the "double and add" algorithm but in steps of 4 bits, using the lookup table T to extract 4-bit multiples of P
    for i in 1..NScalarSlices {
        accumulator = double_with_hint::<F, Curve>(
            accumulator,
            transcript[9 * NMuls + (4 + NMuls) * (i - 1)],
        );
        accumulator = double_with_hint::<F, Curve>(
            accumulator,
            transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 1],
        );
        accumulator = double_with_hint::<F, Curve>(
            accumulator,
            transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 2],
        );
        accumulator = double_with_hint::<F, Curve>(
            accumulator,
            transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 3],
        );
        for j in 0..NMuls {
            accumulator = incomplete_add_with_hint::<F, Curve>(
                accumulator,
                tables[j].get::<Curve>(scalars[j].base4_slices[i] as u32),
                transcript[9 * NMuls + (4 + NMuls) * (i - 1) + 4 + j],
            );
        }
    }

    // 9 * Size + (4 + Size) * (NScalarSlices - 1) - 1
    // 9 + 5 * NScalarSlices - 6
    // windowed non-adjacent form can only represent odd scalar values.
    // if value is even, the result will be off by one and we need to subtract the input point
    for i in 0..NMuls {
        accumulator = conditional_incomplete_subtract_with_hint::<F, Curve>(
            accumulator,
            msm_points[i],
            scalars[i].skew,
            transcript[9 * NMuls + (4 + NMuls) * (NScalarSlices - 1) + i],
        );
    }

    for i in 0..NAdds {
        accumulator = conditional_incomplete_add_with_hint::<F, Curve>(
            accumulator,
            add_points[i],
            !add_points[i].is_infinity(),
            transcript[10 * NMuls + (4 + NMuls) * (NScalarSlices - 1) + i],
        );
    }

    accumulator = sub_with_hint::<F, Curve>(
        accumulator,
        BigCurve::offset_generator_final(),
        transcript[NScalarSlices * NMuls + NScalarSlices * 4 + NMuls * 9 + NAdds - 4],
    );

    accumulator
}
