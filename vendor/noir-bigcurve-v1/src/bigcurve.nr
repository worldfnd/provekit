use crate::curve_jac::types::AffineTranscript;
use crate::scalar_field::ScalarField;
use dep::bignum::BigNum;

use std::ops::{Add, Neg, Sub};

/// Implements an elliptic curve over a prime field that is not the circuit's native field.

pub struct BigCurveParams<B> {
    pub a: B,
    pub b: B,
    pub offset_generator: [B; 2],
    pub offset_generator_final: [B; 2],
    pub one: [B; 2],
}

pub trait BigCurve<B: BigNum>: Eq + Add + Sub + Neg {
    /// Returns the x-coordinate of the point.
    fn x(self) -> B;

    /// Returns the y-coordinate of the point.
    fn y(self) -> B;

    /// Returns the a-coordinate of the curve.
    fn a() -> B;

    /// Returns the b-coordinate of the curve.
    fn b() -> B;

    /// Creates a point from its coordinates.
    fn from_coordinates(x: B, y: B, is_infinity: bool) -> Self;

    /// Returns the point at infinity (the identity element of the curve group).
    fn point_at_infinity() -> Self;

    /// Returns true if the point is the point at infinity.
    fn is_infinity(self) -> bool;

    /// Returns the canonical generator point of the curve.
    fn one() -> Self;

    /// Returns a generator point offset by a fixed value (implementation-specific).
    fn offset_generator() -> Self;

    /// Returns the final offset generator point (implementation-specific).
    fn offset_generator_final() -> Self;

    /// Validates that the point lies on the curve. May panic or fail if invalid.
    fn validate_on_curve(self);

    /// Multiplies the point by a scalar value, returning the resulting point.
    fn mul<let NScalarSlices: u32>(self, scalar: ScalarField<NScalarSlices>) -> Self;

    /// Hashes the provided `seed` to a point on the curve.
    fn hash_to_curve<let N: u32>(seed: [u8; N]) -> Self;

    /// Evaluates a linear expression involving multiple points and scalars, returning the resulting point.
    fn evaluate_linear_expression<let NScalarSlices: u32, let NMuls: u32, let NAdds: u32>(
        mul_points: [Self; NMuls],
        mul_scalars: [ScalarField<NScalarSlices>; NMuls],
        add_points: [Self; NAdds],
    ) -> Self;
}

pub comptime fn derive_curve_impl(
    struct_def: TypeDefinition,
    field_type: Quoted,
    params: Quoted,
) -> Quoted {
    let typ = struct_def.as_type();
    let CurveJ = quote { $crate::curve_jac::types::CurveJ };
    let AffineTranscript = quote { $crate::curve_jac::types::AffineTranscript };

    quote {
        impl $crate::BigCurve<$field_type> for $typ {
            fn x(self) -> $field_type {
                self.x
            }

            fn y(self) -> $field_type {
                self.y
            }

            fn a() -> $field_type {
                $params.a
            }

            fn b() -> $field_type {
                $params.b
            }   

            fn is_infinity(self) -> bool {
                self.is_infinity
            }

            fn from_coordinates(x: $field_type, y: $field_type, is_infinity: bool) -> Self {
                Self { x, y, is_infinity }
            }

            fn point_at_infinity() -> Self {
                Self { 
                    x: $field_type::zero(), 
                    y: $field_type::zero(), 
                    is_infinity: true 
                }
            }

            fn offset_generator() -> Self {
                let result: [$field_type; 2] = $params.offset_generator;
                Self { 
                    x: result[0], 
                    y: result[1], 
                    is_infinity: false 
                }
            }

            fn offset_generator_final() -> Self {
                let result: [$field_type; 2] = $params.offset_generator_final;
                Self { 
                    x: result[0], 
                    y: result[1], 
                    is_infinity: false 
                }
            }

            fn one() -> Self {
                let result: [$field_type; 2] = $params.one;
                Self { 
                    x: result[0], 
                    y: result[1], 
                    is_infinity: false 
                }
            }

            fn validate_on_curve(self) {
                // if is point at infinity, we're on the curve.
                // In this case just sub in a valid point for the x/y coordinates we are about to test
                let one: Self = Self::one();
                let x: $field_type = if self.is_infinity { one.x } else { self.x };
                let y: $field_type = if self.is_infinity { one.y } else { self.y };
                let xx = std::ops::Mul::mul(x, x);
                //  xxx - yy + ax + b = 0
                // (xx + a) * x - y*y + b = 0
                // validate the provided value of `y3` is correct
                $crate::internal::evaluate_quadratic_expression(
                    [[xx, $params.a], [y, $field_type::zero()]],
                    [[false, false], [false, false]],
                    [[x], [y]],
                    [[false], [true]],
                    [$params.b],
                    [false],
                );
            }

            fn mul<let NScalarSlices: u32>(self, scalar: ScalarField<NScalarSlices>) -> Self {
                let transcript: [$AffineTranscript<$field_type>; (NScalarSlices * 5) + 6] =
                    unsafe { $crate::internal::get_mul_transcript::<NScalarSlices, $field_type, $typ>(self, scalar) };
                $crate::internal::mul_with_hint::<NScalarSlices, (NScalarSlices * 5) + 6, $field_type, $typ>(self, scalar, transcript)
            }

            fn hash_to_curve<let N: u32>(seed: [u8; N]) -> Self {
                let r = $crate::utils::hash_to_curve::hash_to_curve::<$field_type, N>(seed, $params.a, $params.b);
                Self { x: r.0, y: r.1, is_infinity: false }
            }

            fn evaluate_linear_expression<let NScalarSlices: u32, let NMuls: u32, let NAdds: u32>(
                mul_points: [Self; NMuls],
                mul_scalars: [ScalarField<NScalarSlices>; NMuls],
                add_points: [Self; NAdds],
            ) -> Self {
                $crate::internal::evaluate_linear_expression::<$field_type,$typ, _, _, _>(mul_points, mul_scalars, add_points)
            }}

            // Expensive witness generation! Avoid if possible
            impl std::ops::Add for $typ {
                fn add(self, other: Self) -> Self {
                    let lhsJ = $CurveJ::<$field_type, $typ>::from(self);
                    let rhsJ = $CurveJ::<$field_type, $typ>::from(other);
                    let (result_jac, j_transcript) = unsafe { lhsJ.add(rhsJ) };
                    let transcript = unsafe { $crate::curve_jac::types::AffineTranscript::from_j(j_transcript) };
                    if std::runtime::is_unconstrained() {
                        $typ::from_coordinates(transcript.x3, transcript.y3, result_jac.is_infinity)
                    } else {
                        $crate::internal::add_with_hint::<$field_type, $typ>(self, other, transcript)           
                    }
                }
            }

            impl std::cmp::Eq for $typ {
                fn eq(self, other: Self) -> bool {
                    let coords_equal =
                        self.x.eq(other.x) & self.y.eq(other.y) & !self.is_infinity & !other.is_infinity;
                    let infinity = self.is_infinity & other.is_infinity;
                    coords_equal | infinity
                }
            }

            impl std::ops::Sub for $typ {
                fn sub(self, other: Self) -> Self {
                    let lhsJ = $CurveJ::<$field_type, $typ>::from(self);
                    let rhsJ = $CurveJ::<$field_type, $typ>::from(other);
                    let (result_jac, j_transcript) = unsafe { lhsJ.sub(rhsJ) };
                    
                    // Convert back to affine coordinates using the transcript
                    let transcript = unsafe { $crate::curve_jac::types::AffineTranscript::from_j(j_transcript) };
                    if std::runtime::is_unconstrained() {
                        $typ::from_coordinates(transcript.x3, transcript.y3, result_jac.is_infinity)
                    } else {
                        $crate::internal::sub_with_hint::<$field_type, $typ>(self, other, transcript)
                    }
                }
            }

            impl std::ops::Neg for $typ {
                fn neg(self) -> Self {
                    Self { 
                        x: self.x, 
                        y: std::ops::Neg::neg(self.y), 
                        is_infinity: self.is_infinity 
                    }
                }
            }        
    }
}
