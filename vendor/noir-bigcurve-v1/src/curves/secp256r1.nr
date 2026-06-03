use dep::bignum::BigNum;
pub use dep::bignum::{Secp256r1_Fq, Secp256r1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

use crate::curve_jac::types::CurveJ;

pub(crate) type Secp256r1J = CurveJ<Secp256r1_Fq, Secp256r1>;

pub global SECP256r1_PARAM: BigCurveParams<Secp256r1_Fq> = BigCurveParams {
    a: Secp256r1_Fq::from_limbs([
        0xfffffffffffffffffffffffc,
        0xffff00000001000000000000000000,
        0xffff,
    ]),
    b: Secp256r1_Fq::from_limbs([
        0x1d06b0cc53b0f63bce3c3e27d2604b,
        0x35d8aa3a93e7b3ebbd55769886bc65,
        0x5ac6,
    ]),
    one: [
        Secp256r1_Fq::from_limbs([
            0x037d812deb33a0f4a13945d898c296,
            0xd1f2e12c4247f8bce6e563a440f277,
            0x6b17,
        ]),
        Secp256r1_Fq::from_limbs([
            0xce33576b315ececbb6406837bf51f5,
            0x42e2fe1a7f9b8ee7eb4a7c0f9e162b,
            0x4fe3,
        ]),
    ],
    offset_generator: [
        Secp256r1_Fq::from_limbs([
            351296668306655348126371036589410180,
            14099522553413269749449432069244305,
            23572,
        ]),
        Secp256r1_Fq::from_limbs([
            531116666173442154165394067505655294,
            354979494418088410567905796042406908,
            33819,
        ]),
    ],
    offset_generator_final: [
        Secp256r1_Fq::from_limbs([
            0x4e53e542bc502419d0cb4b99c0aa48,
            0x74d3a045b26542b1a5931d721650ab,
            0x6982,
        ]),
        Secp256r1_Fq::from_limbs([
            0xbe3c1ef0581c8f76517e499277b269,
            0xfd562740986614ce3b7025c0dfb8aa,
            0xfc88,
        ]),
    ],
};

pub global SECP256r1_SCALAR_SLICES: u32 = 65;

pub type Secp256r1Scalar = ScalarField<SECP256r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::Secp256r1_Fq }, quote { SECP256r1_PARAM })]
pub struct Secp256r1 {
    pub x: Secp256r1_Fq,
    pub y: Secp256r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, Secp256r1_Fq, Secp256r1_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{Secp256r1, SECP256r1_SCALAR_SLICES, Secp256r1Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = Secp256r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == SECP256r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = Secp256r1::one();
        let negone = Secp256r1_Fr::one().neg();
        let scalar = Secp256r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = Secp256r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = Secp256r1_Fr::from(4);
        let p_minus_4_fr = Secp256r1_Fr::modulus() - four;
        let p_minus_4 = Secp256r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - Secp256r1_Fr::one();
        let p_minus_5 = Secp256r1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = Secp256r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result =
            Secp256r1::evaluate_linear_expression(points, scalars, [Secp256r1::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // Secp256r1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<Secp256r1_Fq, SECP256r1_SCALAR_SLICES, Secp256r1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Secp256r1_Fr = Secp256r1_Fr::derive_from_seed(seed);
        let scalar_field = Secp256r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }

}
