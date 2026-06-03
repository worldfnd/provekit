use dep::bignum::BigNum;
pub use dep::bignum::BN254_Fq;

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

use crate::curve_jac::types::CurveJ;

pub global BN254_PARAMS: BigCurveParams<BN254_Fq> = BigCurveParams {
    a: BN254_Fq::from_limbs([0x00, 0x00, 0x00]),
    b: BN254_Fq::from_limbs([0x03, 0x00, 0x00]),
    offset_generator: [
        BN254_Fq::from_limbs([
            0x377f339fa8372d1d3adc42a3d4901c,
            0x96cbfde252d4502d20fe63e6eb2b52,
            0x0666,
        ]),
        BN254_Fq::from_limbs([
            0x06d5ac65dd163514b69bb7b45a8c52,
            0xa20295561f2b500335be517e2f9ddf,
            0x1390,
        ]),
    ],
    offset_generator_final: [
        BN254_Fq::from_limbs([
            0x876f472cd3289fef9f11dc404e447f,
            0x7b083434c2a69effc4cb7fce9fecb6,
            0x0336,
        ]),
        BN254_Fq::from_limbs([
            0xa33149d0f82e5335a130fd3baf1bf4,
            0x37bbf991eefb0b04d52e689358228b,
            0x178e,
        ]),
    ],
    one: [BN254_Fq::from_limbs([0x01, 0x00, 0x00]), BN254_Fq::from_limbs([0x02, 0x00, 0x00])],
};

pub global BN254_SCALAR_SLICES: u32 = 64;
pub(crate) type BN254J = CurveJ<BN254_Fq, BN254>;
pub type BN254Scalar = ScalarField<BN254_SCALAR_SLICES>;

#[derive_curve_impl(quote { BN254_Fq }, quote {BN254_PARAMS})]
pub struct BN254 {
    pub x: BN254_Fq,
    pub y: BN254_Fq,
    pub is_infinity: bool,
}

mod test {
    use crate::bigcurve::BigCurve;
    use bignum::{BigNum, BN254_Fq};
    use std::ops::Neg;

    use super::{BN254, BN254_SCALAR_SLICES, BN254Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BN254_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert_eq(scalar_slices, BN254_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BN254::one();
        let scalar = BN254Scalar::from(-1);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BN254::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BN254_Fq::from(4);
        let p_minus_4_fr = BN254_Fq::modulus() - four;
        let p_minus_4 = BN254Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BN254_Fq::one();
        let p_minus_5 = BN254Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BN254::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BN254::evaluate_linear_expression(points, scalars, [b]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BN254 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<BN254_Fq, BN254_SCALAR_SLICES, BN254>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BN254_Fq = BN254_Fq::derive_from_seed(seed);
        let scalar_field = BN254Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
