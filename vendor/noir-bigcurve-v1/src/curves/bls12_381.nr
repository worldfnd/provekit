use dep::bignum::BigNum;
use dep::bignum::BLS12_381_Fq;

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global BLS12_381_SCALAR_SLICES: u32 = 64;
pub global BLS12_381_PARAMS: BigCurveParams<BLS12_381_Fq> = BigCurveParams {
    a: BLS12_381_Fq::from_limbs([0x00, 0x00, 0x00, 0x00]),
    b: BLS12_381_Fq::from_limbs([0x04, 0x00, 0x00, 0x00]),
    offset_generator: [
        BLS12_381_Fq::from_limbs([
            0xa5e7acf04e24afbb0f741fa304b8f1,
            0xe0581564ab34a38b34162f2a1f1814,
            0x6114857e74eadf24d5389a93ca9101,
            0x12a21c,
        ]),
        BLS12_381_Fq::from_limbs([
            0xfb7e9923e9251c6055753ba0d6579c,
            0x80a07936fdc550b20b6ae7fbaa3a68,
            0xb8f19f0f26792df418be11ffc25cca,
            0x15c50a,
        ]),
    ],
    offset_generator_final: [
        BLS12_381_Fq::from_limbs([
            0x5d61eb4475daee01ef2bf486549fa9,
            0x16c147559aaa74f6ebf063183a80f9,
            0x8c5f1cc110c563224ee2195cd6d32b,
            0x165621,
        ]),
        BLS12_381_Fq::from_limbs([
            0xf26a44e54a85d8b814aa72179d05c6,
            0xa5b0adde9190828c1c21c6ea3d6965,
            0x7e0f01621d824700252b1f6c22974e,
            0x73285,
        ]),
    ],
    one: [
        BLS12_381_Fq::from_limbs([
            0x55e83ff97a1aeffb3af00adb22c6bb,
            0x8c4f9774b905a14e3a3f171bac586c,
            0xa73197d7942695638c4fa9ac0fc368,
            0x17f1d3,
        ]),
        BLS12_381_Fq::from_limbs([
            0x3cc744a2888ae40caa232946c5e7e1,
            0xe095d5d00af600db18cb2c04b3edd0,
            0x81e3aaa0f1a09e30ed741d8ae4fcf5,
            0x08b3f4,
        ]),
    ],
};

pub type BLS12_381Scalar = ScalarField<BLS12_381_SCALAR_SLICES>;

#[derive_curve_impl(quote { BLS12_381_Fq }, quote { BLS12_381_PARAMS })]
pub struct BLS12_381 {
    pub x: BLS12_381_Fq,
    pub y: BLS12_381_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BLS12_381_Fq, BLS12_381_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{BLS12_381, BLS12_381_SCALAR_SLICES, BLS12_381Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BLS12_381_Fr::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BLS12_381_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BLS12_381::one();
        let negone = BLS12_381_Fr::one().neg();
        let scalar = BLS12_381Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BLS12_381::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BLS12_381_Fr::from(4);
        let p_minus_4_fr = BLS12_381_Fr::modulus() - four;
        let p_minus_4 = BLS12_381Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BLS12_381_Fr::one();
        let p_minus_5 = BLS12_381Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BLS12_381::one();
        let b = a.neg();
        let mut points = [a, b];

        let result =
            BLS12_381::evaluate_linear_expression(points, scalars, [BLS12_381::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BLS12-381 cofactor is 0x396C8C005555E1568C00AAAB0000AAAB
        crate::utils::derive_offset_generators::verify_offset_generators::<BLS12_381_Fq, BLS12_381_SCALAR_SLICES, BLS12_381>(
            0x396C8C005555E1568C00AAAB0000AAAB,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BLS12_381_Fr = BLS12_381_Fr::derive_from_seed(seed);
        let scalar_field = BLS12_381Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }

}
