use dep::bignum::BigNum;
pub use dep::bignum::{BLS12_377_Fq, BLS12_377_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global BLS12_377_SCALAR_SLICES: u32 = 64;
pub global BLS12_377_PARAMS: BigCurveParams<BLS12_377_Fq> = BigCurveParams {
    a: BLS12_377_Fq::from_limbs([0x00, 0x00, 0x00, 0x00]),
    b: BLS12_377_Fq::from_limbs([0x01, 0x00, 0x00, 0x00]),
    offset_generator: [
        BLS12_377_Fq::from_limbs([
            0xe279ebba7403b4462b83f55c265caf,
            0xeccaa64d9d21701f5b0ca5e3ed8363,
            0xb86dab1a5897538643a2d539c40a9c,
            0xdb1a,
        ]),
        BLS12_377_Fq::from_limbs([
            0xe8a8c7e4a7ed2355b8f369a91dcd3a,
            0xf1d66715d4202ab869250fbffe6d30,
            0x89fd4105959d8ff4f750b2a2cf6ace,
            0xf224,
        ]),
    ],
    offset_generator_final: [
        BLS12_377_Fq::from_limbs([
            0xe4adcfc2ba97d7dec96a1d0c9eae67,
            0x4084f9cefdc75fa8f2b81a6a4e7d94,
            0xecdabbc2ffa672d388dcdc5b9fb2a6,
            0x169e6,
        ]),
        BLS12_377_Fq::from_limbs([
            0x33efbc5d6f58dbe4e6736d6eebfc86,
            0xdbd2fd5433292a37d9d7ed79778913,
            0x8f102a12aa4738a7ca299cae45f99,
            0x12b1b,
        ]),
    ],
    one: [
        BLS12_377_Fq::from_limbs([
            0x481512ffcd394eeab9b16eb21be9ef,
            0x1e2caa9d41bb188282c8bd37cb5cd5,
            0xdefe740a67c8fc6225bf87ff548595,
            0x8848,
        ]),
        BLS12_377_Fq::from_limbs([
            0xfe3d3634a9591afd82de55559c8ea6,
            0xb348ca3e52d96d182ad44fb82305c2,
            0x69c5102eff1f674f5d30afeec4bd7f,
            0x01914a,
        ]),
    ],
};

pub type BLS12_377Scalar = ScalarField<BLS12_377_SCALAR_SLICES>;

#[derive_curve_impl(quote { BLS12_377_Fq }, quote { BLS12_377_PARAMS })]
pub struct BLS12_377 {
    pub x: BLS12_377_Fq,
    pub y: BLS12_377_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BLS12_377_Fq, BLS12_377_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::BLS12_377;
    use super::BLS12_377_SCALAR_SLICES;
    use super::BLS12_377Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BLS12_377_Fr::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BLS12_377_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BLS12_377::one();
        let negone = BLS12_377_Fr::one().neg();
        let scalar = BLS12_377Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }
    #[test]
    fn test_hash_to_curve() {
        let r = BLS12_377::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let mut four = BLS12_377_Fr::zero();
        four.set_limb(0, 4);
        let p_minus_4_fr = BLS12_377_Fr::modulus() - four;
        let p_minus_4 = BLS12_377Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BLS12_377_Fr::one();
        let p_minus_5 = BLS12_377Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BLS12_377::one();
        let b = a.neg();
        let mut points = [a, b];

        let result =
            BLS12_377::evaluate_linear_expression(points, scalars, [BLS12_377::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BLS12-377 cofactor is 0x170b5d44300000000000000000000000
        crate::utils::derive_offset_generators::verify_offset_generators::<BLS12_377_Fq, BLS12_377_SCALAR_SLICES, BLS12_377>(
            0x170b5d44300000000000000000000000,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BLS12_377_Fr = BLS12_377_Fr::derive_from_seed(seed);
        let scalar_field = BLS12_377Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
