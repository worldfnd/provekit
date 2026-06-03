use dep::bignum::BigNum;
pub use dep::bignum::{MNT4_753_Fq, MNT4_753_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global MNT4_753_SCALAR_SLICES: u32 = 189;

pub global MNT4_753_PARAMS: BigCurveParams<MNT4_753_Fq> = BigCurveParams {
    a: MNT4_753_Fq::from_limbs([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    b: MNT4_753_Fq::from_limbs([
        0xad265458e06372009c9a0491678ef4,
        0x773111c36c8b1b4e8f1ece940ef9ea,
        0xc3d8bb21c8d68bb8cfb9db4b8c8fba,
        0xa92c78dc537e51a16703ec9855c77f,
        0x051c596560835df0c9e50a5b59b882,
        0xc9dcae7a016ac5d7748d3313cd8e39,
        0x01373684a8,
    ]),
    offset_generator: [
        MNT4_753_Fq::from_limbs([
            0x7096d4ad83e62149a57b630c729c93,
            0x43e5fc6f8171a07a06ed1facf93bec,
            0x47ef121ca5433e8cf6d741daa58f79,
            0x8329a61a232ff555c1ddd38dda3a0c,
            0x735e040c13d5aeaa86a2c9916965e0,
            0x8c9a5e148acb24eb637d489a298876,
            0xd9387342,
        ]),
        MNT4_753_Fq::from_limbs([
            0x276d34b05b02dbb35a29ff8f4e52a4,
            0x135737e49cb43ec95ab4afe7dda831,
            0x2b24c2a0e16c027ea2d43fcca370fa,
            0xb338f0b48d80f0c6db4e8b3da62a7c,
            0x1c389c535875341ce204435407b123,
            0x88e500765474d085539bf29fe1b198,
            0x1491b2a17,
        ]),
    ],
    offset_generator_final: [
        MNT4_753_Fq::from_limbs([
            0x45e8d0587792f9fee63cfdf4a964e3,
            0xf8ac8cb84063a10018bffcb9db7f29,
            0x5655e6aa735382c27d472b62c8fc4b,
            0x750bb680f220d69de7e0d36ea11f0a,
            0xa16f3f5ee91371e7b28804ec92bf72,
            0xf754a159fff22611c5aa1f01658ef3,
            0x81167e44,
        ]),
        MNT4_753_Fq::from_limbs([
            0xa4d10fd529b54742901579fadff979,
            0x189599dbd258f0957de75f1aa933a1,
            0xaf45d2ed682ee9962a210121b78392,
            0x86a0076e059c92e19b26a8e0a736ec,
            0xd33ecf3330fce365ab33f16fa90700,
            0x42217eabdac6b165662a43fd5085,
            0x198c06b38,
        ]),
    ],
    one: [
        MNT4_753_Fq::from_limbs([
            0xc2ab23be1c24740af0fdeb3b7f1981,
            0xfeff338dd73a5a7eeecfbce7cf95d3,
            0x463d98a4ea009d57aad9716f708885,
            0x6d1ef781d1de4ffb1f806b314c5ad3,
            0xefa5546444d40c82d6a271f1a43862,
            0x450bb76a02d86daaffbaeb69995eb9,
            0x542f1dad,
        ]),
        MNT4_753_Fq::from_limbs([
            0x031ea99cff05e05ec3be2e4a050358,
            0x23036db8fb990a342449caeb92fa6b,
            0x5dea57ef53ee29157bdf1b741aebd4,
            0xee5599dd7c3dfa4100284833115aec,
            0x7fddcdea19cb10b2bf61f37ae2c456,
            0x26e257b175ae94deb9e10aba4ba72f,
            0x4ab64735,
        ]),
    ],
};

pub type MNT4_753Scalar = ScalarField<MNT4_753_SCALAR_SLICES>;

#[derive_curve_impl(quote { MNT4_753_Fq }, quote { MNT4_753_PARAMS })]
pub struct MNT4_753 {
    pub x: MNT4_753_Fq,
    pub y: MNT4_753_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, MNT4_753_Fq, MNT4_753_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{MNT4_753, MNT4_753_SCALAR_SLICES, MNT4_753Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = MNT4_753_Fr::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == MNT4_753_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = MNT4_753::one();
        let negone = MNT4_753_Fr::one().neg();
        let scalar = MNT4_753Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = MNT4_753::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let mut four = MNT4_753_Fr::from(4);
        let p_minus_4_fr = MNT4_753_Fr::modulus() - four;
        let p_minus_4 = MNT4_753Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - MNT4_753_Fr::one();
        let p_minus_5 = MNT4_753Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = MNT4_753::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = MNT4_753::evaluate_linear_expression(points, scalars, [MNT4_753::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // MNT4-753 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<MNT4_753_Fq, MNT4_753_SCALAR_SLICES, MNT4_753>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: MNT4_753_Fr = MNT4_753_Fr::derive_from_seed(seed);
        let scalar_field = MNT4_753Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
