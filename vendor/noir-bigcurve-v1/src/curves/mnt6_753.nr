use dep::bignum::BigNum;
pub use dep::bignum::{MNT6_753_Fq, MNT6_753_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global MNT6_753_SCALAR_SLICES: u32 = 189;
pub global MNT6_753_PARAMS: BigCurveParams<MNT6_753_Fq> = BigCurveParams {
    a: MNT6_753_Fq::from_limbs([0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    b: MNT6_753_Fq::from_limbs([
        0xba7505ba6fcf2485540b13dfc8468a,
        0xf9a80a95f401867c4e80f4747fde5a,
        0x0fcf2c43d7bf847957c34cca1e3585,
        0xb7985993f62f03b22a9a3c737a1a1e,
        0xbb64b2bb01b10e60a5d5dfe0a25714,
        0x0863c79d56446237ce2e1468d14ae9,
        0x7da285e7,
    ]),
    offset_generator: [
        MNT6_753_Fq::from_limbs([
            0x609ffe70e0461c689f9a40960e5bc5,
            0xb1bed174cf960dcf3ec437a9fa6761,
            0xa457338a8cc16ecd88e2eb0269b7ab,
            0x1d8ba56f3fb444e986028bd1f21bd5,
            0x1b2cccc139248dfc32e73f03bc2aa,
            0x9bc08889e87268ef8cc37928d61ad2,
            0x9fb3e287,
        ]),
        MNT6_753_Fq::from_limbs([
            0x4f3f72133b64a86332cda12fdd2e5c,
            0x44ee033033782484012f59a1357b54,
            0x4690459bb8919e42732b3f64d58c8f,
            0x16c3b7d7210c1ff9261d8f8164fd9f,
            0xe18ff83be1026d997e8bf51045e26a,
            0xf3638a62421dea98805983ae94a71e,
            0x14cac58c6,
        ]),
    ],
    offset_generator_final: [
        MNT6_753_Fq::from_limbs([
            0x74b91bb16f84e624107e70c6cbd7a9,
            0x781d55b1e35fcffa5ad76df1d72c14,
            0x9c7fc6c430ebd9ef94ac10e5a5e926,
            0xfd33bee5663dd47525738359e63981,
            0x26b4c4a59e6faf58ae30b733376e08,
            0x78f77b657abe003eb66527f2289e97,
            0x1092e9cbd,
        ]),
        MNT6_753_Fq::from_limbs([
            0xeeac15d4d7e29ba05f266e6dc72313,
            0xfc8cdae9901edfb374b8a1be1a22c4,
            0xaf97058c91ac2fecd8db5946cab6e7,
            0xb05f072b00ef001eeacc3e5e739be2,
            0x9dded74b9001d7453f2b13aa2082c0,
            0xba386c34c11bb29f45b35ad0b2d094,
            0x5e34452a,
        ]),
    ],
    one: [
        MNT6_753_Fq::from_limbs([
            0x329a6fefa9a1f3f7a1fbd93a7bffb8,
            0x1acbf7da60895b8b3d9d442c4c4123,
            0xe5e3c57b6df120cee3cd9d867e66d1,
            0x0c0d5fc5e818771b931f1d5bdd069c,
            0x131c2437e884c4997fd1dcb409367d,
            0x6e831147412cfb1002284f30338088,
            0x255f8e87,
        ]),
        MNT6_753_Fq::from_limbs([
            0x521df9855687139f0c51754c0ccc49,
            0x4d9992f5cbf4b2cc4c42eff9a5a6c4,
            0x0dc7a593cce5a792e94d0020c335b7,
            0x4c7a18ed9c4bd3c7ed0ffb31c57e61,
            0x2a3585bdd6d7722c6c07d7873bb02d,
            0x6e2eb3fca70dc1063bac3455180120,
            0x0128c02fff,
        ]),
    ],
};

#[derive_curve_impl(quote { MNT6_753_Fq }, quote { MNT6_753_PARAMS })]
pub struct MNT6_753 {
    pub x: MNT6_753_Fq,
    pub y: MNT6_753_Fq,
    pub is_infinity: bool,
}
pub type MNT6_753Scalar = ScalarField<MNT6_753_SCALAR_SLICES>;

mod test {
    use bignum::{BigNum, MNT6_753_Fq, MNT6_753_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{MNT6_753, MNT6_753_SCALAR_SLICES, MNT6_753Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = MNT6_753_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == MNT6_753_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = MNT6_753::one();
        let negone = MNT6_753_Fr::one().neg();
        let scalar = MNT6_753Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = MNT6_753::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let mut four = MNT6_753_Fr::from(4);

        let p_minus_4_fr = MNT6_753_Fr::modulus() - four;
        let p_minus_4 = MNT6_753Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - MNT6_753_Fr::one();
        let p_minus_5 = MNT6_753Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = MNT6_753::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = MNT6_753::evaluate_linear_expression(points, scalars, [MNT6_753::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // MNT6-753 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<MNT6_753_Fq, MNT6_753_SCALAR_SLICES, MNT6_753>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: MNT6_753_Fr = MNT6_753_Fr::derive_from_seed(seed);
        let scalar_field = MNT6_753Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }

}
