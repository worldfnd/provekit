use dep::bignum::BigNum;
pub use bignum::{Pallas_Fq, Pallas_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global PALLAS_SCALAR_SLICES: u32 = 64;

pub global PALLAS_PARAM: BigCurveParams<Pallas_Fq> = BigCurveParams {
    a: Pallas_Fq::from_limbs([0x00, 0x00, 0x00]),
    b: Pallas_Fq::from_limbs([0x05, 0x00, 0x00]),
    one: [
        Pallas_Fq::from_limbs([0x4698fc094cf91b992d30ed00000000, 0x22, 0x4000]),
        Pallas_Fq::from_limbs([0x02, 0x00, 0x00]),
    ],
    offset_generator: [
        Pallas_Fq::from_limbs([
            0x23b6bd3aa81bb54676c6f0df64b08a,
            0xb30c817a6940c0aea027ae1673f040,
            0x241a,
        ]),
        Pallas_Fq::from_limbs([
            0x510986b026c0897b7579aaf7752fbc,
            0xe40f2f0681582eca3b6bd8623a6820,
            0x3d7c,
        ]),
    ],
    offset_generator_final: [
        Pallas_Fq::from_limbs([
            0x4c3b04ed4a7d7c886d039d32162035,
            0x9cb2da6794cd9cbd2c85f2c805157f,
            0x2a84,
        ]),
        Pallas_Fq::from_limbs([
            0x96c3ab1a5c0adef0431c522083d854,
            0x8e1c9c43f468571d01e2549281ce25,
            0x0480,
        ]),
    ],
};

#[derive_curve_impl(quote { Pallas_Fq }, quote { PALLAS_PARAM })]
pub struct Pallas {
    pub x: Pallas_Fq,
    pub y: Pallas_Fq,
    pub is_infinity: bool,
}

pub type PallasScalar = ScalarField<PALLAS_SCALAR_SLICES>;

mod test {
    use bignum::{BigNum, Pallas_Fq, Pallas_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{Pallas, PALLAS_SCALAR_SLICES, PallasScalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = Pallas_Fr::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == PALLAS_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = Pallas::one();
        let negone = Pallas_Fr::one().neg();
        let scalar = PallasScalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }
    #[test]
    fn test_hash_to_curve() {
        let r = Pallas::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let mut four = Pallas_Fr::from(4);
        let p_minus_4_fr = Pallas_Fr::modulus() - four;
        let p_minus_4 = PallasScalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - Pallas_Fr::one();
        let p_minus_5 = PallasScalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = Pallas::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = Pallas::evaluate_linear_expression(points, scalars, [Pallas::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // Pallas cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<Pallas_Fq, PALLAS_SCALAR_SLICES, Pallas>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Pallas_Fr = Pallas_Fr::derive_from_seed(seed);
        let scalar_field = PallasScalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }

}
