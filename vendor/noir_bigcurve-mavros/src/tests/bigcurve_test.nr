use dep::bignum::BigNum;
use dep::bignum::BN254_Fq;
use dep::bignum::MNT6_753_Fq;
use dep::bignum::Secp256r1_Fq;
use std::ops::{Add, Neg, Sub};

use crate::bigcurve::BigCurve;
use crate::curve_jac;
use crate::curve_jac::types::AffineTranscript;
use crate::curve_jac::types::CurveJ;
use crate::curve_jac::types::JTranscript;
use crate::curves::bn254::{BN254, BN254J};
use crate::curves::mnt6_753::MNT6_753;
use crate::curves::secp256r1::{Secp256r1, Secp256r1J};
use crate::ops::point_table::PointTable;
use crate::scalar_field::ScalarField;

unconstrained fn evaluate_mul(P: BN254J, scalar: ScalarField<64>, Q: BN254J, K: BN254J) -> bool {
    let s: (CurveJ<BN254_Fq, BN254>, [AffineTranscript<BN254_Fq>; 326]) = (P.mul(scalar));
    assert(s.0.eq(K.neg()));
    Q.eq(s.0)
}

unconstrained fn get_transcript(
    P: BN254J,
    scalar: ScalarField<64>,
) -> [AffineTranscript<BN254_Fq>; 326] {
    let (_, transcript) = P.mul(scalar);
    transcript
}

#[test]
fn test_mul() {
    let P = BN254::one();

    let scalar: ScalarField<64> = ScalarField::from(
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff,
    ); // p - 2
    let transcript = unsafe { get_transcript(BN254J::from(P), scalar) };

    let result = crate::ops::msm::mul_with_hint::<64, 326, BN254_Fq, BN254>(P, scalar, transcript);

    // -2
    let mut expected = BN254 {
        x: BN254_Fq::from_limbs([
            0x7816a916871ca8d3c208c16d87cfd3,
            0x44e72e131a029b85045b68181585d9,
            0x0306,
        ]),
        y: BN254_Fq::from_limbs([
            0xa6a449e3538fc7ff3ebf7a5a18a2c4,
            0x738c0e0a7c92e7845f96b2ae9c0a68,
            0x15ed,
        ]),
        is_infinity: false,
    };
    expected.y = BigNum::zero() - expected.y;
    assert(result.x == expected.x);
    assert(result.y == expected.y);
}

#[test]
fn test_offset_foo() {
    let P = BN254 {
        x: BN254_Fq::from_limbs([
            0x0b672a3489895d47157f096e077348,
            0x29f5f5b786660171ae9ad36f6db594,
            0x15f1,
        ]),
        y: BN254_Fq::from_limbs([
            0x6e4553aa3ae998fcd27ca8a17188ef,
            0xb3193f7f0a731913174831ca905feb,
            0x21ff,
        ]),
        is_infinity: false,
    };
    let Q = BN254 {
        x: BN254_Fq::from_limbs([
            0x0b672a3489895d47157f096e077348,
            0x29f5f5b786660171ae9ad36f6db594,
            0x15f1,
        ]),
        y: BN254_Fq::from_limbs([
            0x6e4553aa3ae998fcd27ca8a17188ef,
            0xb3193f7f0a731913174831ca905feb,
            0x21ff,
        ]),
        is_infinity: false,
    };

    let R: BN254 = P.sub(Q);
    assert(R.is_infinity == true);
}

#[test]
fn test_mul_by_0() {
    let P = BN254::one();

    let scalar: ScalarField<64> = ScalarField::from(0); // p - 2
    let foo: Field = ScalarField::into(scalar);
    assert(foo == 0);
    let transcript = unsafe { get_transcript(BN254J::from(P), scalar) };

    let result = crate::ops::msm::mul_with_hint::<64, 326, BN254_Fq, BN254>(P, scalar, transcript);
    assert(result.is_infinity == true);
}

#[test]
fn test_mul_a_point_at_infinity() {
    let P = BN254::point_at_infinity();

    let scalar: ScalarField<64> = ScalarField::from(
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff,
    ); // p - 2
    let transcript = unsafe { get_transcript(BN254J::from(P), scalar) };

    let result = crate::ops::msm::mul_with_hint::<64, 326, BN254_Fq, BN254>(P, scalar, transcript);
    assert(result.is_infinity == true);
}

#[test]
fn test_mul_jac() {
    let scalar_multiplier = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000; // p - 1
    let P: CurveJ<BN254_Fq, BN254> = BN254J::one();

    let scalar: ScalarField<64> = ScalarField::from(scalar_multiplier);

    let expected = unsafe { P.incomplete_add(P.dbl().0.neg()).0 };
    let result = unsafe { evaluate_mul(P, scalar, expected, P) };
    assert(result == true);
}

unconstrained fn test_msm_jac_impl(scalars: [ScalarField<64>; 2]) {
    let One = BN254J::one();
    let Two = BN254J {
        x: BN254_Fq::from_limbs([
            0x7816a916871ca8d3c208c16d87cfd3,
            0x44e72e131a029b85045b68181585d9,
            0x0306,
        ]),
        y: BN254_Fq::from_limbs([
            0xa6a449e3538fc7ff3ebf7a5a18a2c4,
            0x738c0e0a7c92e7845f96b2ae9c0a68,
            0x15ed,
        ]),
        z: BigNum::one(),
        is_infinity: false,
    };
    let result = BN254J::msm([One, Two.neg()], scalars);
    let expected = Two.neg();
    assert(result.0 == expected);
}

#[test]
fn test_msm_jac() {
    let p_minus_2 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff; // p - 2
    let p_minus_6 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffb; // p - 6
    let scalar2: ScalarField<64> = ScalarField::from(p_minus_2);
    let scalar6: ScalarField<64> = ScalarField::from(p_minus_6);

    unsafe {
        test_msm_jac_impl([scalar6, scalar2]);
    }
}

#[test]
fn test_add_dbl() {
    let P = BN254J::one();
    let lhs = unsafe { ((P.dbl().0).dbl()).0 };
    let rhs = unsafe { P.dbl().0.incomplete_add(P).0.incomplete_add(P).0 };
    assert(lhs == rhs);
}

#[test]
fn test_transcript() {
    unsafe {
        let P = BN254J::one();

        let P2 = P.dbl();

        let Z_inverse = P2.1.z3.__invmod();

        let lambda = P2.1.lambda_numerator.__mul(Z_inverse);

        let lhs = (lambda.__add(lambda)).__mul(P.y);
        let rhs = (P.x.__add(P.x).__add(P.x)).__mul(P.x);

        assert(lhs == rhs);

        let X2 = P2.1.x3;
        let Y2 = P2.1.y3;
        let ZZ = Z_inverse.__mul(Z_inverse);
        let ZZZ = ZZ.__mul(Z_inverse);

        let x2 = X2.__mul(ZZ);
        let y2 = Y2.__mul(ZZZ);

        // ### test add transcript
        let P3 = P.incomplete_add(P2.0);
        let Z_inverse = P3.1.z3.__invmod();

        let lambda = P3.1.lambda_numerator.__mul(Z_inverse);

        let x1 = P.x;
        let y1 = P.y;

        let lhs = lambda.__mul(x2.__sub(x1));
        let rhs = y2.__sub(y1);

        assert(lhs == rhs);
    }
}

#[test]
fn test_double_with_hint() {
    unsafe {
        let P = BN254J::one();

        let P2 = P.dbl();

        let P_affine = BN254::one();

        let Z_inverse = P2.1.z3.__invmod();

        let lambda = P2.1.lambda_numerator.__mul(Z_inverse);

        let X3 = P2.1.x3;
        let Y3 = P2.1.y3;
        let ZZ = Z_inverse.__mul(Z_inverse);
        let ZZZ = ZZ.__mul(Z_inverse);

        let x3 = X3.__mul(ZZ);
        let y3 = Y3.__mul(ZZZ);

        let transcript: AffineTranscript<BN254_Fq> = AffineTranscript { lambda, x3, y3 };
        let P2_affine =
            crate::ops::affine::double_with_hint::<BN254_Fq, BN254>(P_affine, transcript);

        assert(P2_affine.x == x3);
        assert(P2_affine.y == y3);
    }
}

#[test]
fn test_double_with_hint_secp256r1() {
    unsafe {
        let P = Secp256r1J::one();

        let P2 = P.dbl();

        let P_affine = Secp256r1::one();

        let Z_inverse = P2.1.z3.__invmod();

        let lambda = P2.1.lambda_numerator.__mul(Z_inverse);

        let X3 = P2.1.x3;
        let Y3 = P2.1.y3;
        let ZZ = Z_inverse.__mul(Z_inverse);
        let ZZZ = ZZ.__mul(Z_inverse);

        let x3 = X3.__mul(ZZ);
        let y3 = Y3.__mul(ZZZ);

        let transcript: AffineTranscript<Secp256r1_Fq> = AffineTranscript { lambda, x3, y3 };
        let P2_affine =
            crate::ops::affine::double_with_hint::<Secp256r1_Fq, Secp256r1>(P_affine, transcript);

        assert(P2_affine.x == x3);
        assert(P2_affine.y == y3);
    }
}

#[test]
fn test_incomplete_add_with_hint() {
    unsafe {
        let P = BN254J::one();

        // Q = 2P
        let Q_affine = BN254 {
            x: BN254_Fq::from_limbs([
                0x7816a916871ca8d3c208c16d87cfd3,
                0x44e72e131a029b85045b68181585d9,
                0x0306,
            ]),
            y: BN254_Fq::from_limbs([
                0xa6a449e3538fc7ff3ebf7a5a18a2c4,
                0x738c0e0a7c92e7845f96b2ae9c0a68,
                0x15ed,
            ]),
            is_infinity: false,
        };
        let Q = BN254J::from(Q_affine);
        let R = P.incomplete_add(Q);

        let P_affine = BN254::one();

        let Z_inverse = R.1.z3.__invmod();

        let lambda = R.1.lambda_numerator.__mul(Z_inverse);

        let X3 = R.1.x3;
        let Y3 = R.1.y3;
        let ZZ = Z_inverse.__mul(Z_inverse);
        let ZZZ = ZZ.__mul(Z_inverse);

        let x3 = X3.__mul(ZZ);
        let y3 = Y3.__mul(ZZZ);

        let transcript: AffineTranscript<BN254_Fq> = AffineTranscript { lambda, x3, y3 };
        let P2_affine = crate::ops::affine::incomplete_add_with_hint::<BN254_Fq, BN254>(
            P_affine,
            Q_affine,
            transcript,
        );

        assert(P2_affine.x == x3);
        assert(P2_affine.y == y3);

        let P = BN254J::one();

        let lhs = P.dbl().0.dbl().0;
        let rhs = P.dbl().0.incomplete_add(P).0.incomplete_add(P).0;
        assert(lhs == rhs);
    }
}

#[test]
fn test_constrained_add() {
    unsafe {
        let P = BN254::one();

        // Q = 2P
        let Q = BN254 {
            x: BN254_Fq::from_limbs([
                0x7816a916871ca8d3c208c16d87cfd3,
                0x44e72e131a029b85045b68181585d9,
                0x0306,
            ]),
            y: BN254_Fq::from_limbs([
                0xa6a449e3538fc7ff3ebf7a5a18a2c4,
                0x738c0e0a7c92e7845f96b2ae9c0a68,
                0x15ed,
            ]),
            is_infinity: false,
        };

        let result = BN254J::from(P.add(Q));

        let P_j = BN254J::from(P);
        let Q_j = BN254J::from(Q);
        let expected = P_j.add(Q_j).0;

        assert(result.eq(expected));

        // doubling
        let Q = BN254::one();

        let result = BN254J::from(P.add(Q));
        let expected = P_j.dbl().0;
        assert(result.eq(expected));

        // infinity
        let Q = P.neg();
        let result = BN254J::from(P.add(Q));
        let expected = BN254J::point_at_infinity();
        assert(result.eq(expected));

        // lhs infinity
        let P = BN254::point_at_infinity();
        let result = BN254J::from(P.add(Q));
        let expected = BN254J::from(Q);
        assert(result.eq(expected));

        // rhs infinity
        let result = BN254J::from(Q.add(P));
        assert(result.eq(expected));

        // both infinity
        let Q = BN254::point_at_infinity();
        let result = BN254J::from(Q.add(P));
        let expected = BN254J::point_at_infinity();
        assert(result.eq(expected));
    }
}

#[test]
unconstrained fn test_unconstrained_add() {
    let P = BN254::one();

    // Q = 2P
    let Q = BN254 {
        x: BN254_Fq::from_limbs([
            0x7816a916871ca8d3c208c16d87cfd3,
            0x44e72e131a029b85045b68181585d9,
            0x0306,
        ]),
        y: BN254_Fq::from_limbs([
            0xa6a449e3538fc7ff3ebf7a5a18a2c4,
            0x738c0e0a7c92e7845f96b2ae9c0a68,
            0x15ed,
        ]),
        is_infinity: false,
    };

    let result = BN254J::from(P.add(Q));

    let P_j = BN254J::from(P);
    let Q_j = BN254J::from(Q);
    let expected = P_j.add(Q_j).0;

    assert(result.eq(expected));
}
#[test]
unconstrained fn test_unconstrained_add_one_side_infinity() {
    //Q + infinity and infinity + Q
    let Q = BN254::one();
    let P = BN254::point_at_infinity();
    let expected = BN254J::from(Q);
    let result = BN254J::from(Q.add(P));
    assert(result.eq(expected));
    let result = BN254J::from(P.add(Q));
    assert(result.eq(expected));
}

#[test]
unconstrained fn test_unconstrained_add_doubling() {
    // P + P
    let P = BN254::one();
    let Q = BN254::one();
    let P_j = BN254J::from(P);
    let result = BN254J::from(P.add(Q));
    let expected = P_j.dbl().0;
    assert(result.eq(expected));
}

#[test]
unconstrained fn test_unconstrained_add_infinity() {
    // P = -Q
    let P = BN254::one();
    let Q = P.neg();
    let result = BN254J::from(P.add(Q));
    let expected = BN254J::point_at_infinity();
    assert(result.eq(expected));

    // both at infinity
    let P = BN254::point_at_infinity();
    let Q = BN254::point_at_infinity();
    let result = BN254J::from(Q.add(P));
    let expected = BN254J::point_at_infinity();
    assert(result.eq(expected));
}

#[test]
fn test_sub() {
    unsafe {
        let P = BN254::one();

        // Q = 2P
        let Q = BN254 {
            x: BN254_Fq::from_limbs([
                0x7816a916871ca8d3c208c16d87cfd3,
                0x44e72e131a029b85045b68181585d9,
                0x0306,
            ]),
            y: BN254_Fq::from_limbs([
                0xa6a449e3538fc7ff3ebf7a5a18a2c4,
                0x738c0e0a7c92e7845f96b2ae9c0a68,
                0x15ed,
            ]),
            is_infinity: false,
        };

        let result = BN254J::from(P.sub(Q));

        let P_j = BN254J::from(P);
        let Q_j = BN254J::from(Q);
        let expected = P_j.sub(Q_j).0;

        assert(result.eq(expected));

        // doubling
        let Q = BN254::one();

        let result = BN254J::from(P.sub(Q.neg()));
        let expected = P_j.dbl().0;
        assert(result.eq(expected));

        // infinity
        let result = BN254J::from(P.sub(Q));
        let expected = BN254J::point_at_infinity();
        assert(result.eq(expected));

        // lhs infinity
        let P = BN254::point_at_infinity();
        let result = BN254J::from(P.sub(Q));
        let expected = BN254J::from(Q.neg());
        assert(result.eq(expected));

        // rhs infinity
        let result = BN254J::from(Q.sub(P));
        let expected = expected.neg();
        assert(result.eq(expected));

        // both infinity
        let Q = BN254::point_at_infinity();
        let result = BN254J::from(Q.sub(P));
        let expected = BN254J::point_at_infinity();
        assert(result.eq(expected));
    }
}

#[test]
unconstrained fn test_unconstrained_sub() {
    let P = BN254::one();

    // Q = 2P
    let Q = BN254 {
        x: BN254_Fq::from_limbs([
            0x7816a916871ca8d3c208c16d87cfd3,
            0x44e72e131a029b85045b68181585d9,
            0x0306,
        ]),
        y: BN254_Fq::from_limbs([
            0xa6a449e3538fc7ff3ebf7a5a18a2c4,
            0x738c0e0a7c92e7845f96b2ae9c0a68,
            0x15ed,
        ]),
        is_infinity: false,
    };

    let result = BN254J::from(P.sub(Q));

    let P_j = BN254J::from(P);
    let Q_j = BN254J::from(Q);
    let expected = P_j.sub(Q_j).0;

    assert(result.eq(expected));
}

#[test]
unconstrained fn test_unconstrained_sub_doubling() {
    // doubling
    let P = BN254::one();
    let Q = BN254::one();

    let result = BN254J::from(P.sub(Q.neg()));
    let P_j = BN254J::from(P);
    let expected = P_j.dbl().0;
    assert(result.eq(expected));
}

#[test]
unconstrained fn test_unconstrained_sub_infinity() {
    // both at infinity
    let P = BN254::one();
    let Q = BN254::one();
    let result = BN254J::from(P.sub(Q));
    let expected = BN254J::point_at_infinity();
    assert(result.eq(expected));
    // both infinity
    let P = BN254::point_at_infinity();
    let Q = BN254::point_at_infinity();
    let result = BN254J::from(Q.sub(P));
    let expected = BN254J::point_at_infinity();
    assert(result.eq(expected));
}

#[test]
unconstrained fn test_unconstrained_sub_one_side_infinity() {
    let P = BN254::point_at_infinity();
    let Q = BN254::one();

    // lhs infinity
    let result = BN254J::from(P.sub(Q));
    let expected = BN254J::from(Q.neg());
    assert(result.eq(expected));

    // rhs infinity
    let result = BN254J::from(Q.sub(P));
    let expected = expected.neg();
    assert(result.eq(expected));
}

#[test]
fn test_make_table() {
    unsafe {
        let P: BN254J = BN254J::one();

        let mut transcript: [JTranscript<BN254_Fq>] = &[];
        let T: curve_jac::point_table::PointTable<BN254_Fq> =
            curve_jac::point_table::PointTable::new(P);
        for i in 0..8 {
            transcript = transcript.push_back(T.transcript[i]);
        }

        let mut inverses: [BN254_Fq; 8] = [BN254_Fq::zero(); 8];

        for i in 0..8 {
            inverses[i] = transcript[i].z3;
        }

        inverses = bignum::bignum::batch_invert(inverses);

        let mut affine_transcript: [AffineTranscript<BN254_Fq>; 8] = [AffineTranscript::new(); 8];
        for i in 0..8 {
            let z_inv = inverses[i];

            let lambda = transcript[i].lambda_numerator.__mul(z_inv);
            let zz = z_inv.__mul(z_inv);
            let zzz = zz.__mul(z_inv);
            let x3 = transcript[i].x3.__mul(zz);
            let y3 = transcript[i].y3.__mul(zzz);
            affine_transcript[i] = AffineTranscript { lambda, x3, y3 };
        }

        let P_affine = BN254::one();

        let affine_point_table: PointTable<BN254_Fq> =
            PointTable::<BN254_Fq>::new_with_hint::<BN254>(P_affine, affine_transcript);

        for i in 0..8 {
            let point: BN254 = affine_point_table.get::<BN254>(i);
            point.validate_on_curve();
        }
    }
}

#[test]
fn test_bigcurve_sub_with_hint() {
    let accumulator = MNT6_753 {
        x: MNT6_753_Fq::from_limbs([
            0x5b6ad7b65e3a86239c2efbdb300b8d,
            0x7d06f1a94609f8e4eb48c998d1571d,
            0x95a74f11f2fb5be7544da5c184e38d,
            0x600f8f2fdcd5e802342ebe03c3787f,
            0xc3fa8f3f017c7aed50e1a14b78f3b3,
            0xe7f3b2638fa13f65670c15eb006e99,
            0x016389a6fb,
        ]),
        y: MNT6_753_Fq::from_limbs([
            0x42eb137506b02f7665ebbe0211b768,
            0x814148c3996475176b11c4db1d356a,
            0xf97e6cd350259b5456471a2237553f,
            0x5c822035f3f7c21fc2e6f9aac5945a,
            0xa319d0923fc0ac9db23b819dcb7371,
            0xa4186459f74d57db479c998a5db03a,
            0x7f824db1,
        ]),
        is_infinity: false,
    };
    let offset_generator = MNT6_753 {
        x: MNT6_753_Fq::from_limbs([
            0x5b6ad7b65e3a86239c2efbdb300b8d,
            0x7d06f1a94609f8e4eb48c998d1571d,
            0x95a74f11f2fb5be7544da5c184e38d,
            0x600f8f2fdcd5e802342ebe03c3787f,
            0xc3fa8f3f017c7aed50e1a14b78f3b3,
            0xe7f3b2638fa13f65670c15eb006e99,
            0x016389a6fb,
        ]),
        y: MNT6_753_Fq::from_limbs([
            0x42eb137506b02f7665ebbe0211b768,
            0x814148c3996475176b11c4db1d356a,
            0xf97e6cd350259b5456471a2237553f,
            0x5c822035f3f7c21fc2e6f9aac5945a,
            0xa319d0923fc0ac9db23b819dcb7371,
            0xa4186459f74d57db479c998a5db03a,
            0x7f824db1,
        ]),
        is_infinity: false,
    };
    let transcript: AffineTranscript<MNT6_753_Fq> = AffineTranscript {
        lambda: MNT6_753_Fq::from_limbs([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        x3: MNT6_753_Fq::from_limbs([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        y3: MNT6_753_Fq::from_limbs([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    };
    let result = crate::ops::affine::sub_with_hint::<MNT6_753_Fq, MNT6_753>(
        accumulator,
        offset_generator,
        transcript,
    );
    assert(result.is_infinity);
}
