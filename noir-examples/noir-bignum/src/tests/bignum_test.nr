use crate::bignum::BigNum;
use crate::bignum::BigNumTrait;
use crate::bignum::to_field;
use crate::fns::unconstrained_helpers::__helper_add;

use crate::params::BigNumParams;
use crate::params::BigNumParamsGetter;

use crate::fields::bls12_381Fq::BLS12_381_Fq;
use crate::fields::bls12_381Fr::BLS12_381_Fr;
use crate::fields::bn254Fq::{BN254_Fq, BN254_Fq_Params};
use crate::fields::U256::U256;

struct Test2048Params {}

// See https://github.com/noir-lang/noir/issues/6172
#[test]
fn silence_warning() {
    let _ = Test2048Params {};
}

global TEST_2048_PARAMS: BigNumParams<18, 2048> = BigNumParams {
    has_multiplicative_inverse: false,
    modulus: [
        0xc0a197a5ae0fcdceb052c9732614fe,
        0x656ae034423283422243918ab83be3,
        0x6bf590da48a7c1070b7d5aabaac678,
        0x0cce39f530238b606f24b296e2bda9,
        0x01e1fef9bb9c1c3ead98f226f1bfa0,
        0xad8c1c816e12e0ed1379055e373abf,
        0xcebe80e474f753aa9d1461c435123d,
        0xaee5a18ceedef88d115a8b93c167ad,
        0x268ba83c4a65c4307427fc495d9e44,
        0xdd2777926848667b7df79f342639d4,
        0xf455074c96855ca0068668efe7da3d,
        0x5ddba6b30bbc168bfb3a1225f27d65,
        0x591fec484f36707524133bcd6f4258,
        0x59641b756766aeebe66781dd01d062,
        0x58bc5eaff4b165e142bf9e2480eebb,
        0x667a3964f08e06df772ce64b229a72,
        0x9c1fdb18907711bfe3e3c1cf918395,
        0xb8,
    ],
    double_modulus: [
        0x0181432f4b5c1f9b9d60a592e64c29fc,
        0x01cad5c06884650684448723157077c6,
        0x01d7eb21b4914f820e16fab557558cef,
        0x01199c73ea604716c0de49652dc57b51,
        0x0103c3fdf37738387d5b31e44de37f3f,
        0x015b183902dc25c1da26f20abc6e757d,
        0x019d7d01c8e9eea7553a28c3886a247a,
        0x015dcb4319ddbdf11a22b5172782cf5a,
        0x014d17507894cb8860e84ff892bb3c88,
        0x01ba4eef24d090ccf6fbef3e684c73a7,
        0x01e8aa0e992d0ab9400d0cd1dfcfb47a,
        0x01bbb74d6617782d17f674244be4faca,
        0x01b23fd8909e6ce0ea4826779ade84af,
        0x01b2c836eacecd5dd7cccf03ba03a0c3,
        0x01b178bd5fe962cbc2857f3c4901dd75,
        0x01ccf472c9e11c0dbeee59cc964534e3,
        0x01383fb63120ee237fc7c7839f230729,
        0x0170,
    ],
    redc_param: [
        0x1697def7100cd5cf8d890b4ef2ec3f,
        0x765ba8304214dac764d3f4adc31859,
        0x8404bd14d927ea230e60d4bebf9406,
        0xc4d53a23bacc251ecbfc4b7ba5a0b4,
        0x3eaf3499474a6f5b2fff83f1259c87,
        0xbff4c737b97281f1a5f2384a8c16d9,
        0x1b4cf2f55358476b53237829990555,
        0xe7a804e8eacfe3a2a5673bc3885b86,
        0xabadeae4282906c817adf70eab4ae1,
        0x66f7df257fe2bf27f0809aceed9b0e,
        0xd90fb7428901b8bed11f6b81e36bf1,
        0x36e6ba885c60b7024c563605df7e07,
        0x2b7c58d2fb5d2c8478963ae6d4a44f,
        0x6ee761de26635f114ccc3f7d74f855,
        0x3fb726a10cf2220897513f05243de3,
        0x43a26bbd732496eb4d828591b8056e,
        0xf4e42304e60fb3a54fca735499f2cf,
        0x162f,
    ],
};

impl BigNumParamsGetter<18, 2048> for Test2048Params {
    fn get_params() -> BigNumParams<18, 2048> {
        TEST_2048_PARAMS
    }
}

type BN2048 = BigNum<18, 2048, Test2048Params>;

/**
 * @brief this example was failing - sanity test to validate it now works
 **/
#[test]
fn test_bls_reduction() {
    let X1 = BLS12_381_Fq {
        limbs: [
            0x55e83ff97a1aeffb3af00adb22c6bb,
            0x8c4f9774b905a14e3a3f171bac586c,
            0xa73197d7942695638c4fa9ac0fc368,
            0x17f1d3,
        ],
    };
    X1.validate_in_field();
    // Safety: test code
    let mut (_, XX_mul_3): (BLS12_381_Fq, BLS12_381_Fq) = unsafe {
        BigNum::__compute_quadratic_expression(
            [[X1, X1, X1]],
            [[false, false, false]],
            [[X1]],
            [[false]],
            [],
            [],
        )
    };
    XX_mul_3.validate_in_field();
}

#[test]
fn test_derive_from_seed() {
    let seed = [1, 2, 3, 4];
    let result_bn = BN254_Fq::derive_from_seed(seed);
    result_bn.validate_in_field();
}

fn test_eq<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b = BN::derive_from_seed([1, 2, 3, 4]);
    let c = BN::derive_from_seed([2, 2, 3, 4]);

    assert(a.eq(b) == true);
    assert(c.eq(b) == false);
    assert(c.eq(a) == false);
}

fn test_is_zero<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let zero = BN::zero();
    assert(a.is_zero() == false);
    assert(zero.is_zero() == true);
}

// // // 98760
// // // 99689
// // // 929 gates for a 2048 bit mul
fn test_mul<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a: BN = BN::derive_from_seed([1, 2, 3, 4]);
    let b: BN = BN::derive_from_seed([4, 5, 6, 7]);
    let c = (a + b) * (a + b);
    let d = (a * a) + (b * b) + (a * b) + (a * b);
    assert(c.eq(d));
}

fn test_add<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b: BN = BN::derive_from_seed([4, 5, 6, 7]);
    let one = BN::one();
    a.validate_in_range();
    a.validate_in_field();
    b.validate_in_range();
    b.validate_in_field();
    let mut c = (a + b);
    c += c;
    let d = (a + b) * (one + one);
    assert(c == (d));
    let e = one + one;
    let limbs: [u128; N] = e.get_limbs_slice().as_array();
    let mut first: bool = true;
    for limb in limbs {
        if first {
            first = false;
            assert(limb == 2);
        } else {
            assert(limb == 0);
        }
    }
}

fn test_div<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b = BN::derive_from_seed([4, 5, 6, 7]);

    let c = a / b;
    assert((b * c) == (a));
}

fn test_invmod<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let u = BN::derive_from_seed([1, 2, 3, 4]);
    // Safety: test code
    let v = unsafe { u.__invmod() };
    // Safety: test code
    let result = unsafe { u.__mul(v) };
    let expected = BN::one();
    assert(result == expected);
}

fn assert_is_not_equal<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b = BN::derive_from_seed([4, 5, 6, 7]);

    a.assert_is_not_equal(b);
}

fn assert_is_not_equal_fail<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b = BN::derive_from_seed([1, 2, 3, 4]);

    a.assert_is_not_equal(b);
}

fn assert_is_not_equal_overloaded_lhs_fail<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b = BN::derive_from_seed([1, 2, 3, 4]);

    let modulus = BN::modulus();

    let t0: [u128; N] = a.get_limbs_slice().as_array();
    let t1: [u128; N] = modulus.get_limbs_slice().as_array();
    // Safety: test code
    let a_plus_modulus = BN::from_slice(unsafe { __helper_add(t0, t1) });
    a_plus_modulus.assert_is_not_equal(b);
}

fn assert_is_not_equal_overloaded_rhs_fail<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b = BN::derive_from_seed([1, 2, 3, 4]);

    let modulus = BN::modulus();

    let t0: [u128; N] = b.get_limbs_slice().as_array();
    let t1: [u128; N] = modulus.get_limbs_slice().as_array();
    // Safety: test code
    let b_plus_modulus = BN::from_slice(unsafe { __helper_add(t0, t1) });
    a.assert_is_not_equal(b_plus_modulus);
}

fn assert_is_not_equal_overloaded_fail<let N: u32, BN>()
where
    BN: BigNumTrait,
{
    let a = BN::derive_from_seed([1, 2, 3, 4]);
    let b = BN::derive_from_seed([1, 2, 3, 4]);

    let modulus = BN::modulus();

    let t0: [u128; N] = a.get_limbs_slice().as_array();
    let t1: [u128; N] = b.get_limbs_slice().as_array();
    let t2: [u128; N] = modulus.get_limbs_slice().as_array();
    // Safety: test code
    let a_plus_modulus: BN = BN::from_slice(unsafe { __helper_add(t0, t2) });
    // Safety: test code
    let b_plus_modulus: BN = BN::from_slice(unsafe { __helper_add(t1, t2) });
    a_plus_modulus.assert_is_not_equal(b_plus_modulus);
}

#[test]
fn test_eq_BN() {
    // let stub = BN254_Fq::new();
    test_eq::<3, BN254_Fq>();
}

#[test]
fn test_is_zero_BN() {
    test_is_zero::<3, BN254_Fq>();
}

#[test]
fn test_add_BN() {
    let mut a = BN254_Fq::modulus();
    let mut b = BN254_Fq::modulus();
    let mut expected = BN254_Fq::modulus();

    a.limbs[0] -= 1;

    b.limbs[0] -= 1;

    let mut expected: BN254_Fq = BigNum::modulus();
    expected.limbs[0] -= 2;

    let c = a + b;
    assert(c == expected);
}

#[test]
fn test_add_test_BN_wrap_around() {
    let mut a: BN254_Fq = BigNum::modulus();
    let mut b: BN254_Fq = BN254_Fq { limbs: [3, 0, 0] };
    let mut expected: BN254_Fq = BN254_Fq::one();
    a.limbs[0] -= 2;

    let c = a + b;

    assert(c == expected);
}

#[test]
fn test_sub_test_BN() {
    // 0 - 1 should equal p - 1
    let mut a = BN254_Fq::zero();
    let mut b = BN254_Fq::one();
    let mut expected = BN254_Fq::modulus();
    expected.limbs[0] -= 1; // p - 1
    let result = a - b;
    assert(result == expected);
}

#[test]
fn test_eq_wrap() {
    let a: BN254_Fq = BigNum::modulus();
    let b = BN254_Fq::zero();
    assert(a == b);
}

#[test]
fn test_sub_modulus_limit() {
    // if we underflow, maximum result should be ...
    // 0 - 1 = o-1
    // 0 - p = 0
    let mut a = BN254_Fq::zero();
    let mut b = BN254_Fq::modulus();
    let mut expected = BigNum::zero();

    let result = a - b;
    assert(result == expected);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_sub_modulus_underflow() {
    // 0 - (p + 1) is smaller than p and should produce unsatisfiable constraints
    let mut a = BN254_Fq::zero();
    let mut b = BN254_Fq::modulus();
    b.limbs[0] += 1;
    let mut expected = BigNum::one();

    let result = a - b;
    assert(result == expected);
}

#[test]
fn test_add_modulus_limit() {
    // p + 2^{254} - 1 should be the maximum allowed value fed into an add operation
    // when adding, if the result overflows the modulus, we conditionally subtract the modulus, producing 2^{254} -  1
    // this is the largest value that will satisfy the range check applied when constructing a bignum
    let p: [u128; 3] = BN254_Fq_Params::get_params().modulus;
    let two_pow_254_minus_1: [u128; 3] =
        [0xffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffff, 0x3fff];
    let a = BN254_Fq { limbs: p };
    let b = BN254_Fq { limbs: two_pow_254_minus_1 };
    let result = a + b;
    assert(result == b);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_add_modulus_overflow() {
    //(2^{254} - 1) + (p - 1) = 2^{254} + p
    // after subtracting modulus, result is 2^{254} will does not satisfy the range check applied when constructing a BigNum
    let p: [u128; 3] = BN254_Fq_Params::get_params().modulus;
    let two_pow_254_minus_1: [u128; 3] =
        [0xffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffff, 0x3fff];
    let one = [1, 0, 0];
    // Safety: test code
    let a = BN254_Fq { limbs: unsafe { __helper_add(p, one) } };
    let b = BN254_Fq { limbs: two_pow_254_minus_1 };
    let result = a + b;
    assert(result == b);
}

#[test]
fn test_mul_BN() {
    test_mul::<3, BN254_Fq>();
}

#[test]
fn test_add_BN2() {
    test_add::<3, BN254_Fq>();
}

#[test]
fn test_mul_BN_with_one() {
    let a: BN254_Fq = BN254_Fq::modulus() - (BN254_Fq::one() + BN254_Fq::one());

    let b: BN254_Fq = BN254_Fq::one();

    let c = a * b;
    assert(c == a);
}

#[test]
fn test_div_BN() {
    test_div::<3, BN254_Fq>();
}

#[test]
fn test_invmod_BN() {
    test_invmod::<3, BN254_Fq>();
}

#[test]
fn test_assert_is_not_equal_BN() {
    assert_is_not_equal::<3, BN254_Fq>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_fail_BN() {
    assert_is_not_equal_fail::<3, BN254_Fq>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_lhs_fail_BN() {
    assert_is_not_equal_overloaded_lhs_fail::<3, BN254_Fq>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_rhs_fail_BN() {
    assert_is_not_equal_overloaded_rhs_fail::<3, BN254_Fq>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_fail_BN() {
    assert_is_not_equal_overloaded_fail::<3, BN254_Fq>();
}

#[test]
fn test_eq_2048() {
    test_eq::<18, BN2048>();
}

#[test]
fn test_is_zero_2048() {
    test_is_zero::<18, BN2048>();
}

#[test]
fn test_mul_2048() {
    test_mul::<18, BN2048>();
}

#[test]
fn test_add_2048() {
    test_add::<18, BN2048>();
}

#[test]
fn test_assert_is_not_equal_2048() {
    assert_is_not_equal::<18, BN2048>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_fail_2048() {
    assert_is_not_equal_fail::<18, BN2048>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_lhs_fail_2048() {
    assert_is_not_equal_overloaded_lhs_fail::<18, BN2048>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_rhs_fail_2048() {
    assert_is_not_equal_overloaded_rhs_fail::<18, BN2048>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_fail_2048() {
    assert_is_not_equal_overloaded_fail::<18, BN2048>();
}

#[test]
fn test_eq_U256() {
    test_eq::<3, U256>();
}

#[test]
fn test_is_zero_U256() {
    test_is_zero::<3, U256>();
}

#[test]
fn test_mul_U256() {
    test_mul::<3, U256>();
}

#[test]
fn test_add_U256() {
    test_add::<3, U256>();
}

#[test]
fn test_assert_is_not_equal_U256() {
    assert_is_not_equal::<3, U256>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_fail_U256() {
    assert_is_not_equal_fail::<3, U256>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_lhs_fail_U256() {
    assert_is_not_equal_overloaded_lhs_fail::<3, U256>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_rhs_fail_U256() {
    assert_is_not_equal_overloaded_rhs_fail::<3, U256>();
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn test_assert_is_not_equal_overloaded_fail_U256() {
    assert_is_not_equal_overloaded_fail::<3, U256>();
}

#[test]
fn test_udiv_mod_U256() {
    let a = U256::from_slice([
        0xec0ca0c0adce359af6fcea1a7ab2dc,
        0xdd52c4aa3fde93685d3f7cc285de32,
        0x6fea,
    ]);
    let b = U256::from_slice([12, 0, 0]);

    let (q, r) = a.udiv_mod(b);

    // Safety: test code
    let product = unsafe { q.__mul(b).__add(r) };
    assert(product == a);
}

#[test]
fn test_1_udiv_mod_2() {
    let _0: U256 = BigNum::zero();
    let _1: U256 = BigNum::one();
    assert(_1.udiv_mod(_1 + _1) == (_0, _1));
}

#[test]
fn test_20_udiv_mod_11() {
    let _1: U256 = BigNum::one();
    let _2_POW_120: U256 = BigNum::from_slice([0, 1, 0]);
    let _2_POW_121: U256 = BigNum::from_slice([0, 2, 0]);
    assert(_2_POW_121.udiv_mod(_2_POW_120 + _1) == (_1, _2_POW_120 - _1));
}

// // N.B. witness generation times make these tests take ~15 minutes each! Uncomment at your peril
// #[test]
// fn test_div_2048() {
//     let stub: BN2048 = BigNum::new();
//     test_div(stub);
// }

// // N.B. witness generation times make these tests take ~15 minutes each! Uncomment at your peril
// #[test]
// fn test_invmod_2048() {
//     let stub: BN2048 = BigNum::new();
//     test_invmod(stub);
// }

#[test]
fn test_2048_bit_quadratic_expression() {
    let a: [u128; 18] = [
        0x000000000000000000000000000000000083684820ff40795b8d9f1be2220cba,
        0x0000000000000000000000000000000000d4924fbdc522b07b6cd0ef5508fd66,
        0x0000000000000000000000000000000000d48f6c43c5930f3d70d6db09a48f4a,
        0x0000000000000000000000000000000000e7f72b2c0756704bea85be38352b34,
        0x00000000000000000000000000000000008337197826e2e9ea000ed5b05d5ac5,
        0x000000000000000000000000000000000040680101b43f6d17de8e3507f3d820,
        0x00000000000000000000000000000000000c6ba0cdcf77cff1c10355ea48d387,
        0x0000000000000000000000000000000000e51717a72902214a9dbeb90e4f225f,
        0x0000000000000000000000000000000000c1bd5bec78406b691f71cbcddb4574,
        0x00000000000000000000000000000000001ce5e532cfb306d7b52e7d9f1aa442,
        0x000000000000000000000000000000000019575932f75ddf00595b22782e1ba2,
        0x0000000000000000000000000000000000d630b3fbf0a9e55861e4399900feb9,
        0x0000000000000000000000000000000000d6b37aeb2daa8d2e2f7e29b0f7752a,
        0x0000000000000000000000000000000000e9cacdd93406256b9eb46b73948849,
        0x00000000000000000000000000000000001400e1f0a38695db66993fe042c48b,
        0x0000000000000000000000000000000000e1d829cb4fa8cabb7d0265efbd8527,
        0x000000000000000000000000000000000055f1a92a5dd099ef2bcd89ac175b52,
        0x00000000000000000000000000000000000000000000000000000000000000fc,
    ];
    let b: [u128; 18] = [
        0x0000000000000000000000000000000000c5694493e9bcc76e68dfcf73e0fde1,
        0x0000000000000000000000000000000000ede5e4b8b3e0dec1f4705c35521620,
        0x00000000000000000000000000000000007aa800bab1b33eda0f07695af6c583,
        0x000000000000000000000000000000000045892edea2c02bf0b8b1d2d9a4ebcc,
        0x00000000000000000000000000000000004dffb06bf396f3d0a5b67cff714bdd,
        0x00000000000000000000000000000000004d691db495235e1e032f1ef3e90274,
        0x0000000000000000000000000000000000d92c069d0f2675b2f46cb497aa62d4,
        0x00000000000000000000000000000000003d3f23584f113cef1a4b8b7d183f5c,
        0x0000000000000000000000000000000000289ba11d897837f9cec57dcc430bfc,
        0x0000000000000000000000000000000000765dc64f6ed4a6efd7b26c38f79e59,
        0x00000000000000000000000000000000008edf31fabf5c330ecf7f92fb6487cd,
        0x000000000000000000000000000000000053392f8b14dd78af702b3be2e0d557,
        0x000000000000000000000000000000000034abf357bfd56e9786a7e47ed9a5ae,
        0x0000000000000000000000000000000000a9ebb234064c8ab10d4e7900d4b973,
        0x00000000000000000000000000000000002a6850cce14a20463913002ddc0fa6,
        0x0000000000000000000000000000000000a97e3b06586bfa62325ef7557ab536,
        0x0000000000000000000000000000000000b942b0d26e5be2e08cd425107c59f7,
        0x0000000000000000000000000000000000000000000000000000000000000031,
    ];
    let c_expected: [u128; 18] = [
        0x00000000000000000000000000000000004518a874adebbcf963fed876dfcf78,
        0x00000000000000000000000000000000002b1535070c2deca63e2dc7145a9997,
        0x0000000000000000000000000000000000d9b738665a290c09f09202043d9387,
        0x0000000000000000000000000000000000c88853b11034fe12661eb7a5e41ca7,
        0x0000000000000000000000000000000000357cc4053e7eb127abc2c1430972a1,
        0x0000000000000000000000000000000000224df5e1be31a51562f8574027a992,
        0x000000000000000000000000000000000070ad9287e6326d534f1d2835e159ad,
        0x00000000000000000000000000000000000efa138f75f20b5117955e15bbb447,
        0x0000000000000000000000000000000000d9f45c310be1865ad23fbcdeb1d93f,
        0x00000000000000000000000000000000004f74ca4cf3df59a83f2df796fc9beb,
        0x0000000000000000000000000000000000ed1801428ebf7db771deb45f4311eb,
        0x00000000000000000000000000000000002ded3b46e3a84cda43157d4d927162,
        0x00000000000000000000000000000000009bcd6ac8f90601a44a84a026d4b383,
        0x0000000000000000000000000000000000ab098478b39031a1de85062fd5712b,
        0x00000000000000000000000000000000004432a79276f4375ff3ec2ced8b6cf6,
        0x0000000000000000000000000000000000a0922d75e96e3f9e31c0cbbcbd708a,
        0x00000000000000000000000000000000004013822c9e9aa5b5b1e9c33e4332b7,
        0x0000000000000000000000000000000000000000000000000000000000000058,
    ];

    let a_bn: BN2048 = BigNum { limbs: a };
    let b_bn: BN2048 = BigNum { limbs: b };
    // Safety: test code
    let c_bn = unsafe { a_bn.__mul(b_bn) };
    assert(c_bn.limbs == c_expected);

    a_bn.validate_in_range();

    BigNum::evaluate_quadratic_expression([[a_bn]], [[false]], [[b_bn]], [[false]], [c_bn], [true]);
}

#[test]
fn test_expressions() {
    let x: [u128; 6] = [
        0x000000000000000000000000000000000083684820ff40795b8d9f1be2220cba,
        0x0000000000000000000000000000000000d4924fbdc522b07b6cd0ef5508fd66,
        0x0000000000000000000000000000000000d48f6c43c5930f3d70d6db09a48f4a,
        0x0000000000000000000000000000000000e7f72b2c0756704bea85be38352b34,
        0x00000000000000000000000000000000000000000000000000000000b05d5ac5,
        0,
    ];

    let y = BN254_Fq { limbs: [0x1, 0x1, 0x0] };
    let z = BN254_Fq { limbs: [0x2, 0x2, 0x0] };
    // Safety: test code
    let yy = unsafe { y.__add(y) };

    assert(yy.limbs == z.limbs);

    let uu = BN254_Fq {
        limbs: [
            0x0000000000000000000000000000000000b4a832748da6ad742a1fd81b787643,
            0x00000000000000000000000000000000009575f594e04080471712c1d7f18e89,
            0x000000000000000000000000000000000000000000000000000000000000063,
        ],
    };
    let vv = BN254_Fq {
        limbs: [
            0x0000000000000000000000000000000000b4aec2748da6ad742a1fd81b787643,
            0x00000000000000000000000000000000009575f594e0408047171a01d7f18e89,
            0x0000000000000000000000000000000000000000000000000000000000000062,
        ],
    };
    let w = BN254_Fq {
        limbs: [
            0x0000000000000000000000000000000000b4a832748da6ad742a1fd81b787643,
            0x00000000000000000000000000000000009575f594e04080471712c1d7f18e89,
            0x0000000000000000000000000000000000000000000000000000000000001f93,
        ],
    };
    let x = BN254_Fq {
        limbs: [
            0x0000000000000000000000000000000000b4aec2748da6ad742a1fd81b787643,
            0x00000000000000000000000000000000009575f594e0408047171a01d7f18e89,
            0x0000000000000000000000000000000000000000000000000000000000000f93,
        ],
    };
    // Safety: test code
    let wx = unsafe { w.__mul(x) };
    // Safety: test code
    let uv = unsafe { uu.__mul(vv) };
    // Safety: test code
    let y = unsafe { (uv.__add(wx)).__neg() };
    // Safety: test code
    let z = unsafe { uv.__add(wx) };

    BigNum::evaluate_quadratic_expression(
        [[uu], [w]],
        [[false], [false]],
        [[vv], [x]],
        [[false], [false]],
        [z],
        [true],
    );
    BigNum::evaluate_quadratic_expression(
        [[uu], [w]],
        [[false], [false]],
        [[vv], [x]],
        [[false], [false]],
        [y],
        [false],
    );

    let wx_constrained = w * x;
    assert(wx_constrained.limbs == wx.limbs);
}

#[test]
fn test_from_field_1_digit() {
    let field: Field = 1;
    let result = BN254_Fq::from(field);
    assert(result == BN254_Fq::one());
}

#[test]
fn test_from_field_2_digits() {
    let field: Field = 762576765071760201410184025311678064293966151975347778787092903729041075;
    let result = BN254_Fq::from(field);
    let expected: BN254_Fq =
        BigNum { limbs: [0xe88ed97f8f707abd3fa65763c80eb3, 0x6e7d8b5586595aa1fb2ee04d5cb4f5, 0x0] };
    assert(result == expected);
}

#[test]
fn test_from_field_3_digits() {
    let field: Field = -1;
    let result = BN254_Fq::from(field);
    let expected = BN254_Fq {
        limbs: [0x33e84879b9709143e1f593f0000000, 0x4e72e131a029b85045b68181585d28, 0x3064],
    };
    assert(result == expected);
}

#[test]
fn test_do_nothing() {
    let a: BN254_Fq = BN254_Fq { limbs: [1, 2, 0] };
    let b: BN254_Fq = BN254_Fq { limbs: [1, 2, 0] };
    // Safety: test code
    let c = unsafe { __helper_add(a.limbs, b.limbs) };
    // Safety: test code
    let d = unsafe { a.__add(b) };
    let e = a + b;
    assert(c == d.limbs);
    assert(c == e.limbs);
}

#[test]
fn test_from_field_3_digits_BLS381() {
    let field: Field = -1;
    let result = BLS12_381_Fq::from(field);
    let expected = BLS12_381_Fq {
        limbs: [0x33e84879b9709143e1f593f0000000, 0x4e72e131a029b85045b68181585d28, 0x3064, 0x0],
    };
    assert(result == expected);
}

#[test]
fn test_to_field_one() {
    let field: Field = 1;
    let bn = BN254_Fq::one();
    let result = to_field(bn);
    assert(result == field);
}

#[test]
fn test_to_field_one_digit() {
    let field: Field = 1066513542066841864585910935480267774;
    let bn = BN254_Fq { limbs: [0xcd672d695ef3129e4c40867a7173fe, 0x0, 0x0] };
    let result = to_field(bn);
    assert(result == field);
}

#[test]
fn test_to_field_two_digits() {
    let field: Field = 697955470585821007263499235110798476786097877002667034107578965871052378;
    let bn = BN254_Fq {
        limbs: [0x5a10b956d41840745e0a9f6e34465a, 0x65209b74583b912262843211905e41, 0x0],
    };
    let result = to_field(bn);
    assert(result == field);
}

#[test]
fn test_to_field_three_digits() {
    let field: Field = 2330301921655783950764183713945533646391233209687308929386184468126823563744;
    let bn = BN254_Fq {
        limbs: [0x862cf8ea69d6c70c9cc8d8871b41e0, 0xe7763528201566c2fc8d93973cf1b4, 0x526],
    };
    let result = to_field(bn);
    assert(result == field);
}

#[test(should_fail_with = "BigNum::validate_gt check fails")]
fn test_to_field_three_digits_overflow() {
    let bn = BN254_Fq {
        limbs: [0x4e6405505a33bb9b9c0563df2bd59a, 0x48dbe03a9bb4865ba961e41ef9dded, 0x3a36],
    };
    let _ = to_field(bn);
}

#[test(should_fail_with = "BigNum::validate_gt check fails")]
fn test_to_field_too_many_digits() {
    let bn = BLS12_381_Fq {
        limbs: [0xea1742447ee9d92f9f18e1c80a481e, 0x3d89ad3d3ae85f3f482a08435c93ec, 0x1e9f, 0x1],
    };
    let _ = to_field(bn);
}

#[test]
fn test_from_to_field_1() {
    let a = 20192735083400333763152317277081729935089452774154199134677444560763605803197;
    let b = BN254_Fq::from(a);
    let c = to_field(b);
    assert(c == a);
}

#[test]
fn test_from_to_field_fuzz(a: Field) {
    let b = BLS12_381_Fq::from(a);
    let c = to_field(b);
    assert(c == a);
}

#[test]
fn test_to_from_field_1() {
    let a = BN254_Fq {
        limbs: [0x3c768db7732ea1b536c06ae66bce70, 0xb9936c1401d91e7e9e1138375650b4, 0x8c8],
    };
    let b = to_field(a);
    let c = BN254_Fq::from(b);
    assert(a == c);
}

#[test]
fn test_to_from_field_2() {
    let a = BLS12_381_Fq {
        limbs: [0xd7562bf2b1fe13d458685c96a46d28, 0x2079950acd45bb43a9beeba69d5dc9, 0x18ca, 0x0],
    };
    let b = to_field(a);
    let c = BLS12_381_Fq::from(b);
    assert(a == c);
}

unconstrained fn test_batch_inversion<let N: u32, BN>(fields: [BN; N])
where
    BN: BigNumTrait,
{
    let inverted_fields = BN::__batch_invert(fields);
    for i in 0..N {
        assert_eq(fields[i] * inverted_fields[i], BN::one());
    }
}

#[test]
unconstrained fn test_batch_inversion_BN381(seeds: [[u8; 2]; 3]) {
    let fields = seeds.map(|seed| BLS12_381_Fq::derive_from_seed(seed));
    test_batch_inversion(fields)
}

unconstrained fn test_batch_inversion_slice<BN>(fields: [BN])
where
    BN: BigNumTrait,
{
    let inverted_fields = BN::__batch_invert_slice(fields);
    assert_eq(fields.len(), inverted_fields.len());
    for i in 0..fields.len() {
        assert_eq(fields[i] * inverted_fields[i], BN::one());
    }
}

#[test]
unconstrained fn test_batch_inversion_slice_BN381(seeds: [[u8; 2]; 3]) {
    let fields = seeds.map(|seed| BLS12_381_Fq::derive_from_seed(seed)).as_slice();
    test_batch_inversion_slice(fields)
}

#[test]
unconstrained fn test_batch_inversion_BN381_regression(seeds: [[u8; 2]; 5]) {
    let fields = seeds.map(|seed| BLS12_381_Fr::derive_from_seed(seed));
    test_batch_inversion(fields)
}

#[test]
fn test_sub_underflow_regression() {
    let limbs = [605231426910671071918217543292637230, 925169190305713195541137574269511054, 4915];
    let a = BLS12_381_Fr { limbs: limbs };
    let b = BLS12_381_Fr { limbs: limbs };
    let c = b - a;
    assert(c.limbs == [0, 0, 0]);
}

#[test]
fn test_cmp_BN() {
    let mut a: BN254_Fq = BigNum::modulus();
    let mut b: BN254_Fq = BigNum::modulus();

    a.limbs[0] -= 2;
    b.limbs[0] -= 1;

    assert(a < b);
}

#[test(should_fail_with = "Failed constraint")]
fn test_cmp_BN_fail() {
    let mut a: BN254_Fq = BigNum::modulus();
    let mut b: BN254_Fq = BigNum::modulus();

    a.limbs[0] -= 1;
    b.limbs[0] -= 2;

    assert(a < b);
}

#[test]
fn test_cmp_BN_2() {
    let mut a: BN254_Fq = BigNum::modulus();
    let mut b: BN254_Fq = BigNum::modulus();

    a.limbs[0] -= 1;
    b.limbs[0] -= 2;

    assert(a > b);
}

#[test(should_fail_with = "Failed constraint")]
fn test_cmp_BN_fail_2() {
    let mut a: BN254_Fq = BigNum::modulus();
    let mut b: BN254_Fq = BigNum::modulus();

    a.limbs[0] -= 2;
    b.limbs[0] -= 1;

    assert(a > b);
}

#[test]
fn test_cmp_BN_fuzz(seed: [u8; 5]) {
    let mut a: BN254_Fq = BigNum::derive_from_seed(seed);
    let modulus_sub_1_div_2 = (BN254_Fq::modulus() - BN254_Fq::one()) / BN254_Fq::from(2);

    a = if a > modulus_sub_1_div_2 { -a } else { a };
    assert(a < modulus_sub_1_div_2);
}
