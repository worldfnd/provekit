use crate::fns::constrained_ops::{sub, udiv};
use crate::fns::unconstrained_helpers::__barrett_reduction;
use crate::params::{BigNumParams, BigNumParamsGetter};
use crate::runtime_bignum::RuntimeBigNum;

use crate::fields::bn254Fq::BN254_Fq_Params;

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

pub(crate) struct Test2048Params {}

// See https://github.com/noir-lang/noir/issues/6172
#[test]
fn silence_warning() {
    let _ = Test2048Params {};
}

impl BigNumParamsGetter<18, 2048> for Test2048Params {
    fn get_params() -> BigNumParams<18, 2048> {
        TEST_2048_PARAMS
    }
}

/**
 * @brief experimenting with macro madness and code generation to make some tests that apply to multiple BigNum parametrisations!
 **/
comptime fn make_test(_m: Module, N: u32, MOD_BITS: u32, typ: Quoted) -> Quoted {
    let RuntimeBigNum = quote { crate::RuntimeBigNum };
    let __helper_add = quote { crate::fns::unconstrained_helpers::__helper_add };
    let __helper_sub = quote { crate::fns::unconstrained_helpers::__helper_sub };
    let __one = quote { crate::fns::unconstrained_ops::__one };
    let __shl = quote { crate::fns::unconstrained_helpers::__shl };
    let udiv = quote { crate::fns::constrained_ops::udiv };
    let sub = quote { crate::fns::constrained_ops::sub };
    quote {
#[test]
fn test_add() {
    let params = $typ ::get_params();
    
    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [4, 5, 6, 7]);
    let one: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::one(params);
    a.validate_in_range();
    a.validate_in_field();
    b.validate_in_range();
    b.validate_in_field();
    let mut c = a + b;
    
    c = c + c;
    
    let d = (a + b) * (one + one);
    assert(c == d);

    let e = one + one;
    for i in 1..$N {
        assert(e.limbs[i] == 0);
    }
    assert(e.limbs[0] == 2);
}

#[test]
fn test_sub() {
    let params = $typ ::get_params();

    // 0 - 1 should equal p - 1
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::zero(params);
    let mut b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::one(params);
    let mut expected: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: params.modulus, params };

    expected.limbs[0] -= 1; // p - 1

    let result = a - b;
    assert(result == expected);
}


#[test]
fn test_sub_modulus_limit() {
    let params = $typ ::get_params();
    // if we underflow, maximum result should be ...
    // 0 - 1 = o-1
    // 0 - p = 0
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::zero(params);
    let mut b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: params.modulus, params };
    let mut expected: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::zero(params);

    let result = a - b;
    assert(result == expected);
}


#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_sub_modulus_underflow() {
    let params = $typ ::get_params();

    // 0 - (p + 1) is smaller than p and should produce unsatisfiable constraints
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::zero(params);
    let mut b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: params.modulus, params };
    b.limbs[0] += 1;
    let mut expected: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::one(params);

    let result = a - b;

    assert(result == expected);
}

#[test]
fn test_add_modulus_limit() {
    let params = $typ ::get_params();

    // p + 2^{modulus_bits()} - 1 should be the maximum allowed value fed into an add operation
    // when adding, if the result overflows the modulus, we conditionally subtract the modulus, producing 2^{254} -  1
    // this is the largest value that will satisfy the range check applied when constructing a bignum
    let p: [u128; $N] = params.modulus;
    let one: [u128; $N] = [1; $N];

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: p, params };

    // Safety: test code
    let two_pow_modulus_bits_minus_one: [u128; $N] =  unsafe { $__helper_sub($__shl(one, $MOD_BITS), one) };

    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: two_pow_modulus_bits_minus_one, params };
    let result = a + b;
    assert(result == b);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_add_modulus_overflow() {
    let params = $typ ::get_params();

    let p: [u128; $N] = params.modulus;
    // Safety: test code
    let one = unsafe{$__one()};

    // Safety: test code
    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: unsafe { $__helper_add(p, one) }, params };

    // Safety: test code
    let mut two_pow_modulus_bits_minus_one: [u128; $N] =  unsafe { $__helper_sub($__shl(one, $MOD_BITS), one) };

    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: two_pow_modulus_bits_minus_one, params };
    let result = a + b;
    assert(result == b);
}

#[test]
fn test_mul() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [4, 5, 6, 7]);

    let c = (a + b) * (a + b);
    let d = (a * a) + (b * b) + (a * b) + (a * b);
    assert(c == d);
}

#[test]
fn test_quadratic_expression() {
    let params = $typ ::get_params();

    for i in 0..32 {
        let X1: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [i as u8, 2, 3, 4]);
        let Y1: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [i as u8, i as u8, 6, 7]);
        let Z1: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::one(params);

        let (_, YY_mul_2): ($RuntimeBigNum<$N, $MOD_BITS>, $RuntimeBigNum<$N, $MOD_BITS>) = $RuntimeBigNum::__compute_quadratic_expression(params, [[Y1]], [[false]], [[Y1, Y1]], [[false, false]], [], []);
        let mut (_, XX_mul_3): ($RuntimeBigNum<$N, $MOD_BITS>, $RuntimeBigNum<$N, $MOD_BITS>) = $RuntimeBigNum::__compute_quadratic_expression(
            params,
            [[X1]],
            [[false]],
            [[X1, X1, X1]],
            [[false, false, false]],
            [],
            []
        );
        let (_, D): ($RuntimeBigNum<$N, $MOD_BITS>, $RuntimeBigNum<$N, $MOD_BITS>) = $RuntimeBigNum::__compute_quadratic_expression(params, [[X1, X1]], [[false, false]], [[YY_mul_2]], [[false]], [], []);
        let mut (_, X3) =  $RuntimeBigNum::__compute_quadratic_expression(
            params,
            [[XX_mul_3]],
            [[false]],
            [[XX_mul_3]],
            [[false]],
            [D, D],
            [true, true]
        );
        let (_, Y3): ($RuntimeBigNum<$N, $MOD_BITS>, $RuntimeBigNum<$N, $MOD_BITS>) = $RuntimeBigNum::__compute_quadratic_expression(
            params,
            [[XX_mul_3], [YY_mul_2]],
            [[false], [true]],
            [[D, X3], [YY_mul_2, YY_mul_2]],
            [[false, true], [false, false]],
            [],
            []
        );
        // 3XX * (D - X3) - 8YYYY

        let (_, Z3): ($RuntimeBigNum<$N, $MOD_BITS>, $RuntimeBigNum<$N, $MOD_BITS>) = $RuntimeBigNum::__compute_quadratic_expression(params, [[Y1]], [[false]], [[Z1, Z1]], [[false, false]], [], []);

        X3.validate_in_field();
        Y3.validate_in_field();
        Z3.validate_in_field();
    }
}

#[test]
fn assert_is_not_equal() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [4, 5, 6, 7]);

    a.assert_is_not_equal(b);
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn assert_is_not_equal_fail() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);

    a.assert_is_not_equal(b);
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn assert_is_not_equal_overloaded_lhs_fail() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);

    let modulus = params.modulus;

    let t0: [u128; $N] = a.limbs;
    let t1: [u128; $N] = modulus;
    // Safety: test code
    let a_plus_modulus: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: unsafe { $__helper_add(t0, t1) }, params };

    a_plus_modulus.assert_is_not_equal(b);
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn assert_is_not_equal_overloaded_rhs_fail() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);

    let modulus = params.modulus;

    let t0: [u128; $N] = b.limbs;
    let t1: [u128; $N] = modulus;
    // Safety: test code
    let b_plus_modulus: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: unsafe { $__helper_add(t0, t1) }, params };

    a.assert_is_not_equal(b_plus_modulus);
}

#[test(should_fail_with = "asssert_is_not_equal fail")]
fn assert_is_not_equal_overloaded_fail() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);

    let modulus = params.modulus;

    let t0: [u128; $N] = a.limbs;
    let t1: [u128; $N] = b.limbs;
    let t2: [u128; $N] = modulus;

    // Safety: test code
    let a_plus_modulus: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: unsafe { $__helper_add(t0, t2) }, params };
    // Safety: test code
    let b_plus_modulus: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: unsafe { $__helper_add(t1, t2) }, params };

    a_plus_modulus.assert_is_not_equal(b_plus_modulus);
}

#[test]
fn test_derive()
{
    let params = $typ ::get_params();

    // let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, "hello".as_bytes());
    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    assert_eq(a, b);
}

#[test]
fn test_eq() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let c: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [2, 2, 3, 4]);

    let modulus = a.modulus();

    let t0: [u128; $N] = modulus.limbs;
    let t1: [u128; $N] = b.limbs;

    // Safety: test code
    let b_plus_modulus: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: unsafe { $__helper_add(t0, t1) }, params };

    assert_eq(a, b);
    assert_eq(a, b_plus_modulus);
    assert(!(c == b));
    assert(!(c == a));
}

#[test]
fn test_is_zero() {
    let params = $typ ::get_params();

    let a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::zero(params);
    let b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);

    assert(a.is_zero() == true);
    assert(b.is_zero() == false);
}

#[test]
fn test_cmp() {
    let modulus = $typ ::get_params().modulus;
    let params = $typ ::get_params();
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };
    let mut b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };

    a.limbs[0] -= 1;
    b.limbs[0] -= 2;
    assert(a > b);
}

#[test(should_fail_with = "Failed constraint")]
fn test_cmp_BN_fail() {
    let modulus = $typ ::get_params().modulus;
    let params = $typ ::get_params();
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };
    let mut b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };

    a.limbs[0] -= 1;
    b.limbs[0] -= 2;

    assert(a < b);
}


#[test]
fn test_cmp_BN_2() {
    let modulus = $typ ::get_params().modulus;
    let params = $typ ::get_params();
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };
    let mut b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };

    a.limbs[0] -= 1;
    b.limbs[0] -= 2;

    assert(a > b);
}

#[test(should_fail_with = "Failed constraint")]
fn test_cmp_BN_fail_2() {
    let modulus = $typ ::get_params().modulus;
    let params = $typ ::get_params();
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };
    let mut b: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum { limbs: modulus, params };

    a.limbs[0] -= 2;
    b.limbs[0] -= 1;

    assert(a > b);
}

#[test]
fn test_cmp_fuzz(seed: [u8; 2]){
    let params = $typ ::get_params();
    let modulus = params.modulus;
    let mut a: $RuntimeBigNum<$N, $MOD_BITS> = $RuntimeBigNum::derive_from_seed(params, seed);
    let mut half_modulus = $RuntimeBigNum::zero(params);
    let mut two = [0; $N]; 
    two[0] = 2;
    let mut one = [0; $N];
    one[0] = 1;
    if modulus[0] % 2 == 0 {
        // if modulus is even, half_modulus is modulus / 2
        half_modulus = $RuntimeBigNum {limbs: $udiv(params, modulus, two), params};
    } else {
        // if modulus is odd, half_modulus is (modulus - 1) / 2
        half_modulus = $RuntimeBigNum {limbs: $udiv(params, $sub(params,modulus, one), two), params};
    }


    a = if a > half_modulus {
        - a 
    } else {
        a
    }; 
    assert(a < half_modulus);
}


}
}

#[make_test(3, 254, quote {crate::fields::bn254Fq::BN254_Fq_Params})]
pub mod BNTests {
    use crate::params::BigNumParamsGetter;
}

#[make_test(3, 256, quote {crate::fields::secp256k1Fq::Secp256k1_Fq_Params})]
pub mod Secp256K1FqTests {
    use crate::params::BigNumParamsGetter;
}

#[make_test(4, 381, quote {crate::fields::bls12_381Fq::BLS12_381_Fq_Params})]
pub mod BLS12_381FqTests {
    use crate::params::BigNumParamsGetter;
}

#[make_test(18, 2048, quote {super::Test2048Params})]
pub mod Test2048Tests {
    use crate::params::BigNumParamsGetter;
}

#[make_test(3, 255, quote {crate::fields::bls12_381Fr::BLS12_381_Fr_Params})]
pub mod BLS12_381_Fr_ParamsTests {
    use crate::params::BigNumParamsGetter;
}

#[make_test(4, 377, quote {crate::fields::bls12_377Fq::BLS12_377_Fq_Params})]
pub mod BLS12_377_Fq_ParamsTests {
    use crate::params::BigNumParamsGetter;
}

#[make_test(3, 253, quote {crate::fields::bls12_377Fr::BLS12_377_Fr_Params})]
pub mod BLS12_377_Fr_ParamsTests {
    use crate::params::BigNumParamsGetter;
}

// 98760
// 99689
// 929 gates for a 2048 bit mul

fn test_div<let N: u32, let MOD_BITS: u32>(params: BigNumParams<N, MOD_BITS>) {
    let a: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    let b: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::derive_from_seed(params, [4, 5, 6, 7]);

    let c = a / b;
    assert((b * c) == a);
}

unconstrained fn test_invmod<let N: u32, let MOD_BITS: u32>(params: BigNumParams<N, MOD_BITS>) {
    let u: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::derive_from_seed(params, [1, 2, 3, 4]);
    for _ in 0..1 {
        let v = u.__invmod();
        let result = u.__mul(v);
        let expected: RuntimeBigNum<N, MOD_BITS> = RuntimeBigNum::one(params);
        assert(result.limbs == expected.limbs);
    }
}

#[test]
fn test_div_BN() {
    let params = BN254_Fq_Params::get_params();
    test_div(params);
}

#[test]
fn test_invmod_BN() {
    let params = BN254_Fq_Params::get_params();
    // Safety: test code
    unsafe { test_invmod(params) };
}

// N.B. witness generation times make these tests take ~15 minutes each! Uncomment at your peril
// #[test]
// fn test_div_2048() {
// let params = get_2048_params();
//     test_div(params);
// }

// N.B. witness generation times make these tests take ~15 minutes each! Uncomment at your peril
// #[test]
// fn test_invmod_2048() {
// let params = get_2048_params();
//     test_invmod(params);
// }

#[test]
fn test_2048_bit_quadratic_expression() {
    let params = TEST_2048_PARAMS;
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

    let a_bn: RuntimeBigNum<_, 2048> = RuntimeBigNum { limbs: a, params };
    let b_bn: RuntimeBigNum<_, 2048> = RuntimeBigNum { limbs: b, params };
    let c = a_bn * b_bn;
    assert(c.limbs == c_expected);

    a_bn.validate_in_range();

    RuntimeBigNum::evaluate_quadratic_expression(
        params,
        [[a_bn]],
        [[false]],
        [[b_bn]],
        [[false]],
        [c],
        [true],
    );
}

#[test]
fn test_sqrt_BN() {
    let params = BN254_Fq_Params::get_params();

    let x = RuntimeBigNum { limbs: [9, 0, 0], params };

    let maybe_sqrt_x = x.__tonelli_shanks_sqrt();

    let sqrt_x = maybe_sqrt_x.unwrap();

    assert(sqrt_x * sqrt_x == x);
}

// N.B. this test is only here to check that the barrett reduction is working correctly
//      a bug was introduced in 0.3.7 that caused issues with the RSA library
//      this test is to check that the bug is fixed
#[test]
fn test_barrett_reduction_fix() {
    // the parameters and input that the barrett reduction fails on in the RSA library
    let params: BigNumParams<9, 1024> = BigNumParams::new(
        false,
        [
            0xab238ad9cb37979a43aefbf10be8fb,
            0x31347febe45fe8c2dac1dd30900704,
            0xa5a9a6b9cd0cc2b9d13bbd4e068263,
            0x5eac6390f7873fe97ff9bb14a173ea,
            0xbc41f700c91fd733a2c63177bbdbd4,
            0x41442bd58769a3595b659a2ec9c6be,
            0x4ddc91395f330382aa2e2d3fbe147,
            0x3d008ff255a0bc71c7887f5728ba1,
            0xb640c3a8f511c64e,
        ],
        [
            0x5d53d2634c6a0918266043968ce263,
            0x5dd4be3dce0323a492ee9340aec4db,
            0xf82d0e2e5c8319f01a460c72c01854,
            0x236e6fc6e62e8a1d522acda5fb3892,
            0xdaf755619d66e580901aa224d03174,
            0x8366291616480e7e1f202dbcedda87,
            0x40ba1202537d1e94561ccc05265586,
            0x69b993d857ba89ea5de9822aeb4b93,
            0x167968c0000761a273,
        ],
    );
    let to_reduce: [u128; 18] = [
        0xc4b8aacb43f12eb7f3f356ca26fb91,
        0xfc57d87e81f39810ffb63957395499,
        0x8308e90fc38cfe95d2a0f7ab577c17,
        0xa08ec48b11c8f8106bf59274163f0e,
        0x31d13967c472c9a02fc8099199432c,
        0x8b9ed833878dcb05c9dd19b917fb56,
        0xadd411af43c4dc57d5e1e50800a644,
        0x9075bad2ae6053c55d96ae819c6dfe,
        0xebe4650d4f5449bbdd48b322ec0c65,
        0xf17bc78e881061f738f27e058be410,
        0x1a6d1af41bdb753888b2757986a131,
        0x06dc4cf83a7ceebe8e996e4329c63a,
        0xf64759a546537a899c8e2e7ea745fb,
        0x253f1a623444aa404f989ca5843cf7,
        0x65728e80aa429c676336b3a0613188,
        0x189d0a1000d5b3755d91e0455137fe,
        0x17f512a1cf7cc3470fc054743ceafe,
        0x05,
    ];

    // Safety: test code
    let (_quotient, remainder) =
        unsafe { __barrett_reduction(to_reduce, params.redc_param, 1024, params.modulus) };
    assert((remainder[8] as Field).lt(params.modulus[8] as Field));
}
