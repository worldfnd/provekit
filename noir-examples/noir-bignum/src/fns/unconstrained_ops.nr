use crate::fns::constrained_ops::derive_from_seed;
use crate::fns::unconstrained_helpers::{
    __barrett_reduction, __get_bit, __get_msb, __helper_add, __helper_sub, __increment,
    __multiplicative_generator, __primitive_root_log_size, __shl, __shr,
    __tonelli_shanks_sqrt_inner_loop_check,
};
use crate::params::BigNumParams as P;
use crate::utils::split_bits;
use super::unconstrained_helpers::__shr1;

pub(crate) unconstrained fn __one<let N: u32>() -> [u128; N] {
    let mut limbs: [u128; N] = [0; N];
    limbs[0] = 1;
    limbs
}

/// Deterministically derives a big_num from a seed value.
///
/// Takes a seed byte array and generates a big_num in the range [0, modulus-1].
///
/// ## Value Parameters
///
/// - `params`: The BigNum parameters containing modulus and reduction info
/// - `seed`:  Input seed bytes to derive from.
///
/// ## Returns
///
///  An array of field elements derived from the seed (the limbs of the big_num)
pub(crate) unconstrained fn __derive_from_seed<let N: u32, let MOD_BITS: u32, let SeedBytes: u32>(
    params: P<N, MOD_BITS>,
    seed: [u8; SeedBytes],
) -> [u128; N] {
    let out = derive_from_seed::<N, MOD_BITS, SeedBytes>(params, seed);
    out
}

pub(crate) unconstrained fn __eq<let N: u32>(lhs: [u128; N], rhs: [u128; N]) -> bool {
    lhs == rhs
}

pub(crate) unconstrained fn __is_zero<let N: u32>(limbs: [u128; N]) -> bool {
    let mut result: bool = true;
    for i in 0..N {
        result = result & (limbs[i] == 0);
    }

    result
}

/**
* @brief given an input `x`, compute `2p - x` (unconstrained)
*
* @description we subtract the input from double the modulus, because all constrained BigNum operations
*              only guarantee that the output is in the range [0, ceil(log2(p))].
*              I.E. the input may be larger than the modulus `p`.
*              In order to ensure this operation does not underflow, we compute `2p - x` instead of `p - x`.
*              N.B. constrained BigNum operations do not fully constrain outputs to be in the range [0, p-1]
*              because such a check is expensive and usually unneccesary.
*/
pub(crate) unconstrained fn __neg<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    limbs: [u128; N],
) -> [u128; N] {
    let f: [u128; N] = limbs;
    __helper_sub(params.modulus, f)
}

pub(crate) unconstrained fn __add<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    lhs: [u128; N],
    rhs: [u128; N],
) -> [u128; N] {
    let mut result: [u128; N] = [0; N];
    let mut carry: u128 = 0;
    for i in 0..N {
        let mut add_term = (lhs[i] + rhs[i] + carry);
        carry = add_term >> 120;
        add_term = add_term - (carry << 120);
        result[i] = add_term;
    }
    // check if the result is greater than the modulus
    if __gte(result, params.modulus) {
        __helper_sub(result, params.modulus)
    } else {
        result
    }
}

/**
* @brief given inputs `x, y` compute 2p + x - y (unconstrained)
* @description see `__neg` for why we use 2p instead of p
**/
pub(crate) unconstrained fn __sub<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    lhs: [u128; N],
    rhs: [u128; N],
) -> [u128; N] {
    __add(params, lhs, __neg(params, rhs))
}

pub(crate) unconstrained fn __mul_with_quotient<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    lhs: [u128; N],
    rhs: [u128; N],
) -> ([u128; N], [u128; N]) {
    let mut mul: [Field; 2 * N] = [0; 2 * N];
    for i in 0..N {
        for j in 0..N {
            mul[i + j] += (lhs[i] as Field * rhs[j] as Field);
        }
    }
    let to_reduce: [u128; (N * 2)] = split_bits::__normalize_limbs(mul, 2 * N);
    let (q, r) = __barrett_reduction(to_reduce, params.redc_param, MOD_BITS, params.modulus);
    // ([0; N], [0; N])
    (q, r)
}

pub(crate) unconstrained fn __mul<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    lhs: [u128; N],
    rhs: [u128; N],
) -> [u128; N] {
    let (_, b) = __mul_with_quotient::<_, MOD_BITS>(params, lhs, rhs);
    b
}

pub(crate) unconstrained fn __div<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    numerator: [u128; N],
    divisor: [u128; N],
) -> [u128; N] {
    let inv_divisor: [u128; N] = __invmod::<_, MOD_BITS>(params, divisor);
    __mul::<_, MOD_BITS>(params, numerator, inv_divisor)
}

/**
* @brief __udiv_mod performs *unconstrained* integer division between numerator, divisor 
*
* i.e. 1. floor(numerator / divisor) = quotient
*      2. numerator % divisor = remainder
*      3. divisor * quotient + remainder = numerator
**/
pub(crate) unconstrained fn __udiv_mod<let N: u32>(
    numerator: [u128; N],
    divisor: [u128; N],
) -> ([u128; N], [u128; N]) {
    let mut quotient: [u128; N] = [0; N];
    let mut remainder: [u128; N] = numerator;

    let b = divisor;
    let numerator_msb = __get_msb(numerator);
    let divisor_msb = __get_msb(divisor);
    if divisor_msb > numerator_msb {
        ([0; N], numerator)
    } else {
        let mut bit_difference = __get_msb(remainder) - __get_msb(divisor);
        let mut accumulator: [u128; N] = __one();
        let mut divisor = __shl(divisor, bit_difference);
        accumulator = __shl(accumulator, bit_difference);

        if (__gte(divisor, __increment(remainder))) {
            divisor = __shr1(divisor);
            accumulator = __shr1(accumulator);
        }

        for _ in 0..(N * 120) {
            if (__gte(remainder, b) == false) {
                break;
            }
            // we've shunted 'divisor' up to have the same bit length as our remainder.
            // If remainder >= divisor, then a is at least '1 << bit_difference' multiples of b
            if (__gte(remainder, divisor)) {
                remainder = __helper_sub(remainder, divisor);
                // we can use OR here instead of +, as
                // accumulator is always a nice power of two
                quotient = __helper_add(quotient, accumulator);
            }
            divisor = __shr1(divisor); // >>= 1;
            accumulator = __shr1(accumulator); //  >>= 1;
        }

        (quotient, remainder)
    }
}

pub(crate) unconstrained fn __invmod<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    val: [u128; N],
) -> [u128; N] {
    let one = __one();
    let exp = __helper_sub(params.modulus, __helper_add(one, one));
    __pow::<_, MOD_BITS>(params, val, exp)
}

pub(crate) unconstrained fn __pow<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    val: [u128; N],
    exponent: [u128; N],
) -> [u128; N] {
    let x = exponent;
    let num_bits = MOD_BITS + 1;

    let mut accumulator: [u128; N] = __one::<N>();

    for i in 0..num_bits {
        accumulator = __mul::<_, MOD_BITS>(params, accumulator, accumulator);
        if __get_bit(x, num_bits - i - 1) {
            accumulator = __mul::<_, MOD_BITS>(params, accumulator, val);
        }
    }
    accumulator
}

pub(crate) unconstrained fn __batch_invert<let N: u32, let MOD_BITS: u32, let M: u32>(
    params: P<N, MOD_BITS>,
    x: [[u128; N]; M],
) -> [[u128; N]; M] {
    // TODO: ugly! Will fail if input slice is empty

    let mut accumulator: [u128; N] = __one::<N>();
    let mut temporaries: [[u128; N]; M] = std::mem::zeroed();

    for i in 0..M {
        temporaries[i] = accumulator;
        if (!__is_zero(x[i])) {
            accumulator = __mul::<_, MOD_BITS>(params, accumulator, x[i]);
        }
    }

    let mut result: [[u128; N]; M] = [[0; N]; M];
    accumulator = __invmod::<_, MOD_BITS>(params, accumulator);
    for i in 0..M {
        let idx = M - 1 - i;
        if (!__is_zero(x[idx])) {
            let T0 = __mul::<_, MOD_BITS>(params, accumulator, temporaries[idx]);
            accumulator = __mul::<_, MOD_BITS>(params, accumulator, x[idx]);
            result[idx] = T0;
        }
    }
    result
}

pub(crate) unconstrained fn __batch_invert_slice<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    x: [[u128; N]],
) -> [[u128; N]] {
    // TODO: ugly! Will fail if input slice is empty
    let mut accumulator: [u128; N] = __one::<N>();
    let mut temporaries: [[u128; N]] = &[];
    for i in 0..x.len() {
        temporaries = temporaries.push_back(accumulator);
        if (!__is_zero(x[i])) {
            accumulator = __mul::<_, MOD_BITS>(params, accumulator, x[i]);
        }
    }

    let mut result: [[u128; N]] = [];
    accumulator = __invmod::<_, MOD_BITS>(params, accumulator);
    for i in 0..x.len() {
        let idx = x.len() - 1 - i;
        if (!__is_zero(x[idx])) {
            let T0 = __mul::<_, MOD_BITS>(params, accumulator, temporaries[idx]);
            accumulator = __mul::<_, MOD_BITS>(params, accumulator, x[idx]);
            result = result.push_front(T0);
        } else {
            result = result.push_front([0; N]);
        };
    }

    result
}

/**
* @brief compute a modular square root using the Tonelli-Shanks algorithm
* @details only use for prime fields! Function may infinite loop if used for non-prime fields
* @note this is unconstrained fn. To constrain a square root, validate that output^2 = self
* TODO: create fn that constrains nonexistence of square root (i.e. find x where x^2 = -self)
**/
pub(crate) unconstrained fn __tonelli_shanks_sqrt<let N: u32, let MOD_BITS: u32>(
    params: P<N, MOD_BITS>,
    input: [u128; N],
) -> std::option::Option<[u128; N]> {
    // Tonelli-shanks algorithm begins by finding a field element Q and integer S,
    // such that (p - 1) = Q.2^{s}
    // We can compute the square root of a, by considering a^{(Q + 1) / 2} = R
    // Once we have found such an R, we have
    // R^{2} = a^{Q + 1} = a^{Q}a
    // If a^{Q} = 1, we have found our square root.
    // Otherwise, we have a^{Q} = t, where t is a 2^{s-1}'th root of unity.
    // This is because t^{2^{s-1}} = a^{Q.2^{s-1}}.
    // We know that (p - 1) = Q.w^{s}, therefore t^{2^{s-1}} = a^{(p - 1) / 2}
    // From Euler's criterion, if a is a quadratic residue, a^{(p - 1) / 2} = 1
    // i.e. t^{2^{s-1}} = 1
    // To proceed with computing our square root, we want to transform t into a smaller subgroup,
    // specifically, the (s-2)'th roots of unity.
    // We do this by finding some value b,such that
    // (t.b^2)^{2^{s-2}} = 1 and R' = R.b
    // Finding such a b is trivial, because from Euler's criterion, we know that,
    // for any quadratic non-residue z, z^{(p - 1) / 2} = -1
    // i.e. z^{Q.2^{s-1}} = -1
    // => z^Q is a 2^{s-1}'th root of -1
    // => z^{Q^2} is a 2^{s-2}'th root of -1
    // Since t^{2^{s-1}} = 1, we know that t^{2^{s - 2}} = -1
    // => t.z^{Q^2} is a 2^{s - 2}'th root of unity.
    // We can iteratively transform t into ever smaller subgroups, until t = 1.
    // At each iteration, we need to find a new value for b, which we can obtain
    // by repeatedly squaring z^{Q}
    let one = __one();
    let primitive_root_log_size = __primitive_root_log_size::<_, MOD_BITS>(params);
    let Q = __shr(
        __helper_sub(params.modulus, one),
        primitive_root_log_size - 1,
    );
    let two = __helper_add(one, one);
    let Q_minus_one_over_two = __shr(__helper_sub(Q, two), 2);
    let mut z = __multiplicative_generator::<_, MOD_BITS>(params); // the generator is a non-residue
    let mut b = __pow::<_, MOD_BITS>(params, input, Q_minus_one_over_two);
    let mut r = __mul::<_, MOD_BITS>(params, input, b);
    let mut t = __mul::<_, MOD_BITS>(params, r, b);
    let mut check: [u128; N] = t;
    for _ in 0..primitive_root_log_size - 1 {
        check = __mul::<_, MOD_BITS>(params, check, check);
    }
    let mut result = Option::none();
    if (__eq(check, one)) {
        let mut t1 = __pow::<_, MOD_BITS>(params, z, Q_minus_one_over_two);
        let mut t2 = __mul::<_, MOD_BITS>(params, t1, z);
        let mut c = __mul::<_, MOD_BITS>(params, t2, t1);
        let mut m: u32 = primitive_root_log_size;
        // tonelli shanks inner 1
        // (if t2m == 1) then skip
        // else increase i and square t2m and go again
        // algorithm runtime should only be max the number of bits in modulus
        for _ in 0..MOD_BITS {
            if (__eq(t, one)) {
                result = Option::some(r);
                break;
            }
            let mut t2m = t;
            // while loop time
            let i = __tonelli_shanks_sqrt_inner_loop_check::<_, MOD_BITS>(params, t2m, 0);
            let mut j = m - i - 1;
            b = c;
            for _ in 0..j {
                // how big
                if (j == 0) {
                    break;
                }
                b = __mul(params, b, b);
                //j -= 1;
            }
            c = __mul::<_, MOD_BITS>(params, b, b);
            t = __mul::<_, MOD_BITS>(params, t, c);
            r = __mul::<_, MOD_BITS>(params, r, b);
            m = i;
        }
    }
    result
}

pub(crate) unconstrained fn __gte<let N: u32, let MOD_BITS: u32>(
    lhs: [u128; N],
    rhs: [u128; N],
) -> bool {
    let mut result = false;
    let mut early_exit = false;
    for i in 0..(N) {
        let idx = (N) - 1 - i;
        if (rhs[idx] == lhs[idx]) {
            continue;
        }

        result = rhs[idx] < lhs[idx];
        early_exit = true;
        break;
    }
    if early_exit {
        result
    } else {
        lhs[0] == rhs[0]
    }
}
