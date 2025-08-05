use crate::utils::split_bits;

use crate::constants::{TWO_POW_32, TWO_POW_38, TWO_POW_70};
use crate::fns::{
    constrained_ops::validate_quotient_in_range, unconstrained_helpers::__barrett_reduction,
};
use crate::params::BigNumParams as P;
use std::ops::{WrappingAdd, WrappingSub};

/**
* @brief Given a degree-2 BigNum expression that is equal to 0 mod p, compute the quotient and borrow flags 
* @description The expression is of the form:
*
* \sum_{i=0}^{NUM_PRODUCTS - 1} ((\sum_{j=0}^{LHS_N-1}lhs[i][j]) * (\sum_{j=0}^{RHS_N-1}rhs[i][j])) + \sum_{i=0}^{ADD_N - 1}linear_terms[i] = quotient * modulus
*
* The intent is to capture an arbitrary degree-2 expression within the limitations of Noir (no efficient dynamically-sized vectors)
*
* When performing BigNum arithmetic, we want to represent desired BigNum operations in a way that minimizes the number of modular reductions that are required.
* This can be achieved by minimizing the number of degree-2 relations required.
*
* The borrow flags describe whether individual Field limbs will underflow when evaluating the above relation.
* For example, when computing the product a * b - q * p = 0, it is possible that:
*      1. a[0]*b[0] - p[0]*q[0] = -2^{120}
*      2. a[0]*b[1] + a[1]*b[0] - p[0]*q[1] - p[1]*q[0] = 1
* In the above example, the value represented by these two limbs is zero despite each limb being nonzero.
* In this case, to correctly constrain the result, we must add (at least) 2^{120} from the first limb and subtract 1 from the second.
*
* @param lhs_terms a 2D array of BigNum
* @param lhs_flags a 2D array of sign flags
* @param rhs_terms a 2D array of BigNum
* @param rhs_flags a 2D array of sign flags
* @param linear_terms an array of BigNum
* @param linear_flags an array of sign flags
**/

unconstrained fn __compute_quadratic_expression_with_borrow_flags<let N: u32, let MOD_BITS: u32, let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
    params: P<N, MOD_BITS>,
    lhs_terms: [[[u64; N]; LHS_N]; NUM_PRODUCTS],
    lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
    rhs_terms: [[[u64; N]; RHS_N]; NUM_PRODUCTS],
    rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
    linear_terms: [[u64; N]; ADD_N],
    linear_flags: [bool; ADD_N],
) -> ([u64; N], [u64; N], [u128; 2 * N - 2]) {
    // TODO, validate we do not overflow N2 when multiplying and N when adding
    let mut mulout_p = __compute_quadratic_expression_product(
        params,
        lhs_terms,
        lhs_flags,
        rhs_terms,
        rhs_flags,
        linear_terms,
        linear_flags,
    );

    let mut mulout_n: [u128; 2 * N] = [0; 2 * N];
    let mut relation_result = split_bits::__normalize_limbs(mulout_p, 2 * N);

    let (quotient, remainder) =
        __barrett_reduction(relation_result, params.redc_param, MOD_BITS, params.modulus);
    assert(remainder == [0 as u64; N]);
    for i in 0..N {
        for j in 0..N {
            mulout_n[i + j] += quotient[i] as u128 * params.modulus[j] as u128;
        }
    }

    // compute borrow flags from mulout_p and mulout_n
    let mut borrow_flags: [u128; 2 * N - 2] = [0; 2 * N - 2];
    let borrow_shift: u128 = TWO_POW_70; // 2^{70}
    let borrow_carry: u128 = TWO_POW_38 as u128; // 2^{70 - 32} = 2^{38}
    let downshift: u128 = 1 / (TWO_POW_32 as u128);

    // determine whether we need to borrow from more significant limbs.
    // initial limb is "simple" comparison operation
    // TODO: check how expensive `lt` operator is w.r.t. witness generation
    borrow_flags[0] = (mulout_p[0] < mulout_n[0]) as u128;
    // we have 2N - 2 borrow flags. The number of limbs from our product computation is 2N - 1
    // and there is nothing to borrow against for the final limb.
    let mut hi_bits = 0;
    if borrow_flags[0] == 1 {
        hi_bits = (mulout_p[0] + ((borrow_flags[0] * borrow_shift) - mulout_n[0])) * downshift;
    } else {
        hi_bits = (mulout_p[0] - mulout_n[0] + (borrow_flags[0] * borrow_shift)) * downshift;
    }
    for i in 1..(N + N - 2) {
        // compute the contribution from limb `i-1` that gets added into limb `i`, and add into limb `i`
        // let hi_bits = (mulout_p.get(i - 1) - mulout_n.get(i - 1) + (borrow_flags.get(i - 1) * borrow_shift))
        //     * downshift;
        mulout_p[i] += hi_bits;

        // determine whether negative limb values are greater than positive limb values
        let underflow: u128 =
            (mulout_p[i] < (mulout_n[i] + (borrow_flags[i - 1] * borrow_carry))) as u128;
        borrow_flags[i] = underflow;

        if underflow == 1 {
            hi_bits = (
                mulout_p[i] + (borrow_flags[i] * borrow_shift - mulout_n[i])
                    - (borrow_flags[i - 1] * borrow_carry)
            )
                * downshift;
        } else {
            hi_bits = (
                mulout_p[i] - mulout_n[i] + (borrow_flags[i] * borrow_shift)
                    - (borrow_flags[i - 1] * borrow_carry)
            )
                * downshift;
        }
    }

    (quotient, remainder, borrow_flags)
}

/**
* @brief Computes the result of a linear combination of (possibly negative) BigNum values (unconstrained)
**/
// NOTE: modulus2 is structured such that all limbs will be greater than 0, even when subtracting.
// To do this, when computing `p - x`, we ensure that each limb in `p` is greater than each limb in `x`.
// We know that, for a valid bignum element, the limbs in `x` will be <2^{120}
// Therefore each of the limbs in `p` (except the most significant) will borrow 2^{120} from the more significant limb.
// Finally, to ensure we do not underflow in the most significant limb, we use `2p` instead of `p`
unconstrained fn __add_linear_expression<let N: u32, let MOD_BITS: u32, let M: u32>(
    params: P<N, MOD_BITS>,
    x: [[u64; N]; M],
    flags: [bool; M],
) -> ([u64; N]) {
    // TODO, validate we do not overflow N2 when multiplying and N when adding
    let mut sum: [u64; N] = [0; N];
    // TODO: ugly! Will fail if input array is empty
    let double_modulus: [u64; N] = params.double_modulus;
    for i in 0..M {
        if (flags[i]) {
            for j in 0..N {
                sum[j] = sum[j] + (double_modulus[j] - x[i][j]);
            }
        } else {
            for j in 0..N {
                sum[j] = sum[j] + x[i][j];
            }
        }
    }
    // problem if we normalize when used in computing quotient
    sum
}

/**
* @brief computes the limb products of a quadratic expression
* @details see __compute_quadratic_expression_with_borrow_flags for full description
**/
unconstrained fn __compute_quadratic_expression_product<let N: u32, let MOD_BITS: u32, let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
    params: P<N, MOD_BITS>,
    lhs_terms: [[[u64; N]; LHS_N]; NUM_PRODUCTS],
    lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
    rhs_terms: [[[u64; N]; RHS_N]; NUM_PRODUCTS],
    rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
    linear_terms: [[u64; N]; ADD_N],
    linear_flags: [bool; ADD_N],
) -> [u128; 2 * N] {
    // TODO, validate we do not overflow N2 when multiplying and N when adding
    let mut lhs: [[u64; N]; NUM_PRODUCTS] = [[0; N]; NUM_PRODUCTS];
    let mut rhs: [[u64; N]; NUM_PRODUCTS] = [[0; N]; NUM_PRODUCTS];

    for i in 0..NUM_PRODUCTS {
        lhs[i] = __add_linear_expression(params, lhs_terms[i], lhs_flags[i]);
        rhs[i] = __add_linear_expression(params, rhs_terms[i], rhs_flags[i]);
    }

    let add: [u64; N] = __add_linear_expression(params, linear_terms, linear_flags);

    let mut mulout: [u128; 2 * N] = [0; 2 * N];

    for i in 0..N {
        for j in 0..N {
            for k in 0..NUM_PRODUCTS {
                mulout[i + j] += (lhs[k][i] as u128 * rhs[k][j] as u128);
            }
        }
        mulout[i] += add[i] as u128;
    }
    mulout
}

// /**
// * @brief computes the quotient/remainder of a quadratic expression
// * @details see __compute_quadratic_expression_with_borrow_flags for full description
// **/
// pub(crate) unconstrained fn __compute_quadratic_expression<let N: u32, let MOD_BITS: u32, let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
//     params: P<N, MOD_BITS>,
//     lhs_terms: [[[u128; N]; LHS_N]; NUM_PRODUCTS],
//     lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
//     rhs_terms: [[[u128; N]; RHS_N]; NUM_PRODUCTS],
//     rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
//     linear_terms: [[u128; N]; ADD_N],
//     linear_flags: [bool; ADD_N],
// ) -> ([u128; N], [u128; N]) {
//     // TODO, validate we do not overflow N2 when multiplying and N when adding
//     let mulout: [Field; (N * 2)] = __compute_quadratic_expression_product(
//         params,
//         lhs_terms,
//         lhs_flags,
//         rhs_terms,
//         rhs_flags,
//         linear_terms,
//         linear_flags,
//     );
//     let mut relation_result: [u128; 2 * N] = split_bits::__normalize_limbs(mulout, 2 * N);

//     // size 4
//     // a[3] * b[3] = a[6] = 7
//     // TODO: ugly! Will fail if input slice is empty
//     let k = MOD_BITS;

//     let (quotient, remainder) =
//         __barrett_reduction(relation_result, params.redc_param, k, params.modulus);

//     let mut q = quotient;
//     let mut r = remainder;
//     (q, r)
// }

/**
* @brief Constrain a degree-2 BigNum expression to be equal to 0 modulo self.modulus
* @description The expression is of the form (when evaluated as an integer relation):
*
* \sum_{i=0}^{NUM_PRODUCTS - 1} ((\sum_{j=0}^{LHS_N-1}lhs[i][j]) * (\sum_{j=0}^{RHS_N-1}rhs[i][j])) + \sum_{i=0}^{ADD_N - 1}linear_terms[i] - quotient * modulus = 0
*
* The intent is to capture an arbitrary degree-2 expression within the limitations of Noir (no efficient dynamically-sized vectors)
*
* Note: this method requires the remainder term of the expression to be ZERO
* When performing BigNum arithmetic, we want to represent desired BigNum operations in a way that minimizes the number of modular reductions that are required.
* This can be achieved by minimizing the number of degree-2 relations required.
*
* The expensive parts of this algorithm are the following:
*      1. evaluating the limb products required to compute `lhs * rhs`
*      2. applying range constraints to validate the result is 0
*
* Range constraints are needed for the following reason:
* When evaluating the above expression over N-limb BigNum objects, the result will consist of 2N - 1 limbs.
* Each limb will be in the range [0, ..., 2^{240 + twiddle_factor} - 1] (twiddle_factor needs to be less than 6).
* Because of the subtractions, the limbs may underflow and represent NEGATIVE values.
* To account for this, we allow the Prover to borrow values from more significant limbs and add them into less significant limbs
* (explicitly, we can borrow 2^{126} from limb `i + 1` to add `2^{246}` into `i`).
* To ensure this has been done correctly, we validate that the borrow-adjusted limbs are all-zero for the first 120 bits.
* We do *this* by multiplying the borrow-adjusted limbs by 1 / 2^{120} modulo CircutModulus, and we validate the result is in the range [0, ..., 2^{126} - 1].
* TODO: explain why this check works. It's statistically sound but not perfectly sound. Chance of the check failing is ~1 in 2^{120}
* I believe this is the most efficient way of performing the zero-check for this relation as it only requires `2N - 2` 126-bit range checks.
* TODO: explain why we apply a 126-bit range check, this feels like a magic number
* (it is. we could go higher, up to the number of bits in the CircuitModulus - 121, but 126 *should be* sufficient and is much cheaper)
* TODO: apply checks in this method to validate twiddle_factor does not exceed 6
* 
* @param lhs_terms a 2D array of BigNum
* @param lhs_flags a 2D array of sign flags
* @param rhs_terms a 2D array of BigNum
* @param rhs_flags a 2D array of sign flags
* @param linear_terms an array of BigNum
* @param linear_flags an array of sign flags
**/
pub fn evaluate_quadratic_expression<let N: u32, let MOD_BITS: u32, let LHS_N: u32, let RHS_N: u32, let NUM_PRODUCTS: u32, let ADD_N: u32>(
    params: P<N, MOD_BITS>,
    lhs_terms: [[[u64; N]; LHS_N]; NUM_PRODUCTS],
    lhs_flags: [[bool; LHS_N]; NUM_PRODUCTS],
    rhs_terms: [[[u64; N]; RHS_N]; NUM_PRODUCTS],
    rhs_flags: [[bool; RHS_N]; NUM_PRODUCTS],
    linear_terms: [[u64; N]; ADD_N],
    linear_flags: [bool; ADD_N],
) {
    // safety: use an unconstrained function to compute the value of the quotient
    let (quotient, _, borrow_flags): ([u64; N], [u64; N], [u128; 2 * N - 2]) = unsafe {
        __compute_quadratic_expression_with_borrow_flags::<_, MOD_BITS, _, _, _, _>(
            params,
            lhs_terms,
            lhs_flags,
            rhs_terms,
            rhs_flags,
            linear_terms,
            linear_flags,
        )
    };

    // constrain the quotient to be in the range [0, ..., 2^{m} - 1], where `m` is log2(modulus) rounded up.
    // Additionally, validate quotient limbs are also in the range [0, ..., 2^{14} - 1]
    validate_quotient_in_range::<_, MOD_BITS>(quotient);
    // TODO, validate we do not overflow N2 when multiplying and N when adding
    // (should be a compile-time check...unconstrained function?)
    // Compute the linear sums that represent lhs_1, rhs_1, lhs_2, rhs_2, add
    let mut t0: [[u128; N]; NUM_PRODUCTS] = [[0; N]; NUM_PRODUCTS];
    let mut t1: [[u128; N]; NUM_PRODUCTS] = [[0; N]; NUM_PRODUCTS];
    let mut t4: [u128; N] = [0; N];

    // TODO: this is super nasty as it requires a multiplication
    let double_modulus: [u64; N] = params.double_modulus;

    for k in 0..NUM_PRODUCTS {
        for i in 0..N {
            for j in 0..LHS_N {
                // note: if is_negative is not known at comptime this is very expensive
                if (lhs_flags[k][j]) {
                    t0[k][i] = t0[k][i].wrapping_sub(lhs_terms[k][j][i] as u128);
                    t0[k][i] = t0[k][i].wrapping_add(double_modulus[i] as u128);
                } else {
                    t0[k][i] = t0[k][i].wrapping_add(lhs_terms[k][j][i] as u128);
                }
            }
            for j in 0..RHS_N {
                if (rhs_flags[k][j]) {
                    t1[k][i] = t1[k][i].wrapping_sub(rhs_terms[k][j][i] as u128);
                    t1[k][i] = t1[k][i].wrapping_add(double_modulus[i] as u128);
                } else {
                    t1[k][i] = t1[k][i].wrapping_add(rhs_terms[k][j][i] as u128);
                }
            }
        }
    }

    for i in 0..N {
        for j in 0..ADD_N {
            if (linear_flags[j]) {
                t4[i] = t4[i].wrapping_sub(linear_terms[j][i] as u128);

                t4[i] = t4[i].wrapping_add(double_modulus[i] as u128);
            } else {
                t4[i] = t4[i].wrapping_add(linear_terms[j][i] as u128);
            }
        }
    }

    // We want to evaluate that t0 * t1 + t2 * t3 + t4 - Quotient * Modulus = 0, evaluated over the integers
    // For this we need to be able to borrow values from more-significant limbs into less-significant limbs,
    // so that we can ensure that no limbs will underflow for an honest Prover
    let mut product_limbs: [u128; 2 * N] = [0; 2 * N];

    // Compute the product t0 * t1 + t2 * t3 + t4 - Quotient * Modulus
    // TODO: this is super nasty as it requires a multiplication
    // First: Add all positive terms
    for i in 0..N {
        for j in 0..N {
            for k in 0..NUM_PRODUCTS {
                let product = t0[k][i] * t1[k][j] as u128;
                product_limbs[i + j] = product_limbs[i + j].wrapping_add(product);
            }
        }
        product_limbs[i] = product_limbs[i].wrapping_add(t4[i]);
    }

    // each limb product represents the sum of 120-bit products.
    // by setting the borrow value to 2^246 we are restricting this method's completeness to expressions
    // where no more than 64 limb products are summed together.
    // TODO: check in unconstrained function that this condition is satisfied
    // TODO: define trade-offs regarding the value of borrow_shift
    // (the larger the value, the greater the range check that is required on product_limbs)
    // (126-bit range check is a sweet spot for the barretenberg backend as it decomposes into 9 14-bit range checks)
    // (the barretenberg backend can evaluate these in 5.25 gates. 127 bits costs 6.5 gates)
    let borrow_shift: u128 = TWO_POW_70; // 2^{70}
    let borrow_carry: u128 = TWO_POW_38 as u128; // 2^{70 - 32} = 2^{38}
    // N.B. borrow_flags is `u128` type because making it `bool` would apply boolean constraints to all `N2` array entries.
    //      We only use `N2 - 2` borrow flags so applying 1-bit range checks on the array elements we use is more efficient.
    // TODO: Once it is possible to perform arithmetic on generics we can use `borrow_flags: [bool;N+N-2]` to avoid this issue

    (borrow_flags[0] as Field).assert_max_bit_size::<1>();
    product_limbs[0] = product_limbs[0].wrapping_add(borrow_flags[0] * borrow_shift);

    for i in 1..(N + N - 2) {
        (borrow_flags[i] as Field).assert_max_bit_size::<1>();
        product_limbs[i] = product_limbs[i].wrapping_add(borrow_flags[i] * borrow_shift);
    }

    for i in 0..N {
        for j in 0..N {
            let quotient_mod_product = quotient[i] as u128 * params.modulus[j] as u128;
            product_limbs[i + j] = product_limbs[i + j].wrapping_sub(quotient_mod_product);
        }
    }

    for i in 1..(N + N - 2) {
        let borrow_subtract = borrow_flags[i - 1] as u128 * borrow_carry as u128;
        product_limbs[i] = product_limbs[i].wrapping_sub(borrow_subtract);
    }

    let final_borrow_subtract = (borrow_flags[N + N - 3] as u128) * borrow_carry as u128;
    product_limbs[N + N - 2] = product_limbs[N + N - 2].wrapping_sub(final_borrow_subtract);

    for i in 0..N + N - 2 {
        // Check if low 32 bits are zero
        assert(product_limbs[i] & (0xffffffff as u128) == 0);

        product_limbs[i] = product_limbs[i] >> 32;
        (product_limbs[i] as Field).assert_max_bit_size::<39>();
        product_limbs[i + 1] = product_limbs[i + 1].wrapping_add(product_limbs[i]);
    }

    assert(product_limbs[N + N - 2] == 0);
}
