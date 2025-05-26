//! Bn254 scalar field modular reduction routines.
//!
//! TODO: These should live in some field arithmetic crate.

use {
    crate::{
        arithmetic::{less_than, overflowing_sub, sub},
        constants::{MODULUS, MODULUS_N_MINUS_RC},
    },
    core::hint::cold_path,
};

/// Fully reduce any input to [0, M)
#[inline(always)]
pub fn reduce(x: [u64; 4]) -> [u64; 4] {
    reduce_1(reduce_partial(x))
}

/// Fully reduce an input in range [0, 2M) to [0, M)
/// Optimized for likely x < M, e.g. a partially reduced input.
#[inline(always)]
pub fn reduce_1(x: [u64; 4]) -> [u64; 4] {
    debug_assert!(less_than(x, MODULUS[2]));
    let (r, borrow) = overflowing_sub(x, MODULUS[1]);
    if borrow {
        x
    } else {
        cold_path();
        r
    }
}

/// Reduce any input to [0, M + ϵ)
#[inline(always)]
pub fn reduce_partial(x: [u64; 4]) -> [u64; 4] {
    // The compiler should turn this division by constant into an umulh.
    let multiple = (x[3] / (MODULUS[1][3] + 1)) as usize;
    let r = sub(x, MODULUS[multiple]);
    debug_assert!(r[3] < MODULUS[1][3] + 3);
    r
}

/// Combined partial reduction and add round constant
/// Input can be any value.
/// Output is in range [0, 2M + ϵ)  (TODO: Analyse more carefully)
/// TODO: Maybe with a round dependend lookup factor it can be [0, M + ϵ)
#[inline(always)]
pub fn reduce_partial_add_rc(x: [u64; 4], rc: usize) -> [u64; 4] {
    // The compiler should turn this division by constant into an umulh.
    let multiple = (x[3] / (MODULUS[1][3] + 1)) as usize;
    let (r, borrow) = overflowing_sub(x, MODULUS_N_MINUS_RC[multiple][rc]);
    debug_assert!(!borrow || multiple == 0);
    debug_assert!(less_than(r, MODULUS[2]));
    r
}

/// Vectorized version of [`reduce_partial_add_rc`]
#[inline(always)]
pub fn reduce_partial_add_rcv<const N: usize>(x: [[u64; 4]; N], rc: usize) -> [[u64; 4]; N] {
    x.map(|x| reduce_partial_add_rc(x, rc))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_range_loop)]

    use {
        super::*,
        crate::{arithmetic::add, constants::ROUND_CONSTANTS},
        ark_bn254::Fr,
        ark_ff::{BigInt, PrimeField},
        proptest::proptest,
    };

    #[test]
    fn test_reduce() {
        proptest!(|(x: [u64; 4])| {
            let e = Fr::new(BigInt(x)).into_bigint().0;
            let r = reduce(x);
            assert_eq!(r, e);
        })
    }

    #[test]
    fn test_reduce_partial() {
        proptest!(|(x: [u64; 4])| {
            let e = reduce(x);
            let r = reduce_partial(x);
            assert_eq!(reduce(r), e);
            assert!(r[3] < MODULUS[1][3] + 3);
        })
    }

    #[test]
    fn test_reduce_partial_max() {
        for i in 0..6 {
            let mut x = [u64::MAX; 4];
            x[3] = MODULUS[i][3] + 1;
            let e = reduce(x);
            let r = reduce_partial(x);
            assert_eq!(reduce(r), e);
            assert!(r[3] < MODULUS[1][3] + 3);
        }
    }

    #[test]
    fn test_reduce_partial_add_rc() {
        proptest!(|(x: [u64; 4], rc in 0_usize..18)| {
            let e = reduce(add(reduce(x), ROUND_CONSTANTS[rc]));
            let r = reduce_partial_add_rc(x, rc);
            assert_eq!(reduce(r), e);
            assert!(less_than(r, MODULUS[2]))
        })
    }

    #[test]
    fn test_reduce_partial_add_rc_max() {
        for i in 0..6 {
            for rc in 0..18 {
                let mut x = [u64::MAX; 4];
                x[3] = MODULUS[i][3] + 1;
                let e = reduce(add(reduce(x), ROUND_CONSTANTS[rc]));
                let r = reduce_partial_add_rc(x, rc);
                assert_eq!(reduce(r), e);
                assert!(r[3] < MODULUS[2][3]);
            }
        }
    }
}
