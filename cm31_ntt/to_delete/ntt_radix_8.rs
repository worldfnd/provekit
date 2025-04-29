use crate::cm31::CF;
use num_traits::{Zero, Pow};
use crate::ntt_utils::*;

pub const NTT_BLOCK_SIZE_FOR_CACHE: usize = 32768;

/// Performs a radix-8 NTT on the polynomial f.
/// This is unoptimised as it does not use any precomputed twiddles. We only use it for testing
/// purposes.
/// It is also slower than ntt() as it allocates Vecs at each level of recursion, and doing so at
/// the lower levels (to handle 8^1 to 8^5) incurs significant memory allocation overhead.
/// @param f The coefficients of the polynomial to be transformed.
/// @param w The n-th root of unity, where n is the length of f.
/// @return The transformed polynomial in evaluation form.
pub fn ntt_radix_8(f: &Vec<CF>, w: CF) -> Vec<CF> {
    let n = f.len();
    debug_assert!(n >= 8, "n must be at least 8");
    debug_assert!(is_power_of(n as u32, 8), "n must be a power of 8");

    fn do_ntt(f: &Vec<CF>, w: CF) -> Vec<CF> {
        let n = f.len();
        if n == 1 {
            return f.clone();
        }

        let m = n / 8;
        let w_pow_8 = w.pow(8);

        // Partition f into 8 subarrays.
        let mut a = vec![vec![CF::zero(); m]; 8];

        let mut res = vec![CF::zero(); n];
        unsafe {
            for i in 0..m {
                let i_8 = i * 8;
                for j in 0..8 {
                    a[j][i] = *f.get_unchecked(i_8 + j);
                }
            }

            // Recurse
            let mut ntt_a = Vec::with_capacity(8);
            for i in 0..8 {
                ntt_a.push(do_ntt(&a[i], w_pow_8));
            }

            for k in 0..m {
                // Calculate twiddle factors
                let wt   = w.pow(k);
                let wt2  = wt  * wt;
                let wt3  = wt2 * wt;
                let wt4  = wt3 * wt;
                let wt5  = wt4 * wt;
                let wt6  = wt5 * wt;
                let wt7  = wt6 * wt;

                let f0 = *ntt_a.get_unchecked(0).get_unchecked(k);
                let f1 = *ntt_a.get_unchecked(1).get_unchecked(k);
                let f2 = *ntt_a.get_unchecked(2).get_unchecked(k);
                let f3 = *ntt_a.get_unchecked(3).get_unchecked(k);
                let f4 = *ntt_a.get_unchecked(4).get_unchecked(k);
                let f5 = *ntt_a.get_unchecked(5).get_unchecked(k);
                let f6 = *ntt_a.get_unchecked(6).get_unchecked(k);
                let f7 = *ntt_a.get_unchecked(7).get_unchecked(k);

                let butterfly = ntt_block_8(
                    f0, f1, f2, f3, f4, f5, f6, f7,
                    wt, wt2, wt3, wt4, wt5, wt6, wt7
                );

                *res.get_unchecked_mut(k) = butterfly.0;
                *res.get_unchecked_mut(k + m) = butterfly.1;
                *res.get_unchecked_mut(k + 2 * m) = butterfly.2;
                *res.get_unchecked_mut(k + 3 * m) = butterfly.3;
                *res.get_unchecked_mut(k + 4 * m) = butterfly.4;
                *res.get_unchecked_mut(k + 5 * m) = butterfly.5;
                *res.get_unchecked_mut(k + 6 * m) = butterfly.6;
                *res.get_unchecked_mut(k + 7 * m) = butterfly.7;
            }
        }
        res
    }

    do_ntt(&f, w)
}
