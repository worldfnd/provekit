/*
 * This file contains various versions of the NTT algorithm which were found to be slower than
 * ntt() in ntt.rs.
 */

use crate::NTT_BLOCK_SIZE_FOR_CACHE;
use crate::cm31::CF;
use num_traits::{Zero, One, Pow};
use crate::ntt_utils::*;

pub fn precomp_vec_twiddles(n: usize, w: CF, radix: usize) -> Vec<CF> {
    assert!(n.is_power_of_two(), "n must be a power of 2");
    assert!(n >= radix, "n must be at least as large as radix");
    assert!(radix.is_power_of_two(), "radix must be a power of 2");

    let mut twiddles = Vec::new();
    let mut current_n = n;
    let mut current_w = w;
    
    while current_n > 1 {
        let m = current_n / radix;
        let next_w = current_w.pow(radix);
        twiddles.push(next_w.reduce());
        
        for k in 0..m {
            let base = current_w.pow(k);
            let mut factor = CF::one();
            for _r in 1..radix {
                factor = factor * base;
                twiddles.push(factor.reduce());
            }
        }
        
        current_n /= radix;
        current_w = next_w;
    }
    
    twiddles
}

/// Performs a radix-8 NTT on the polynomial f. Creates new Vecs at each level of recursion.
/// On ARM CPUs, this is slower than ntt().
/// @param f The coefficients of the polynomial to be transformed.
/// @param twiddles The precomputed twiddles, which must be computed using precomp_vec_twiddles().
pub fn ntt_radix_8_precomp(
    f: &Vec<CF>,
    twiddles: &Vec<CF>,
) -> Vec<CF> {
    let n = f.len();
    debug_assert!(n >= 8, "n must be at least 8");
    debug_assert!(is_power_of(n as u32, 8), "n must be a power of 8");

    fn level_offset(n_total: usize, depth: usize) -> usize {
        let mut off = 0;
        let mut len = n_total / 8;
        for _ in 0..depth {
            off += 1 + 7 * len;
            len /= 8;
        }
        off
    }

    fn do_ntt_precomputed(
        f: &Vec<CF>,
        twiddles: &Vec<CF>,
        depth: usize,
        overall_transform_size: usize,
    ) -> Vec<CF> {
        let n = f.len();
        
        // Base case
        if n == 1 {
            return f.clone();
        }

        // n is divisible by 8
        let m = n / 8;

        // Compute the starting offset for the current recursion level
        let lvl_offset = level_offset(overall_transform_size, depth);
        
        // Partition f into eight subarrays
        let mut a0 = vec![CF::zero(); m];
        let mut a1 = vec![CF::zero(); m];
        let mut a2 = vec![CF::zero(); m];
        let mut a3 = vec![CF::zero(); m];
        let mut a4 = vec![CF::zero(); m];
        let mut a5 = vec![CF::zero(); m];
        let mut a6 = vec![CF::zero(); m];
        let mut a7 = vec![CF::zero(); m];

        let mut res = vec![CF::zero(); n];

        unsafe {
            for i in 0..m {
                let i_8 = i * 8;

                a0[i] = *f.get_unchecked(i_8);
                a1[i] = *f.get_unchecked(i_8 + 1);
                a2[i] = *f.get_unchecked(i_8 + 2);
                a3[i] = *f.get_unchecked(i_8 + 3);
                a4[i] = *f.get_unchecked(i_8 + 4);
                a5[i] = *f.get_unchecked(i_8 + 5);
                a6[i] = *f.get_unchecked(i_8 + 6);
                a7[i] = *f.get_unchecked(i_8 + 7);
            }

            // Recurse on each subarray
            let next_depth = depth + 1;
            let ntt_a0 = do_ntt_precomputed(&a0, twiddles, next_depth, overall_transform_size);
            let ntt_a1 = do_ntt_precomputed(&a1, twiddles, next_depth, overall_transform_size);
            let ntt_a2 = do_ntt_precomputed(&a2, twiddles, next_depth, overall_transform_size);
            let ntt_a3 = do_ntt_precomputed(&a3, twiddles, next_depth, overall_transform_size);
            let ntt_a4 = do_ntt_precomputed(&a4, twiddles, next_depth, overall_transform_size);
            let ntt_a5 = do_ntt_precomputed(&a5, twiddles, next_depth, overall_transform_size);
            let ntt_a6 = do_ntt_precomputed(&a6, twiddles, next_depth, overall_transform_size);
            let ntt_a7 = do_ntt_precomputed(&a7, twiddles, next_depth, overall_transform_size);

            for k in 0..m {
                let f0 = *ntt_a0.get_unchecked(k);
                let f1 = *ntt_a1.get_unchecked(k);
                let f2 = *ntt_a2.get_unchecked(k);
                let f3 = *ntt_a3.get_unchecked(k);
                let f4 = *ntt_a4.get_unchecked(k);
                let f5 = *ntt_a5.get_unchecked(k);
                let f6 = *ntt_a6.get_unchecked(k);
                let f7 = *ntt_a7.get_unchecked(k);

                let base_idx = lvl_offset + 1 + 7 * k;
                let wt =  *twiddles.get_unchecked(base_idx);
                let wt2 = *twiddles.get_unchecked(base_idx + 1);
                let wt3 = *twiddles.get_unchecked(base_idx + 2);
                let wt4 = *twiddles.get_unchecked(base_idx + 3);
                let wt5 = *twiddles.get_unchecked(base_idx + 4);
                let wt6 = *twiddles.get_unchecked(base_idx + 5);
                let wt7 = *twiddles.get_unchecked(base_idx + 6);

                // Apply the radix-8 butterfly
                let butterfly = ntt_block_8(
                    f0, f1, f2, f3, f4, f5, f6, f7,
                    wt, wt2, wt3, wt4, wt5, wt6, wt7
                );

                // Write the results to the correct positions
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

    do_ntt_precomputed(&f, twiddles, 0, n)
}

/// An in-place radix-8 NTT without precomputed twiddles.
/// @param f The input array to modify in-place.
/// @param w The n-th root of unity where n is the length of f.
pub fn ntt_radix_8_in_place(f: &mut [CF], w: CF) {
    fn do_ntt(
        f: &mut [CF],
        scratch: &mut [CF],
        offset: usize,
        stride: usize,
        n: usize,
        w_lvl: CF,
    ) {
        if n == 1 {
            return;
        }

        let m = n / 8;
        let w_next = w_lvl.pow(8);

        // Recurse
        for r in 0..8 {
            do_ntt(
                f,
                scratch,
                offset + r * stride,
                stride * 8,
                m,
                w_next,
            );
        }

        unsafe {
            for i in 0..n {
                scratch[i] = *f.get_unchecked(offset + i * stride);
            }

            let mut base = CF::one();
            for k in 0..m {
                if k != 0 {
                    base = base * w_lvl;
                }

                let wt  = base;
                let wt2 = wt  * base;
                let wt3 = wt2 * base;
                let wt4 = wt3 * base;
                let wt5 = wt4 * base;
                let wt6 = wt5 * base;
                let wt7 = wt6 * base;

                let k8  = k * 8;
                let res = ntt_block_8(
                    *scratch.get_unchecked(k8 + 0),
                    *scratch.get_unchecked(k8 + 1),
                    *scratch.get_unchecked(k8 + 2),
                    *scratch.get_unchecked(k8 + 3),
                    *scratch.get_unchecked(k8 + 4),
                    *scratch.get_unchecked(k8 + 5),
                    *scratch.get_unchecked(k8 + 6),
                    *scratch.get_unchecked(k8 + 7),
                    wt, wt2, wt3, wt4, wt5, wt6, wt7,
                );

                *f.get_unchecked_mut(offset + k * stride) = res.0;
                *f.get_unchecked_mut(offset + (k + m) * stride) = res.1;
                *f.get_unchecked_mut(offset + (k + 2 * m) * stride) = res.2;
                *f.get_unchecked_mut(offset + (k + 3 * m) * stride) = res.3;
                *f.get_unchecked_mut(offset + (k + 4 * m) * stride) = res.4;
                *f.get_unchecked_mut(offset + (k + 5 * m) * stride) = res.5;
                *f.get_unchecked_mut(offset + (k + 6 * m) * stride) = res.6;
                *f.get_unchecked_mut(offset + (k + 7 * m) * stride) = res.7;
            }
        }
    }

    let n = f.len();
    debug_assert!(n >= 8, "N must be at least 8");
    debug_assert!(is_power_of(n as u32, 8), "N must be a power of 8");

    let mut scratch = vec![CF::zero(); n];
    do_ntt(f, &mut scratch, 0, 1, n, w);
}

/// Performs a radix-8 NTT on the polynomial f.
/// It uses an in-place NTT (ntt_radix_8_in_place) with NTT_BLOCK_SIZE_FOR_CACHE as the minimum
/// block size. The performance gain outweighs the creation of Vecs in the higher levels of
/// recursion. The block size was selected based on benchmarks on a Raspberry Pi 5 (ARM
/// Cortex-A76).
/// @param f The coefficients of the polynomial to be transformed.
/// @param w The n-th root of unity, where n is the length of f.
/// @return The transformed polynomial in evaluation form.
pub fn ntt_radix_8_using_ntt_radix_8_in_place(
    f: &Vec<CF>,
    w: CF,
) -> Vec<CF> {
    let n = f.len();

    fn do_ntt(
        f: &Vec<CF>,
        w: CF,
        n: usize,
    ) -> Vec<CF> {
        // Base case
        if n <= NTT_BLOCK_SIZE_FOR_CACHE {
            let mut res = f.clone();
            ntt_radix_8_in_place(&mut res, w);
            return res;
        }

        let m = n / 8;
        let w_pow_8 = w.pow(8);

        let mut parts = vec![vec![CF::zero(); m]; 8];
        let mut res   = vec![CF::zero(); n];

        unsafe {
            // Partition
            for i in 0..m {
                let base = i * 8;
                for j in 0..8 {
                    *parts.get_unchecked_mut(j).get_unchecked_mut(i) = *f.get_unchecked(base + j);
                }
            }

            // Recurse
            let mut sub_ntt = Vec::with_capacity(8);
            for j in 0..8 {
                sub_ntt.push(do_ntt(parts.get_unchecked(j), w_pow_8, m));
            }

            // Combine
            for k in 0..m {
                let wt  = w.pow(k);
                let wt2 = wt * wt;
                let wt3 = wt2 * wt;
                let wt4 = wt3 * wt;
                let wt5 = wt4 * wt;
                let wt6 = wt5 * wt;
                let wt7 = wt6 * wt;

                let f0 = *sub_ntt.get_unchecked(0).get_unchecked(k);
                let f1 = *sub_ntt.get_unchecked(1).get_unchecked(k);
                let f2 = *sub_ntt.get_unchecked(2).get_unchecked(k);
                let f3 = *sub_ntt.get_unchecked(3).get_unchecked(k);
                let f4 = *sub_ntt.get_unchecked(4).get_unchecked(k);
                let f5 = *sub_ntt.get_unchecked(5).get_unchecked(k);
                let f6 = *sub_ntt.get_unchecked(6).get_unchecked(k);
                let f7 = *sub_ntt.get_unchecked(7).get_unchecked(k);

                let butterfly = ntt_block_8(
                    f0, f1, f2, f3, f4, f5, f6, f7,
                    wt, wt2, wt3, wt4, wt5, wt6, wt7,
                    );

                *res.get_unchecked_mut(k)         = butterfly.0;
                *res.get_unchecked_mut(k + m)     = butterfly.1;
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

    do_ntt(f, w, n)
}

/// Performs a radix-8 NTT on the polynomial f.
/// Slightly slower than ntt_precomp_full(), as it does not use precomputed twiddles for the layers
/// above NTT_BLOCK_SIZE_FOR_CACHE.
pub fn ntt_precomp(f: &Vec<CF>, w: CF, precomp_small: &Vec<CF>) -> Vec<CF> {
    fn do_ntt(
        f: &Vec<CF>,
        w: CF,
        n: usize,
        precomp_small: &Vec<CF>,
    ) -> Vec<CF> {
        // Base case
        if n <= NTT_BLOCK_SIZE_FOR_CACHE {
            let mut res = f.clone();
            ntt_radix_8_in_place_precomp(&mut res, precomp_small);
            return res;
        }

        let m = n / 8;
        let w_pow_8 = w.pow(8);

        let mut parts = vec![vec![CF::zero(); m]; 8];
        let mut res   = vec![CF::zero(); n];

        unsafe {
            // Partition
            for i in 0..m {
                let base = i * 8;
                for j in 0..8 {
                    *parts.get_unchecked_mut(j).get_unchecked_mut(i) = *f.get_unchecked(base + j);
                }
            }

            // Recurse
            let mut sub_ntt = Vec::with_capacity(8);
            for j in 0..8 {
                sub_ntt.push(do_ntt(parts.get_unchecked(j), w_pow_8, m, precomp_small));
            }

            // Combine
            for k in 0..m {
                let wt  = w.pow(k);
                let wt2 = wt * wt;
                let wt3 = wt2 * wt;
                let wt4 = wt3 * wt;
                let wt5 = wt4 * wt;
                let wt6 = wt5 * wt;
                let wt7 = wt6 * wt;

                let f0 = *sub_ntt.get_unchecked(0).get_unchecked(k);
                let f1 = *sub_ntt.get_unchecked(1).get_unchecked(k);
                let f2 = *sub_ntt.get_unchecked(2).get_unchecked(k);
                let f3 = *sub_ntt.get_unchecked(3).get_unchecked(k);
                let f4 = *sub_ntt.get_unchecked(4).get_unchecked(k);
                let f5 = *sub_ntt.get_unchecked(5).get_unchecked(k);
                let f6 = *sub_ntt.get_unchecked(6).get_unchecked(k);
                let f7 = *sub_ntt.get_unchecked(7).get_unchecked(k);

                let butterfly = ntt_block_8(
                    f0, f1, f2, f3, f4, f5, f6, f7,
                    wt, wt2, wt3, wt4, wt5, wt6, wt7,
                );

                *res.get_unchecked_mut(k)         = butterfly.0;
                *res.get_unchecked_mut(k + m)     = butterfly.1;
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

    let n = f.len();
    
    if n <= NTT_BLOCK_SIZE_FOR_CACHE {
        let mut res = f.clone();
        ntt_radix_8_in_place_precomp(&mut res, precomp_small);
        return res;
    }

    do_ntt(f, w, n, precomp_small)
}

#[cfg(test)]
pub mod tests {
    use crate::NTT_BLOCK_SIZE_FOR_CACHE;
    use crate::cm31::CF;
    use crate::ntt::*;
    use crate::ntt_utils::*;
    use crate::ntt_radix_8::*;
    use crate::ntt_experiments::*;
    use rand::Rng;
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;
    use num_traits::Zero;

    fn gen_rand_poly(n: usize, seed: u64) -> Vec<CF> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut poly = vec![CF::zero(); n];
        for i in 0..n {
            poly[i] = rng.r#gen();
        }
        poly
    }

    #[test]
    pub fn test_ntt_radix_8_vec() {
        for log8_n in 1..5 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);
            for seed in 0..4 {
                let f = gen_rand_poly(n, seed);

                let res = ntt_radix_8(&f, wn);
                let expected = naive_ntt(&f);
                assert_eq!(res, expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_radix_8_vec_precomp() {
        for log8_n in 1..5 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);
            let precomp = precomp_vec_twiddles(n, wn, 8);
            for seed in 0..4 {
                let f = gen_rand_poly(n, seed);

                let res = ntt_radix_8_precomp(&f, &precomp);
                let expected = naive_ntt(&f);
                assert_eq!(res, expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_radix_8_in_place() {
        for n in [8, 64, 4096] {
            let wn = get_root_of_unity(n);
            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let expected = naive_ntt(&f);
                ntt_radix_8_in_place(&mut f, wn);
                assert_eq!(f, expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_optimised() {
        for log8_n in 1..5 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);
            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let res = ntt_radix_8_using_ntt_radix_8_in_place(&mut f, wn);
                let expected = ntt_radix_8(&f, wn);
                assert!(res == expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_optimised_precomp() {
        for log8_n in 1..9 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);

            // TODO: refactor
            let precomp_small = if n < NTT_BLOCK_SIZE_FOR_CACHE {
                precomp_twiddles(n, wn)
            } else {
                precomp_twiddles(NTT_BLOCK_SIZE_FOR_CACHE, get_root_of_unity(NTT_BLOCK_SIZE_FOR_CACHE))
            };

            for seed in 0..1 {
                let mut f = gen_rand_poly(n, seed);

                let res = ntt_precomp(&mut f, wn, &precomp_small);
                let expected = ntt_radix_8(&f, wn);
                assert!(res == expected);
            }
        }
    }
}
