use crate::cm31::CF;
use num_traits::{Zero, One, Pow};
use crate::ntt_utils::*;

pub const NTT_BLOCK_SIZE_FOR_CACHE: usize = 8usize.pow(5);

/// Performs a radix-8 NTT on the polynomial f.
/// This is unoptimised as it does not use any precomputed twiddles.
/// It is also slower than ntt_r8_hybrid_p() as it allocates Vecs at each level of recursion, and doing so at
/// the lower levels (to handle 8^1 to 8^5) incurs significant memory allocation overhead.
/// @param f The coefficients of the polynomial to be transformed.
/// @param w The n-th root of unity, where n is the length of f.
/// @return The transformed polynomial in evaluation form.
pub fn ntt_r8_vec(f: &Vec<CF>, w: CF) -> Vec<CF> {
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

/// Performs a radix-2 NTT on the polynomial f.
/// This is unoptimised as it does not use any precomputed twiddles.
/// Like ntt_r8_vec, it is also slower than ntt_r8_s2_hybrid_p() as it allocates Vecs at each level
/// of recursion.
/// @param f The coefficients of the polynomial to be transformed.
/// @param w The n-th root of unity, where n is the length of f.
/// @return The transformed polynomial in evaluation form.
pub fn ntt_radix_2(f: &Vec<CF>, w: CF) -> Vec<CF> {
    let n = f.len();
    assert!(n >= 2, "n must be at least 2");
    assert!(n.is_power_of_two(), "n must be a power of 2");

    fn do_ntt(f: &Vec<CF>, w: CF) -> Vec<CF> {
        let n = f.len();

        // Base case
        if n == 1 {
            return f.clone();
        }

        // Divide
        let mut f_even = vec![CF::zero(); n/2];
        let mut f_odd = vec![CF::zero(); n/2];
        for i in 0..n/2 {
            f_even[i] = f[2*i];
            f_odd[i] = f[2*i + 1];
        }

        // Recurse
        let ntt_even = do_ntt(&f_even, w.pow(2));
        let ntt_odd = do_ntt(&f_odd, w.pow(2));

        // Combine
        let mut res = vec![CF::zero(); n];

        let mut wk = CF::one();
        for i in 0..n/2 {
            // Perform a radix-2 butterfly
            res[i] = ntt_even[i] + wk * ntt_odd[i];
            res[i + n/2] = ntt_even[i] - wk * ntt_odd[i];
            wk = wk * w;
        }

        res
    }

    do_ntt(f, w)
}

/// Precompute twiddles for use in the ntt_r8_vec_p() function.
pub fn precomp_for_ntt_r8_vec_p(n: usize, w: CF) -> Vec<CF> {
    let radix: usize = 8;
    assert!(n.is_power_of_two(), "n must be a power of 2");
    assert!(radix.is_power_of_two(), "radix must be a power of 2");
    assert!(n >= radix, "n must be at least as large as 8");

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

pub fn ntt_r8_vec_p(
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
pub fn ntt_r8_ip(f: &mut [CF], w: CF) {
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

pub fn precomp_for_ntt_r8_ip_p(n: usize, w: CF) -> Vec<CF> {
    assert!(n >= 8 && is_power_of(n as u32, 8), "n must be 8^x");

    fn precomp_stage(n: usize, w: CF) -> Vec<CF> {
        let m = n / 8;
        let mut tw = Vec::with_capacity(7 * m);
        for k in 0..m {
            let base = w.pow(k);
            let mut cur = base;
            tw.push(cur);
            for _ in 2..=7 {
                cur = cur * base;
                tw.push(cur);
            }
        }
        tw
    }

    let mut res = Vec::new();
    let mut len = n;
    let mut root = w;
    while len >= 8 {
        let stage = precomp_stage(len, root);
        res.extend(stage);
        root = root.pow(8);
        len /= 8;
    }
    res
}

pub fn ntt_r8_ip_p(
    f: &mut [CF],
    scratch: &mut [CF],
    pre: &[CF],
) {
    fn recurse(
        f: &mut [CF],
        scratch: &mut [CF],
        offset: usize,
        stride: usize,
        n: usize,
        pre: &[CF],
        mut pre_off: usize,
    ) {
        unsafe {
            if n == 8 {
                let bf = ntt_block_8(
                    *f.get_unchecked(offset),
                    *f.get_unchecked(offset + stride),
                    *f.get_unchecked(offset + 2 * stride),
                    *f.get_unchecked(offset + 3 * stride),
                    *f.get_unchecked(offset + 4 * stride),
                    *f.get_unchecked(offset + 5 * stride),
                    *f.get_unchecked(offset + 6 * stride),
                    *f.get_unchecked(offset + 7 * stride),
                    pre[pre_off],
                    pre[pre_off + 1],
                    pre[pre_off + 2],
                    pre[pre_off + 3],
                    pre[pre_off + 4],
                    pre[pre_off + 5],
                    pre[pre_off + 6],
                );
                *f.get_unchecked_mut(offset) = bf.0;
                *f.get_unchecked_mut(offset + stride) = bf.1;
                *f.get_unchecked_mut(offset + 2 * stride) = bf.2;
                *f.get_unchecked_mut(offset + 3 * stride) = bf.3;
                *f.get_unchecked_mut(offset + 4 * stride) = bf.4;
                *f.get_unchecked_mut(offset + 5 * stride) = bf.5;
                *f.get_unchecked_mut(offset + 6 * stride) = bf.6;
                *f.get_unchecked_mut(offset + 7 * stride) = bf.7;
                return;
            }

            let m = n / 8;
            let cur_len = 7 * m;
            let stage_pre = &pre[pre_off..pre_off + cur_len];
            pre_off += cur_len;
            for r in 0..8 {
                recurse(
                    f,
                    scratch,
                    offset + r * stride,
                    stride * 8,
                    m,
                    pre,
                    pre_off,
                );
            }

            for i in 0..n {
                scratch[i] = *f.get_unchecked(offset + i * stride);
            }

            for k in 0..m {
                let idx = k * 8;
                let base = k * 7;
                let bf = ntt_block_8(
                    *scratch.get_unchecked(idx),
                    *scratch.get_unchecked(idx + 1),
                    *scratch.get_unchecked(idx + 2),
                    *scratch.get_unchecked(idx + 3),
                    *scratch.get_unchecked(idx + 4),
                    *scratch.get_unchecked(idx + 5),
                    *scratch.get_unchecked(idx + 6),
                    *scratch.get_unchecked(idx + 7),
                    *stage_pre.get_unchecked(base),
                    *stage_pre.get_unchecked(base + 1),
                    *stage_pre.get_unchecked(base + 2),
                    *stage_pre.get_unchecked(base + 3),
                    *stage_pre.get_unchecked(base + 4),
                    *stage_pre.get_unchecked(base + 5),
                    *stage_pre.get_unchecked(base + 6),
                );
                *f.get_unchecked_mut(offset + (k) * stride) = bf.0;
                *f.get_unchecked_mut(offset + (k + m) * stride) = bf.1;
                *f.get_unchecked_mut(offset + (k + 2 * m) * stride) = bf.2;
                *f.get_unchecked_mut(offset + (k + 3 * m) * stride) = bf.3;
                *f.get_unchecked_mut(offset + (k + 4 * m) * stride) = bf.4;
                *f.get_unchecked_mut(offset + (k + 5 * m) * stride) = bf.5;
                *f.get_unchecked_mut(offset + (k + 6 * m) * stride) = bf.6;
                *f.get_unchecked_mut(offset + (k + 7 * m) * stride) = bf.7;
            }
        }
    }

    let n = f.len();
    debug_assert!(n >= 8 && is_power_of(n as u32, 8), "length must be a power of 8");

    recurse(f, scratch, 0, 1, n, pre, 0);
}

/// Performs a radix-8 NTT on the polynomial f. This function is optimised to maximise cache use.
/// It uses an in-place NTT (ntt_radix_8_in_place) with NTT_BLOCK_SIZE_FOR_CACHE as the minimum
/// block size. The performance gain outweighs the creation of Vecs in the higher levels of
/// recursion. The block size was selected based on benchmarks on a Raspberry Pi 5 (ARM
/// Cortex-A76).
/// @param f The coefficients of the polynomial to be transformed.
/// @param w The n-th root of unity, where n is the length of f.
/// @return The transformed polynomial in evaluation form.
pub fn ntt_r8_hybrid(
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
            ntt_r8_ip(&mut res, w);
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

pub fn ntt_r8_hybrid_ps(f: &Vec<CF>, w: CF, precomp_small: &Vec<CF>) -> Vec<CF> {
    fn do_ntt(
        f: &Vec<CF>,
        scratch: &mut [CF],
        w: CF,
        n: usize,
        precomp_small: &Vec<CF>,
    ) -> Vec<CF> {
        // Base case
        if n <= NTT_BLOCK_SIZE_FOR_CACHE {
            let mut res = f.clone();
            ntt_r8_ip_p(&mut res, scratch, precomp_small);
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
                sub_ntt.push(do_ntt(parts.get_unchecked(j), scratch, w_pow_8, m, precomp_small));
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
    let mut scratch = vec![CF::zero(); n];
    
    if n <= NTT_BLOCK_SIZE_FOR_CACHE {
        let mut res = f.clone();
        ntt_r8_ip_p(&mut res, &mut scratch, precomp_small);
        return res;
    }

    do_ntt(f, &mut scratch, w, n, precomp_small)
}

pub fn gen_precomp_full(n: usize, w: CF, block: usize) -> Vec<CF> {
    debug_assert!(n >= block && is_power_of(n as u32, 8), "n must be power of 8 and >= block");
    debug_assert!(block >= 8 && block <= n && block % 8 == 0, "block must be a multiple of 8 and <= n");
    let mut tw: Vec<CF> = Vec::new();
    let mut curr_len = n;
    let mut w_lvl = w;
    while curr_len > block {
        let m = curr_len / 8;
        for k in 0..m {
            let base = w_lvl.pow(k);
            let mut cur = base;
            for _ in 0..7 {
                tw.push(cur);
                cur = cur * base;
            }
        }
        w_lvl = w_lvl.pow(8);
        curr_len /= 8;
    }
    tw
}

/// Performs a radix-8 NTT on the polynomial f.
/// Uses a hybrid approach, where an in-place algorithm is used for the base case which accepts an
/// input size of NTT_BLOCK_SIZE_FOR_CACHE, and memory allocation via Vecs for the higher levels.
/// This is done to maximise cache use and minimise memory allocations.
/// This function expects a reference to a zero buffer as the scratch parameter, of size
/// NTT_BLOCK_SIZE_FOR_CACH, of size NTT_BLOCK_SIZE_FOR_CACHE.
/// The precomp_small and precomp_full parameters are precomputed twiddles for the base NTT and the
/// higher layers, respectively. They must be generated using precomp_for_ntt_r8_hybrid_p().
/// @param f The coefficients of the polynomial to be transformed.
/// @param scratch A scratch space for intermediate results.
/// @param precomp_small Precomputed twiddles for the base NTT.
/// @param precomp_full Precomputed twiddles for the higher layers.
pub fn ntt_r8_hybrid_p(
    f: &Vec<CF>,
    scratch: &mut [CF],
    precomp_small: &Vec<CF>,
    precomp_full: &Vec<CF>,
) -> Vec<CF> {

    fn level_offset(n_total: usize, depth: usize) -> usize {
        let mut off = 0;
        let mut len = n_total / 8;
        for _ in 0..depth {
            off += 7 * len;
            len /= 8;
        }
        off
    }

    fn recurse(
        f: &Vec<CF>,
        scratch: &mut [CF],
        pre_small: &[CF],
        pre_full: &[CF],
        depth: usize,
        overall_n: usize,
    ) -> Vec<CF> {
        let n = f.len();
        let mut res = vec![CF::zero(); n];

        unsafe {
            // Base case
            if n <= NTT_BLOCK_SIZE_FOR_CACHE {
                let mut r = f.clone();
                ntt_r8_ip_p(&mut r, scratch, pre_small);
                return r;
            }

            // Divide
            let m = n / 8;
            let mut parts = vec![vec![CF::zero(); m]; 8];
            for i in 0..m {
                for r in 0..8 {
                    *parts.get_unchecked_mut(r).get_unchecked_mut(i) = *f.get_unchecked(i * 8 + r);
                }
            }

            // Recurse
            let mut subs = Vec::with_capacity(8);
            for r in 0..8 {
                subs.push(recurse(&parts.get_unchecked(r), scratch, pre_small, pre_full, depth + 1, overall_n));
            }

            // Combine
            let lvl = level_offset(overall_n, depth);

            for k in 0..m {
                let base = lvl + 7 * k;
                let wt  = *pre_full.get_unchecked(base);
                let wt2 = *pre_full.get_unchecked(base + 1);
                let wt3 = *pre_full.get_unchecked(base + 2);
                let wt4 = *pre_full.get_unchecked(base + 3);
                let wt5 = *pre_full.get_unchecked(base + 4);
                let wt6 = *pre_full.get_unchecked(base + 5);
                let wt7 = *pre_full.get_unchecked(base + 6);

                let f0 = *subs.get_unchecked(0).get_unchecked(k);
                let f1 = *subs.get_unchecked(1).get_unchecked(k);
                let f2 = *subs.get_unchecked(2).get_unchecked(k);
                let f3 = *subs.get_unchecked(3).get_unchecked(k);
                let f4 = *subs.get_unchecked(4).get_unchecked(k);
                let f5 = *subs.get_unchecked(5).get_unchecked(k);
                let f6 = *subs.get_unchecked(6).get_unchecked(k);
                let f7 = *subs.get_unchecked(7).get_unchecked(k);

                let bf = ntt_block_8(
                    f0, f1, f2, f3, f4, f5, f6, f7,
                    wt, wt2, wt3, wt4, wt5, wt6, wt7,
                    );

                *res.get_unchecked_mut(k) = bf.0;
                *res.get_unchecked_mut(k + m) = bf.1;
                *res.get_unchecked_mut(k + 2 * m) = bf.2;
                *res.get_unchecked_mut(k + 3 * m) = bf.3;
                *res.get_unchecked_mut(k + 4 * m) = bf.4;
                *res.get_unchecked_mut(k + 5 * m) = bf.5;
                *res.get_unchecked_mut(k + 6 * m) = bf.6;
                *res.get_unchecked_mut(k + 7 * m) = bf.7;
            }
        }
        res
    }

    let n = f.len();
    debug_assert!(n > 8 && is_power_of(n as u32, 8), "the input size must be a power of 8 and greater than 8");
    debug_assert!(scratch.len() == NTT_BLOCK_SIZE_FOR_CACHE, "the scratch space must be NTT_BLOCK_SIZE_FOR_CACHE");
    // TODO: why slice?
    recurse(f, scratch, &precomp_small[..], &precomp_full[..], 0, n)
}

/// Precomputes twiddle factors needed for a stride-2 combination stage of an NTT.
/// @param n The size of the full NTT
/// @return Vector of w^i factors for i in 0..n/2
pub fn precomp_s2(n: usize) -> Vec<CF> {
    assert!(n.is_power_of_two(), "n must be a power of 2");
    assert!(n >= 2, "n must be at least 2");
    
    let w = get_root_of_unity(n);
    
    // Precompute w^i for i in 0..n/2
    let mut w_powers = Vec::with_capacity(n/2);
    let mut w_i = CF::one();
    
    for _ in 0..n/2 {
        w_powers.push(w_i);
        
        // Update for next iteration
        w_i = w_i * w;
    }
    
    w_powers
}

/// Precomputes twiddle factors needed for a stride-4 combination stage of an NTT.
/// @param n The size of the full NTT
/// @return Vector of [w^i, w^(2i), w^(3i)] arrays for i in 0..n/4
pub fn precomp_s4(n: usize) -> Vec<CF> {
    assert!(n.is_power_of_two(), "n must be a power of 2");
    assert!(n >= 4, "n must be at least 4");
    assert!(n % 4 == 0, "n must be divisible by 4");
    
    let w = get_root_of_unity(n);
    
    // Precompute w^i, w^(2i), w^(3i) for i in 0..n/4
    let subn = n / 4;
    let mut w_powers = Vec::with_capacity(subn);
    let mut w_i = CF::one();
    
    for _ in 0..subn {
        let w_2i = w_i * w_i;       // w^(2i)
        let w_3i = w_2i * w_i;      // w^(3i)

        w_powers.push(w_i);
        w_powers.push(w_2i);
        w_powers.push(w_3i);
        
        // Update for next iteration
        w_i = w_i * w;
    }
    
    w_powers
}


/// Performs a radix-8 NTT on the polynomial f.
/// Supports input sizes of the form 8^k * 2.
/// Uses precomputed twiddles.
/// precomp_small and precomp_full must be generated using precomp_for_ntt_r8_hybrid_p().
/// precomp_s2 must be generated using precomp_s2().
/// @param f The coefficients of the polynomial to be transformed.
/// @param scratch A scratch space for intermediate results.
/// @param precomp_small Precomputed twiddles for the base NTT.
/// @param precomp_full Precomputed twiddles for the higher layers.
/// @param precomp_s2 Precomputed twiddles for the stride-2 combination stage.
pub fn ntt_r8_s2_hybrid_p(
    f: &Vec<CF>,
    scratch: &mut [CF],
    precomp_small: &Vec<CF>,
    precomp_full: &Vec<CF>,
    precomp_s2: &Vec<CF>,
) -> Vec<CF> {
    let n = f.len();

    // Input length must be at least 16 and of the form (8^k) * 2
    assert!(n >= 16, "n must be at least 16");
    assert!(n % 2 == 0, "n must be divisible by 2");
    let half_n = n / 2;
    assert!(is_power_of((n / 2) as u32, 8), "n must be of the form (8^k) * 2");
    
    // Split input into even and odd parts
    let mut f_even = vec![CF::zero(); half_n];
    let mut f_odd = vec![CF::zero(); half_n];
    
    for i in 0..half_n {
        f_even[i] = f[2 * i];
        f_odd[i] = f[2 * i + 1];
    }
    
    // Perform radix-8 NTT on each half using precomputed twiddles
    let ntt_even = ntt_r8_hybrid_p(&mut f_even, scratch, &precomp_small, &precomp_full);
    let ntt_odd  = ntt_r8_hybrid_p(&mut f_odd,  scratch, &precomp_small, &precomp_full);
    
    // Combine using radix-2 butterfly operations with precomputed twiddles
    let mut res = vec![CF::zero(); n];
    
    for i in 0..half_n {
        // Get the precomputed twiddle factor
        let w_i = precomp_s2[i];
        
        // Perform the radix-2 butterfly
        res[i] = ntt_even[i] + w_i * ntt_odd[i];
        res[i + half_n] = ntt_even[i] - w_i * ntt_odd[i];
    }
    
    res
}

/// Performs a radix-8 NTT on the polynomial f.
/// Supports input sizes of the form 8^k * 4.
/// Uses precomputed twiddles.
/// precomp_small and precomp_full must be generated using precomp_for_ntt_r8_hybrid_p().
/// precomp_s4 must be generated using precomp_s4().
/// @param f The coefficients of the polynomial to be transformed.
/// @param scratch A scratch space for intermediate results.
/// @param precomp_small Precomputed twiddles for the base NTT.
/// @param precomp_full Precomputed twiddles for the higher layers.
/// @param precomp_s2 Precomputed twiddles for the stride-2 combination stage.
pub fn ntt_r8_s4_hybrid_p(
    f: &Vec<CF>,
    scratch: &mut [CF],
    precomp_small: &Vec<CF>,
    precomp_full: &Vec<CF>,
    precomp_s4: &Vec<CF>
) -> Vec<CF> {
    let n = f.len();

    // Input length must be at least 16 and of the form (8^k) * 2
    assert!(n >= 16, "n must be at least 16");
    assert!(n % 2 == 0, "n must be divisible by 2");
    let quarter_n = n / 4;
    assert!(is_power_of(quarter_n as u32, 8), "n must be of the form (8^k) * 4");
    
    // Split input into 4 parts with stride 4
    let mut f0 = vec![CF::zero(); quarter_n];
    let mut f1 = vec![CF::zero(); quarter_n];
    let mut f2 = vec![CF::zero(); quarter_n];
    let mut f3 = vec![CF::zero(); quarter_n];
    
    for i in 0..quarter_n {
        f0[i] = f[4*i];
        f1[i] = f[4*i + 1];
        f2[i] = f[4*i + 2];
        f3[i] = f[4*i + 3];
    }
    
    // Perform radix-8 NTT on each quarter using precomputed twiddles
    let ntt_f0 = ntt_r8_hybrid_p(&mut f0, scratch, &precomp_small, &precomp_full);
    let ntt_f1 = ntt_r8_hybrid_p(&mut f1, scratch, &precomp_small, &precomp_full);
    let ntt_f2 = ntt_r8_hybrid_p(&mut f2, scratch, &precomp_small, &precomp_full);
    let ntt_f3 = ntt_r8_hybrid_p(&mut f3, scratch, &precomp_small, &precomp_full);
    
    // Combine using radix-4 butterfly operations with precomputed twiddles
    let mut res = vec![CF::zero(); n];
    
    for i in 0..quarter_n {
        // Get precomputed twiddle factors for this position
        let w_i = precomp_s4[i * 3];
        let w_2i = precomp_s4[i * 3 + 1];
        let w_3i = precomp_s4[i * 3 + 2];
        
        // Apply twiddle factors to the NTT results
        let t0 = ntt_f0[i];
        let t1 = ntt_f1[i] * w_i;
        let t2 = ntt_f2[i] * w_2i;
        let t3 = ntt_f3[i] * w_3i;
        
        // Perform radix-4 butterfly operations
        let a0 = t0 + t2;
        let a1 = t0 - t2;
        let a2 = t1 + t3;
        let a3 = t1 - t3;
        
        // Using j = sqrt(-1)
        let a3_j = a3.mul_j();
        
        // Final combination using the radix-4 pattern
        res[i]                 = a0 + a2;
        res[i + quarter_n]     = a1 + a3_j;
        res[i + 2 * quarter_n] = a0 - a2;
        res[i + 3 * quarter_n] = a1 - a3_j;
    }
    
    res
}

/// Precompute precomp_full and precomp_small for ntt_r8_hybrid_p().
pub fn precomp_for_ntt_r8_hybrid_p(n: usize) -> (Vec<CF>, Vec<CF>) {
    let wn = get_root_of_unity(n);
    let precomp_full = if n < NTT_BLOCK_SIZE_FOR_CACHE {
        gen_precomp_full(n, wn, n)
    } else {
        gen_precomp_full(n, wn, NTT_BLOCK_SIZE_FOR_CACHE)
    };
    let precomp_small = if n < NTT_BLOCK_SIZE_FOR_CACHE {
        precomp_for_ntt_r8_ip_p(n, wn)
    } else {
        precomp_for_ntt_r8_ip_p(NTT_BLOCK_SIZE_FOR_CACHE, get_root_of_unity(NTT_BLOCK_SIZE_FOR_CACHE))
    };
    (precomp_small, precomp_full)
}

#[cfg(test)]
pub mod tests {
    use crate::cm31::CF;
    use crate::ntt::*;
    use rand::Rng;
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    /// Helper function to generate a Vec of random CF values.
    fn gen_rand_poly(n: usize, seed: u64) -> Vec<CF> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut poly = vec![CF::zero(); n];
        for i in 0..n {
            poly[i] = rng.r#gen();
        }
        poly
    }

    #[test]
    pub fn test_ntt_r8_vec() {
        for log8_n in 1..5 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);
            for seed in 0..4 {
                let f = gen_rand_poly(n, seed);

                let res = ntt_r8_vec(&f, wn);
                let expected = naive_ntt(&f);
                assert_eq!(res, expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_vec_p() {
        for log8_n in 1..5 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);
            let precomp = precomp_for_ntt_r8_vec_p(n, wn);
            for seed in 0..4 {
                let f = gen_rand_poly(n, seed);

                let res = ntt_r8_vec_p(&f, &precomp);
                let expected = naive_ntt(&f);
                assert_eq!(res, expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_ip() {
        for log8_n in 1..5 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);
            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let g = f.clone();
                let expected = ntt_r8_vec(&g, wn);

                ntt_r8_ip(&mut f, wn);
                assert_eq!(f, expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_ip_p() {
        for log8_n in 1..7 {
            let n = 8usize.pow(log8_n);
            let mut scratch = vec![CF::zero(); n];
            let wn = get_root_of_unity(n);
            let precomp = precomp_for_ntt_r8_ip_p(n, wn);
            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let g = f.clone();
                let expected = ntt_r8_vec(&g, wn);
                ntt_r8_ip_p(&mut f, &mut scratch, &precomp);
                assert_eq!(f, expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_hybrid() {
        for log8_n in 1..7 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);
            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let res = ntt_r8_hybrid(&mut f, wn);
                let expected = ntt_r8_vec(&f, wn);
                assert!(res == expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_hybrid_ps() {
        for log8_n in 1..8 {
            let n = 8usize.pow(log8_n);
            let wn = get_root_of_unity(n);

            // TODO: refactor
            let precomp_small = if n < NTT_BLOCK_SIZE_FOR_CACHE {
                precomp_for_ntt_r8_ip_p(n, wn)
            } else {
                precomp_for_ntt_r8_ip_p(NTT_BLOCK_SIZE_FOR_CACHE, get_root_of_unity(NTT_BLOCK_SIZE_FOR_CACHE))
            };

            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let res = ntt_r8_hybrid_ps(&mut f, wn, &precomp_small);
                let expected = ntt_r8_vec(&f, wn);
                assert!(res == expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_hybrid_p() {
        for log8_n in 2..8 {
            let n = 8usize.pow(log8_n);
            let mut scratch = vec![CF::zero(); NTT_BLOCK_SIZE_FOR_CACHE];
            let wn = get_root_of_unity(n);

            let (precomp_small, precomp_full) = precomp_for_ntt_r8_hybrid_p(n);

            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let res = ntt_r8_hybrid_p(&mut f, &mut scratch, &precomp_small, &precomp_full);
                let expected = ntt_r8_vec(&f, wn);
                assert!(res == expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_s2_hybrid_p() {
        for n in [1024, 65536] {
            let mut scratch = vec![CF::zero(); NTT_BLOCK_SIZE_FOR_CACHE];
            let wn = get_root_of_unity(n);

            let (precomp_small, precomp_full) = precomp_for_ntt_r8_hybrid_p(n / 2);
            let precomp_s2 = precomp_s2(n);

            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let res = ntt_r8_s2_hybrid_p(&mut f, &mut scratch, &precomp_small, &precomp_full, &precomp_s2);
                let expected = ntt_radix_2(&f, wn);
                assert!(res == expected);
            }
        }
    }

    #[test]
    pub fn test_ntt_r8_s4_hybrid_p() {
        for n in [2048, 131072] {
            let mut scratch = vec![CF::zero(); NTT_BLOCK_SIZE_FOR_CACHE];
            let wn = get_root_of_unity(n);

            let (precomp_small, precomp_full) = precomp_for_ntt_r8_hybrid_p(n / 4);
            let precomp_s4 = precomp_s4(n);

            for seed in 0..4 {
                let mut f = gen_rand_poly(n, seed);

                let res = ntt_r8_s4_hybrid_p(&mut f, &mut scratch, &precomp_small, &precomp_full, &precomp_s4);
                let expected = ntt_radix_2(&f, wn);
                assert!(res == expected);
            }
        }
    }
}
