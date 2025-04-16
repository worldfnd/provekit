use crate::cm31::CF;
use num_traits::Zero;
use num_traits::One;
use num_traits::Pow;
use crate::ntt_utils::*;

fn do_ntt(
    f: &mut [CF],
    scratch: &mut [CF],
    twiddles: &[CF],
    offset: usize,
    stride: usize,
    n: usize,
    depth: usize,
    overall_transform_size: usize,
) {
    if n == 1 {
        return;
    }

    let m = n / 8;

    for r in 0..8 {
        do_ntt(f, scratch, twiddles, offset + r * stride, stride * 8, m, depth + 1, overall_transform_size);
    }

    unsafe {
        for i in 0..n {
            scratch[i] = *f.get_unchecked(offset + i * stride);
        }

        let lvl_offset = level_offset(overall_transform_size, depth);

        for k in 0..m {
            let base_idx = lvl_offset + 1 + 7 * k;
            let wt =  twiddles.get_unchecked(base_idx);
            let wt2 = twiddles.get_unchecked(base_idx + 1);
            let wt3 = twiddles.get_unchecked(base_idx + 2);
            let wt4 = twiddles.get_unchecked(base_idx + 3);
            let wt5 = twiddles.get_unchecked(base_idx + 4);
            let wt6 = twiddles.get_unchecked(base_idx + 5);
            let wt7 = twiddles.get_unchecked(base_idx + 6);

            let k8 = k * 8;
            let res = ntt_block_8(
                *scratch.get_unchecked(0 + k8),
                *scratch.get_unchecked(1 + k8),
                *scratch.get_unchecked(2 + k8),
                *scratch.get_unchecked(3 + k8),
                *scratch.get_unchecked(4 + k8),
                *scratch.get_unchecked(5 + k8),
                *scratch.get_unchecked(6 + k8),
                *scratch.get_unchecked(7 + k8),
                *wt,
                *wt2,
                *wt3,
                *wt4,
                *wt5,
                *wt6,
                *wt7,
            );

            for j in 0..8 {
                f[offset + (k + j * m) * stride] = *res.get_unchecked(j);
            }
        }
    }
}

/// An in-place radix-8 NTT with precomputed twiddles.
/// @param f The input array to modify in-place.
/// @param twiddles The precomputed twiddles generated using precompute_twiddles().
pub fn ntt_radix_8_in_place_precomputed(
    f: &mut [CF],
    twiddles: &[CF],
) {
    let n = f.len();
    debug_assert!(n >= 8, "N must be at least 8");
    debug_assert!(is_power_of(n as u32, 8), "N must be a power of 8");

    let mut s = vec![CF::zero(); n];

    do_ntt(f, &mut s, &twiddles, 0, 1, n, 0, n);
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

        let m      = n / 8;
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

                for j in 0..8 {
                    *f.get_unchecked_mut(offset + (k + j * m) * stride) =
                        *res.get_unchecked(j);
                }
            }
        }
    }

    let n = f.len();
    debug_assert!(n >= 8, "N must be at least 8");
    debug_assert!(is_power_of(n as u32, 8), "N must be a power of 8");

    let mut scratch = vec![CF::zero(); n];
    do_ntt(f, &mut scratch, 0, 1, n, w);
}

#[cfg(test)]
pub mod tests {
    use crate::ntt::*;
    use crate::ntt_optimisation_attempt::*;
    use crate::cm31::CF;
    use num_traits::Zero;
    use rand::Rng;
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_ntt_in_place() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let n = 512;
        let w = get_root_of_unity(n);
        let radix = 8;

        for _ in 0..4 {
            let mut f = vec![CF::zero(); 512];
            for i in 0..n {
                f[i] = rng.r#gen();
            }

            let expected = ntt_radix_8(&f, w);

            ntt_radix_8_in_place(&mut f, w);

            let is_correct = f.to_vec() == expected;
            assert!(is_correct);
        }
    }

    #[test]
    fn test_ntt_in_place_precomputed() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let n = 512;
        let w = get_root_of_unity(n);
        let radix = 8;
        let twiddles = precompute_twiddles(n, w, radix);

        for _ in 0..4 {
            let mut f = vec![CF::zero(); 512];
            for i in 0..n {
                f[i] = rng.r#gen();
            }

            let expected = ntt_radix_8(&f, w);

            ntt_radix_8_in_place_precomputed(&mut f, &twiddles);

            let is_correct = f.to_vec() == expected;
            assert!(is_correct);
        }
    }
}
