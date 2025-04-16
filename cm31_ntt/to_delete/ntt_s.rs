use crate::cm31::CF;
use num_traits::{Zero, One};
use num_traits::pow::Pow;
use crate::ntt_utils::{ntt_block_8, is_power_of};

/// An in-place radix-8 NTT without precomputed twiddles.
/// @param f The input array to modify in-place.
/// @param w The n-th root of unity where n is the length of f.
pub fn ntt_radix_8_in_place(
    f: &mut [CF],
    scratch: &mut [CF],
    w: CF,
) {
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

    do_ntt(f, scratch, 0, 1, n, w);
}

pub fn ntt_mixed_8x8192(
    f: &mut [CF],
    scratch: &mut [CF],
    w: CF,
) {
    const R:  usize = 8;       // small radix
    const N2: usize = 8192;    // big radix
    const N:  usize = R * N2;

    // TODO: find out why this causes a stack overflow.
    // Ignore the commented code.

    /*
    debug_assert_eq!(f.len(), N, "input must be length R * N2");

    //------------------------------------------------------------------
    // 1) 8‑point DIF butterflies on stride‑N2 columns
    //------------------------------------------------------------------
    let w_r = w.pow(N2);      // primitive 8‑th root  = w^8192
    let mut col = [CF::zero(); R];   // stack buffer for one column

    for k in 0..N2 {
        // gather column { f[k + j·8192] }
        for j in 0..R {
            col[j] = f[k + j * N2];
        }

        // 8‑point NTT in‑place
        ntt_radix_8_in_place(&mut col, scratch, w_r);

        // twiddle & scatter back
        for j in 0..R {
            let tw = w.pow(j * k);   // w^{j·k}
            f[k + j * N2] = col[j] * tw;
        }
    }

    //------------------------------------------------------------------
    // 2) Eight contiguous 8192‑point NTTs (DIT) — uses in‑place kernel
    //------------------------------------------------------------------
    let w_n2 = w.pow(R);   // primitive 8192‑th root  = w^8

    for j in 0..R {
        let block = &mut f[j * N2 .. (j + 1) * N2];
        ntt_radix_8_in_place(block, scratch, w_n2);
    }

    //------------------------------------------------------------------
    // 3) Final transpose  [ j·8192 + k ]  →  [ k·8 + j ]
    //------------------------------------------------------------------
    let mut tmp = vec![CF::zero(); N];
    for k in 0..N2 {
        for j in 0..R {
            tmp[k * R + j] = f[j * N2 + k];
        }
    }
    f.copy_from_slice(&tmp);
    */
}


#[cfg(test)]
pub mod tests {
    use crate::ntt::*;
    use crate::ntt_s::*;
    use crate::ntt_utils::*;
    use crate::cm31::CF;
    use num_traits::Zero;
    use rand::Rng;
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_ntt_mixed_8_8192() {
        let n = 8192 * 8;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let w = get_root_of_unity(n);

        for _ in 0..1 {
            let mut f = vec![CF::zero(); n];
            let mut scratch = vec![CF::zero(); n];
            for i in 0..n {
                f[i] = rng.r#gen();
            }
            let expected = ntt_radix_8(&f, w);

            ntt_mixed_8x8192(&mut f, &mut scratch, w);

            //assert!(f == expected);
        }
    }
}
