use crate::cm31::CF;
use num_traits::Zero;
use num_traits::pow::Pow;
use crate::ntt_utils::is_power_of;
use crate::ntt_optimisation_attempt::ntt_radix_8_in_place;

/// @param f The coefficients of the polynomial to be transformed with length n.
/// @param The minimum length of f, and n should be a power of r.
/// @param w The n-th root of unity.
/// @param w_r The r-th root of unity.
/// @return The transformed polynomial in evaluation form.
pub fn ntt_radix_r(f: Vec<CF>, r: usize, w: CF, w_r: CF) -> Vec<CF> {
    let n = f.len();
    debug_assert!(n > r, "n must be greater than r");
    debug_assert!(is_power_of(n as u32, r as u32), "n must be a power of r");

    fn do_ntt(f: Vec<CF>, r: usize, w: CF, w_r: CF) -> Vec<CF> {
        let n = f.len();
        if n == 1 {
            return f;
        }

        let m = n / r;

        // Partition f into r subarrays.
        let mut a = vec![vec![CF::zero(); m]; r];

        for i in 0..m {
            let i_r = i * r;
            for j in 0..r {
                a[j][i] = f[i_r + j];
            }
        }

        let w_pow_r = w.pow(r);

        // Recurse
        let mut ntt_a = vec![vec![CF::zero(); m]; r];
        for i in 0..r {
            ntt_a[i] = do_ntt(a[i].clone(), r, w_pow_r, w_r);
        }

        let mut res = vec![CF::zero(); n];
        for k in 0..m {
            // Calculate twiddle factors
            let mut twiddles = vec![CF::zero(); r - 1];
            twiddles[0] = w.pow(k);
            for j in 1..r - 1 {
                twiddles[j] = twiddles[j - 1] * twiddles[0];
            }

            let mut f = vec![CF::zero(); r];
            f[0] = ntt_a[0][k];
            for j in 1..r {
                f[j] = ntt_a[j][k] * twiddles[j - 1];
            }

            let mut butterfly = f.clone();
            ntt_radix_8_in_place(&mut butterfly, w_r);

            //let butterfly = ntt_radix_8(f.clone(), w_r);

            for r in 0..r {
                res[k + r * m] = butterfly[r];
            }
        }
        res
    }

    do_ntt(f, r, w, w_r)
}

pub fn ntt_mixed_2x4096(
    f: &mut [CF],
    w: CF
) {
    const M: usize = 4096;
    let n = 2 * M;
    debug_assert!(f.len() == n, "mixed‑radix only supports len=8192 here");

    for k in 0..M {
        let a = f[k];
        let b = f[k + M];
        f[k]       = a + b;
        f[k + M]   = a - b;
    }

    for k in 0..M {
        f[k + M] = f[k + M] * w.pow(k);
    }

    // ——— 3) Two 4096‑point DIT NTTs ———
    // The 4096‑point root is w^2, since (w^2)^4096 = w^8192 = 1
    let w2 = w.pow(2);
    let (even_half, odd_half) = f.split_at_mut(M);
    ntt_radix_8_in_place(even_half, w2);
    ntt_radix_8_in_place(odd_half,  w2);

    // ——— 4) Final “even/odd” ↔ natural re‑interleave ———
    let mut tmp = Vec::with_capacity(n);
    tmp.resize(n, CF::zero());
    for k in 0..M {
        // weave them back: tmp[2*k] ← X(2*k), tmp[2*k+1] ← X(2*k+1)
        tmp[2*k]     = f[k];
        tmp[2*k + 1] = f[k + M];
    }
    f.copy_from_slice(&tmp);
}

pub fn ntt_mixed_8x64(f: &mut [CF], w: CF) {
    const R:  usize = 8;       // small radix
    const N2: usize = 64;    // big radix
    const N:  usize = R * N2;

    debug_assert_eq!(f.len(), N, "input must be length 32 768");

    //------------------------------------------------------------------
    // 1) 8‑point DIF butterflies on stride‑N2 columns
    //------------------------------------------------------------------
    let w_r = w.pow(N2);      // primitive 8‑th root  = w^64
    let mut col = [CF::zero(); R];   // stack buffer for one column

    for k in 0..N2 {
        // gather column { f[k + j·64] }
        for j in 0..R {
            col[j] = f[k + j * N2];
        }

        // 8‑point NTT in‑place
        ntt_radix_8_in_place(&mut col, w_r);

        // twiddle & scatter back
        for j in 0..R {
            let tw = w.pow(j * k);   // w^{j·k}
            f[k + j * N2] = col[j] * tw;
        }
    }

    //------------------------------------------------------------------
    // 2) Eight contiguous 64‑point NTTs (DIT) — uses in‑place kernel
    //------------------------------------------------------------------
    let w_n2 = w.pow(R);   // primitive 64‑th root  = w^8

    for j in 0..R {
        let block = &mut f[j * N2 .. (j + 1) * N2];
        ntt_radix_8_in_place(block, w_n2);
    }

    //------------------------------------------------------------------
    // 3) Final transpose  [ j·64 + k ]  →  [ k·8 + j ]
    //------------------------------------------------------------------
    let mut tmp = vec![CF::zero(); N];
    for k in 0..N2 {
        for j in 0..R {
            tmp[k * R + j] = f[j * N2 + k];
        }
    }
    f.copy_from_slice(&tmp);
}


#[cfg(test)]
pub mod tests {
    use crate::ntt::*;
    use crate::ntt_r::*;
    use crate::ntt_utils::*;
    use crate::cm31::CF;
    use num_traits::Zero;
    use rand::Rng;
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_ntt_radix_64() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let r = 64;
        let n = r * r;
        let w = get_root_of_unity(n);
        let w_r = get_root_of_unity(r);

        for _ in 0..4 {
            let mut f = vec![CF::zero(); n];
            for i in 0..n {
                f[i] = rng.r#gen();
            }
            let res = ntt_radix_r(f.clone(), r, w, w_r);
            let expected = ntt_radix_8(&f, w);
            assert!(res == expected);
        }
    }

    #[test]
    fn test_ntt_mixed_2_4096() {
        let n = 8192;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let w = get_root_of_unity(n);

        for _ in 0..1 {
            let mut f = vec![CF::zero(); n];
            for i in 0..n {
                f[i] = rng.r#gen();
            }
            let expected = ntt_8_stride_2(f.clone());

            ntt_mixed_2x4096(&mut f, w);

            assert!(f == expected);
        }
    }

    #[test]
    fn test_ntt_mixed_8_64() {
        let n = 64 * 8;
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let w = get_root_of_unity(n);

        for _ in 0..1 {
            let mut f = vec![CF::zero(); n];
            for i in 0..n {
                f[i] = rng.r#gen();
            }
            let expected = ntt_radix_8(&f, w);

            ntt_mixed_8x64(&mut f, w);

            assert!(f == expected);
        }
    }
}
