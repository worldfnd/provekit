use crate::cm31::{CF, gen_roots_of_unity, W_8};
use crate::rm31::RF;
use num_traits::{Zero, One};
use num_traits::pow::Pow;
use rayon::prelude::*;

pub fn is_power_of(n: u32, x: u32) -> bool {
    if n == 0 {
        return false;
    }

    if x == 1 && n == 1 {
        return true;
    }

    if x == 1 && n != 1 {
        return false;
    }

    let mut num = n;
    while num % x == 0 {
        num /= x;
    }

    num == 1
}


/// Helper function to get the n-th root of unity in CF.
pub fn get_root_of_unity(n: usize) -> CF {
    assert!(n.is_power_of_two(), "n must be a power of 2");
    let roots_of_unity = gen_roots_of_unity((n as f64).log2() as usize);
    roots_of_unity[roots_of_unity.len() - 1]
}

/// A radix-8 NTT butterfly.
#[inline]
pub fn ntt_block_8(
    f0: CF,
    f1: CF,
    f2: CF,
    f3: CF,
    f4: CF,
    f5: CF,
    f6: CF,
    f7: CF,
    wt: CF,
    wt2: CF,
    wt3: CF,
    wt4: CF,
    wt5: CF,
    wt6: CF,
    wt7: CF,
) -> (CF, CF, CF, CF, CF, CF, CF, CF) {
    // Refer to Yuval's Radix 8 DIT diagram.
    // 1st columm of black dots: a0-a8
    // 2nd columm of black dots: b0-b8
    // 3nd columm of black dots: res[0]-res[8]

    let t0 = f0;
    let t1 = f1 * wt;
    let t2 = f2 * wt2;
    let t3 = f3 * wt3;
    let t4 = f4 * wt4;
    let t5 = f5 * wt5;
    let t6 = f6 * wt6;
    let t7 = f7 * wt7;

    // Column 1
    let a0 = t0 + t4;
    let a1 = t0 - t4;
    let a2 = t2 + t6;
    let a3 = t2 - t6;
    let a4 = t1 + t5;
    let a5 = t1 - t5;
    let a6 = t3 + t7;
    let a7 = t3 - t7;

    // Column 2
    let a3_j = a3.mul_j();
    let a7_j = a7.mul_j();

    let b0 = a0 + a2;
    let b1 = a0 - a2;
    let b2 = a1 + a3_j;
    let b3 = a1 - a3_j;
    let b4 = a4 + a6;
    let b5 = a4 - a6;
    let b6 = a5 + a7_j;
    let b7 = a5 - a7_j;

    // Column 3
    let b5_j = b5.mul_j();
    let b7_j = b7.mul_j();
    let b6_w8 = b6 * W_8;
    let b7_j_w8 = b7_j * W_8;

    let res0 = b0 + b4;
    let res4 = b0 - b4;
    let res2 = b1 + b5_j;
    let res6 = b1 - b5_j;
    let res1 = b2 + b6_w8;
    let res5 = b2 - b6_w8;
    let res3 = b3 + b7_j_w8;
    let res7 = b3 - b7_j_w8;

    (res0, res1, res2, res3, res4, res5, res6, res7)
}

pub fn naive_ntt(f: &Vec<CF>) -> Vec<CF> {
    let n = f.len();
    let wn = get_root_of_unity(n);
    let mut res = vec![CF::zero(); n];
    
    // Parallelize the outer loop
    res.par_iter_mut().enumerate().for_each(|(i, res_i)| {
        // Each thread computes one output element
        let wni = wn.pow(i);
        let mut wnij = wni;
        *res_i = f[0];
        for j in 1..(n - 1) {
            *res_i += f[j] * wnij;
            wnij *= wni;
        }
        *res_i += f[n - 1] * wnij;
    });

    res
}

pub fn naive_intt(f: &Vec<CF>) -> Vec<CF> {
    let n = f.len();
    let wn = get_root_of_unity(n);
    let n_inv = RF::new(n as u32).try_inverse().unwrap();

    let mut res = vec![CF::zero(); n];
    
    // Parallelize the outer loop for computing values
    res.par_iter_mut().enumerate().for_each(|(i, res_i)| {
        for j in 0..n {
            *res_i += f[j] * wn.pow(i * j).try_inverse().unwrap();
        }
        // Apply scaling factor
        *res_i = res_i.mul_by_f(n_inv);
    });

    res
}

/// Precomputes twiddle factors for a given size `n`.
/// @param n The size of the NTT (must be a power of 2).
/// @param w The nth root of unity
/// @param radix The butterfly size
/// @return A vector of precomputed twiddle factors.
pub fn precompute_twiddles(n: usize, w: CF, radix: usize) -> Vec<CF> {
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

#[cfg(test)]
pub mod tests {
    use crate::ntt_utils::*;
    use num_traits::Zero;
    use rand::Rng;
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_is_power_of() {
        assert!(is_power_of(1, 1));
        assert!(is_power_of(1, 2));
        assert!(is_power_of(8, 2));
        assert!(is_power_of(1024, 2));
        assert!(is_power_of(64, 8));
        assert!(!is_power_of(2, 1));
        assert!(!is_power_of(8, 3));
    }

    // Schoolbook multiplication
    fn naive_poly_mul(
        f1: &Vec<CF>,
        f2: &Vec<CF>,
    ) -> Vec<CF> {
        let n = f1.len();
        assert_eq!(n, f2.len());
        let mut res = vec![CF::zero(); 2 * n - 1];
        for i in 0..n {
            for j in 0..n {
                res[i + j] += f1[i] * f2[j];
            }
        }
        res
    }

    #[test]
    fn test_naive_poly_mul() {
        let f1 = vec![CF::new(1, 0), CF::new(2, 0), CF::new(3, 0), CF::new(4, 0)];
        let f3 = vec![CF::new(1, 0), CF::new(3, 0), CF::new(5, 0), CF::new(7, 0)];
        let res = naive_poly_mul(&f1, &f3);
        let expected = vec![CF::new(1, 0), CF::new(5, 0), CF::new(14, 0), CF::new(30, 0), CF::new(41, 0), CF::new(41, 0), CF::new(28, 0)];
        assert_eq!(res, expected);
    }

    #[test]
    fn test_naive_ntt_by_property() {
        // Test the correctness of the native NTT and inverse NTT functions.
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for n in [2, 4, 8] {
            let mut poly1 = vec![CF::zero(); n];
            let mut poly2 = vec![CF::zero(); n];
            for i in 0..n {
                poly1[i] = rng.r#gen();
                poly2[i] = rng.r#gen();
            }

            let mut poly1_padded = vec![CF::zero(); n * 2];
            let mut poly2_padded = vec![CF::zero(); n * 2];

            for i in 0..n {
                poly1_padded[i] = poly1[i];
                poly2_padded[i] = poly2[i];
            }

            let poly1_ntt = naive_ntt(&poly1_padded);
            let poly2_ntt = naive_ntt(&poly2_padded);
            let mut product_ntt = vec![CF::zero(); n * 2];

            for i in 0..n * 2 {
                product_ntt[i] = poly1_ntt[i] * poly2_ntt[i];
            }
            let product_poly = naive_intt(&product_ntt);
            let expected_product = naive_poly_mul(&poly1, &poly2);

            for i in 0..expected_product.len() {
                assert_eq!(product_poly[i], expected_product[i]);
            }
        }
    }
}
