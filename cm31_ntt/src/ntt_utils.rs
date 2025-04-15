use crate::cm31::{
    CF,
    gen_roots_of_unity,
    W_8,
};
use crate::rm31::RF;
use num_traits::{Zero, One};
use num_traits::pow::Pow;

//pub(crate) fn log_8(n: usize) -> usize {
    //let mut log = 0;
    //let mut m = n;
    //while m > 1 {
        //m /= 8;
        //log += 1;
    //}
    //log
//}

pub(crate) fn is_power_of_8(n: u32) -> bool {
    if n == 0 {
        return false;
    }

    let mut num = n;
    while num % 8 == 0 {
        num /= 8;
    }

    num == 1
}


/// Helper function to get the n-th root of unity in CF.
pub fn get_root_of_unity(n: usize) -> CF {
    assert!(n.is_power_of_two(), "n must be a power of 2");
    let roots_of_unity = gen_roots_of_unity((n as f64).log2() as usize);
    roots_of_unity[roots_of_unity.len() - 1]
}

pub(crate) fn level_offset(overall_transform_size: usize, d: usize) -> usize {
    let mut offset = 0;
    let mut current = overall_transform_size;
    for _ in 0..d {
        offset += 1 + 7 * (current / 8);
        current /= 8;
    }
    offset
}

/// A radix-4 NTT butterfly.
pub fn ntt_block_4(f: [CF; 4]) -> [CF; 4] {
    debug_assert_eq!(f.len(), 4);
    let mut res = [CF::zero(); 4];

    let a0 = f[0] + f[2];
    let a1 = f[0] - f[2];
    let a2 = f[1] + f[3];
    let a3 = f[1] - f[3];

    let a3_j = a3.mul_j();

    res[0] = a0 + a2;
    res[2] = a0 - a2;
    res[1] = a1 + a3_j;
    res[3] = a1 - a3_j;

    res
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
) -> [CF; 8] {
    let mut res = [CF::zero(); 8];

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

    res[0] = b0 + b4;
    res[4] = b0 - b4;
    res[2] = b1 + b5_j;
    res[6] = b1 - b5_j;
    res[1] = b2 + b6_w8;
    res[5] = b2 - b6_w8;
    res[3] = b3 + b7_j_w8;
    res[7] = b3 - b7_j_w8;

    res
}

/// A helper function to perform the NTT in a very simple but unoptimised O(n^2) way to test for
/// correctness of the optimised NTT functions.
pub fn naive_ntt(f: Vec<CF>) -> Vec<CF> {
    let n = f.len();
    let wn = get_root_of_unity(n);
    let mut res = vec![CF::zero(); f.len()];
    for i in 0..n {
        for j in 0..n {
            res[i] += f[j] * wn.pow(i * j);
        }
    }

    res
}

/// A helper function to perform the inverse NTT in a very simple but unoptimised O(n^2) way to
/// help test for correctness of the NTT.
pub fn naive_intt(f: Vec<CF>) -> Vec<CF> {
    let n = f.len();
    let wn = get_root_of_unity(n);

    let mut res = vec![CF::zero(); n];
    for i in 0..n {
        for j in 0..n {
            res[i] += f[j] * wn.pow(i * j).try_inverse().unwrap();
        }
    }
    for i in 0..n {
        res[i] = res[i].mul_by_f(RF::new(n as u32).try_inverse().unwrap());
    }

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

/// Precomputes twiddle factors needed for a stride-2 combination stage of an NTT.
/// @param n The size of the full NTT
/// @return Vector of w^i factors for i in 0..n/2
pub fn precompute_twiddles_stride2(n: usize) -> Vec<CF> {
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
pub fn precompute_twiddles_stride4(n: usize) -> Vec<[CF; 3]> {
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
        w_powers.push([w_i, w_2i, w_3i]);
        
        // Update for next iteration
        w_i = w_i * w;
    }
    
    w_powers
}
