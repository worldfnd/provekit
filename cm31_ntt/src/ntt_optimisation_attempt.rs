use crate::cm31::{CF, W_8};
use num_traits::Zero;
use crate::ntt_utils::*;

/// A radix-8 NTT butterfly.
/// @param read_from The slice of all coefficients of the original polynomial. In practice, it is
///                  the scratch array that do_ntt() uses to store the intermediate results.
/// @param write_to The slice to write the results to.
/// @param read_indices The indices of the coefficients in read_from to read from.
/// @param write_indices The indices of the coefficients in write_to to write to.
/// @param wts The twiddle factors 1 - 8 (excluding the 0th twiddle factor).
#[inline]
pub fn ntt_block_8_in_place(
    read_from: &mut [CF],
    write_to: &mut [CF],
    k: usize,
    m: usize,
    offset: usize,
    stride: usize,
    wt: CF,
    wt2: CF,
    wt3: CF,
    wt4: CF,
    wt5: CF,
    wt6: CF,
    wt7: CF,
) {
    // Refer to Yuval's Radix 8 DIT diagram.
    // 1st columm of black dots: a0-a8
    // 2nd columm of black dots: b0-b8
    // 3nd columm of black dots: res[0]-res[8]
    let t0 = read_from[0 + 8 * k];
    let t1 = read_from[1 + 8 * k] * wt;
    let t2 = read_from[2 + 8 * k] * wt2;
    let t3 = read_from[3 + 8 * k] * wt3;
    let t4 = read_from[4 + 8 * k] * wt4;
    let t5 = read_from[5 + 8 * k] * wt5;
    let t6 = read_from[6 + 8 * k] * wt6;
    let t7 = read_from[7 + 8 * k] * wt7;

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

    // Note that the order of the writes is in bit-reversed order (0, 4, 2, 6, 1, 5, 3, 7).
    write_to[offset + (k + 0 * m) * stride] = b0 + b4;
    write_to[offset + (k + 4 * m) * stride] = b0 - b4;
    write_to[offset + (k + 2 * m) * stride] = b1 + b5_j;
    write_to[offset + (k + 6 * m) * stride] = b1 - b5_j;
    write_to[offset + (k + 1 * m) * stride] = b2 + b6_w8;
    write_to[offset + (k + 5 * m) * stride] = b2 - b6_w8;
    write_to[offset + (k + 3 * m) * stride] = b3 + b7_j_w8;
    write_to[offset + (k + 7 * m) * stride] = b3 - b7_j_w8;
}


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

    for i in 0..n {
        scratch[i] = f[offset + i * stride];
    }

    let level_size = 1 + 7 * m;
    let lvl_offset = level_offset(overall_transform_size, depth);
    let level_twiddles = &twiddles[lvl_offset..lvl_offset + level_size];

    for k in 0..m {
        let base_idx = 1 + 7 * k;
        let wt = level_twiddles[base_idx];
        let wt2 = level_twiddles[base_idx + 1];
        let wt3 = level_twiddles[base_idx + 2];
        let wt4 = level_twiddles[base_idx + 3];
        let wt5 = level_twiddles[base_idx + 4];
        let wt6 = level_twiddles[base_idx + 5];
        let wt7 = level_twiddles[base_idx + 6];
        
        ntt_block_8_in_place(
            scratch.as_mut(),
            f,
            k,
            m,
            offset,
            stride,
            wt,
            wt2,
            wt3,
            wt4,
            wt5,
            wt6,
            wt7,
        );
    }
}

/// An in-place radix-8 NTT with precomputed twiddles.
/// @param f The input array to modify in-place.
/// @param twiddles The precomputed twiddles generated using precompute_twiddles().
pub fn ntt_radix_8_in_place(
    f: &mut [CF],
    twiddles: &[CF],
) {
    let n = f.len();
    debug_assert!(n >= 8, "N must be at least 8");
    debug_assert!(is_power_of_8(n as u32), "N must be a power of 8");

    let mut s = vec![CF::zero(); n];

    do_ntt(f, &mut s, &twiddles, 0, 1, n, 0, n);
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
    fn test_ntt() {
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

            let expected = ntt_radix_8(f.clone().to_vec(), w);

            ntt_radix_8_in_place(&mut f, &twiddles);

            let is_correct = f.to_vec() == expected;
            assert!(is_correct);
        }
    }
}
