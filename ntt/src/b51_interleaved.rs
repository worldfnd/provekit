use {
    crate::workload_size,
    ark_bn254::Fr,
    bn254_multiplier::{
        constants::{self, U64_P_MULTIPLES},
        rne,
        utils::{self, addv, div_p_32b, subby, subtraction_reduce},
    },
    rayon::{
        iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
};

/// In-place Number Theoretic Transform (NTT) from normal order to reverse bit
/// order.
///
/// # Use Case
///
/// Use this function when you have multiple polynomials
/// stored in an interleaved fashion within a single vector, such as
/// `[a0, b0, c0, d0, a1, b1, c1, d1, ...]` for four polynomials `a`, `b`,
/// `c`, and `d`. By operating on interleaved data, you can perform the
/// NTT on all polynomials in-place without needing to first transpose
/// the data
///
/// # Arguments
/// * `reversed_ordered_roots` - Precomputed roots of unity in reverse bit
///   order.
/// * `values` - coefficients to be transformed in place with evaluation or vice
///   versa.
pub fn interleaved_ntt_nr(
    reversed_ordered_roots: &[Fr],
    values: &mut [Fr],
    codeword_size: usize,
    mut num_groups: usize,
) {
    // Reversed ordered roots idea from "Inside the FFT blackbox"
    // Implementation is a DIT NR algorithm

    // This conditional is here because chunk_size for *chunk_exact_mut can't be 0
    if codeword_size <= 1 {
        return;
    }

    assert!(codeword_size.is_power_of_two());

    // Each unique twiddle factor within a stage is a group.
    let mut elements_in_group = values.len() / num_groups;

    // num of groups is the same as inner inner ntt size
    // let mut num_groups = 1;

    // For large NTTs we start with linear scans through memory and once all the
    // elements of the sub NTTs reach the size of workload_size we know that they
    // are contiguous in cache memory and we switch over to a different strategy.
    // If at the start the NTT already fits in cache memory we go directly to the
    // cache strategy strategy.

    // These following two loops could be merged together, but in microbenchmarks
    // this split performs 5% better than nesting par_iter_mut inside
    // par_chunks_exact over the ranges 2ˆ20 to 2ˆ24.

    // Parallelizing over the groups is most effective but in the beginning there
    // aren't enough groups to occupy all threads.
    while num_groups < 32.min(codeword_size) && elements_in_group > workload_size::<Fr>() {
        values
            .chunks_exact_mut(elements_in_group)
            .enumerate()
            .for_each(|(k, group)| {
                let omega = reversed_ordered_roots[k];
                let (evens, odds) = group.split_at_mut(elements_in_group / 2);

                evens
                    .par_iter_mut()
                    .zip(odds)
                    .for_each(|(even, odd)| b51_kernel(even, odd, &omega));
            });
        elements_in_group /= 2;
        num_groups *= 2;
    }

    while num_groups < codeword_size && elements_in_group > workload_size::<Fr>() {
        values
            .par_chunks_exact_mut(elements_in_group)
            .enumerate()
            .for_each(|(k, group)| {
                let omega = reversed_ordered_roots[k];
                let (evens, odds) = group.split_at_mut(elements_in_group / 2);

                evens
                    .iter_mut()
                    .zip(odds)
                    .for_each(|(even, odd)| b51_kernel(even, odd, &omega));
            });
        elements_in_group /= 2;
        num_groups *= 2;
    }

    values
        .par_chunks_exact_mut(elements_in_group)
        .enumerate()
        .for_each(|(k, group)| {
            dit_nr_cache(reversed_ordered_roots, k, group, codeword_size / num_groups);
        });
}

pub fn dit_nr_cache(reverse_ordered_roots: &[Fr], segment: usize, input: &mut [Fr], size: usize) {
    let mut elements_in_group = input.len();
    let mut num_of_groups = 1;

    debug_assert!(size.is_power_of_two());

    while num_of_groups < size {
        let twiddle_base = segment * num_of_groups;
        for (k, group) in input.chunks_exact_mut(elements_in_group).enumerate() {
            let twiddle = twiddle_base + k;
            let omega = reverse_ordered_roots[twiddle];
            let (evens, odds) = group.split_at_mut(elements_in_group / 2);
            evens
                .iter_mut()
                .zip(odds)
                .for_each(|(even, odd)| b51_kernel(even, odd, &omega));
        }
        elements_in_group /= 2;
        num_of_groups *= 2;
    }
}

#[inline(always)]
fn b51_kernel(even: &mut Fr, odd: &mut Fr, omega: &Fr) {
    let f = rne::mono::mul(odd.0 .0, omega.0 .0);
    let l = subtraction_reduce(subby, addv(even.0 .0, f));
    let r = subtraction_reduce(
        subby,
        addv(even.0 .0, utils::sub(constants::U64_P_MULTIPLES[3], f)),
    );

    (even.0 .0) = l;
    (odd.0 .0) = r;
}

fn canonicalize_b51(values: &mut [Fr]) {
    for elem in values.iter_mut() {
        let reduced = subtraction_reduce(div_p_32b, elem.0 .0);
        let tentative = utils::sub(reduced, U64_P_MULTIPLES[1]);
        elem.0 .0 = if tentative[3] >> 63 == 1 {
            reduced
        } else {
            tentative
        };
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use {
        super::interleaved_ntt_nr,
        crate::{ark_interleaved, b51_interleaved::canonicalize_b51, ntt::extend_roots_table},
        ark_bn254::Fr,
        ark_ff::BigInt,
        proptest::{collection, prelude::*},
    };

    proptest! {
        #[test]
        fn b51_matches_ark(
            values in (1_usize..=15).prop_flat_map(|k| {
                let len = 1 << k;
                collection::vec(
                    proptest::array::uniform4(0u64..).prop_map(|val| Fr::new(BigInt(val))),
                    len..=len,
                )
            })
        ) {
            let codeword_size = values.len();
            let roots = extend_roots_table(codeword_size);

            let mut b51_out = values.clone();
            interleaved_ntt_nr(&roots.0, &mut b51_out, codeword_size, 1);
            canonicalize_b51(&mut b51_out);

            let mut ark_out = values;
            ark_interleaved::interleaved_ntt_nr(&roots.0, &mut ark_out, codeword_size, 1);

            prop_assert_eq!(b51_out, ark_out);
        }
    }
}
