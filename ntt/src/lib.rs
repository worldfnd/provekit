use {
    ark_bn254::Fr,
    rayon::{
        iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
};

/// Target single-thread workload size for `T`.
/// Should ideally be a multiple of a cache line (64 bytes)
/// and close to the L1 cache size (32 KB).
pub const fn workload_size<T: Sized>() -> usize {
    const CACHE_SIZE: usize = 1 << 15;
    CACHE_SIZE / size_of::<T>()
}

/// NTT from normal order to reverse order
pub fn ntt(reversed_ordered_roots: &[Fr], input: &mut [Fr]) {
    // Reversed ordered roots idea from "Inside the FFT blackbox"

    let n = input.len();

    // Each unique twiddle factor within a stage is a group.
    let mut pairs_in_group = n / 2;
    let mut num_of_groups = 1;

    // For small NTTs go directly to the NTT optimized for cache size
    if n > workload_size::<Fr>() {
        // Parallelizing over the groups is most effective but in the beginning there
        // aren't enough groups to occupy all threads.
        while num_of_groups < 32 {
            input
                .chunks_exact_mut(2 * pairs_in_group)
                .enumerate()
                .for_each(|(k, group)| {
                    let omega = reversed_ordered_roots[k];
                    let (evens, odds) = group.split_at_mut(pairs_in_group);

                    evens.par_iter_mut().zip(odds).for_each(|(even, odd)| {
                        (*even, *odd) = (*even + omega * *odd, *even - omega * *odd)
                    });
                });
            pairs_in_group /= 2;
            num_of_groups *= 2;
        }

        // Once the active set (2*pairs_in_group) reaches workload size switch to
        // cache-optimized NTT invariant: num_of_groups * pairs_of_groups = n
        // -> num_of_group / (workload_size / 2)
        while num_of_groups < n / (workload_size::<Fr>() / 2) {
            input
                .par_chunks_exact_mut(2 * pairs_in_group)
                .enumerate()
                .for_each(|(k, group)| {
                    let omega = reversed_ordered_roots[k];
                    let (evens, odds) = group.split_at_mut(pairs_in_group);

                    evens.iter_mut().zip(odds).for_each(|(even, odd)| {
                        (*even, *odd) = (*even + omega * *odd, *even - omega * *odd)
                    });
                });
            pairs_in_group /= 2;
            num_of_groups *= 2;
        }
    }

    input
        .par_chunks_exact_mut(2 * pairs_in_group)
        .enumerate()
        .for_each(|(k, group)| {
            dit_nr_cache(reversed_ordered_roots, k, group);
        })
}

// TODO(xrvdg) Add test and then change this implementation to be more rust-like
// can't really change the order of the roots
fn dit_nr_cache(reverse_ordered_roots: &[Fr], segment: usize, input: &mut [Fr]) {
    let n = input.len();

    let mut pairs_in_group = n / 2;
    let mut num_of_groups = 1;
    let mut distance = n / 2;

    while num_of_groups < n {
        let twiddle_base = segment * num_of_groups;
        for k in 0..num_of_groups {
            let twiddle = twiddle_base + k;
            let omega = reverse_ordered_roots[twiddle];
            let j_group = (2 * k * pairs_in_group..).take(pairs_in_group); // or distance
            for j in j_group {
                // println!("k: {k} jtwiddle: {jtwiddle} even: {j} odd:{}", j + distance);
                (input[j], input[j + distance]) = (
                    input[j] + omega * input[j + distance],
                    input[j] - omega * input[j + distance],
                )
            }
        }
        pairs_in_group /= 2;
        num_of_groups *= 2;
        distance /= 2;
    }
}

// proptest that takes a regular NTT written using horner multiplication and
// compare it to the reverse ordered NTT That would require
