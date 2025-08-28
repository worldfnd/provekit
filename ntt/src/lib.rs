use {
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    rayon::{
        iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
};

mod proptest;

// Taken from utils in noir-r1cs crate
/// Target single-thread workload size for `T`.
/// Should ideally be a multiple of a cache line (64 bytes)
/// and close to the L1 cache size (32 KB).
pub const fn workload_size<T: Sized>() -> usize {
    const CACHE_SIZE: usize = 1 << 15;
    CACHE_SIZE / size_of::<T>()
}

// Add type for power of 2 vector?
// Allows for

// TODO(xrvdg) Deal with reversed_ordered_roots that are finer grained than
// required for the current NTT .

/// In-place Number Theoretic Transform (NTT) from normal order to reverse bit
/// order.
///
/// # Arguments
/// * `reversed_ordered_roots` - Precomputed roots of unity in reverse bit
///   order.
/// * `input` - The input slice to be transformed in place.
pub fn ntt_nr(reversed_ordered_roots: &[Fr], input: &mut [Fr]) {
    // Reversed ordered roots idea from "Inside the FFT blackbox"

    // TODO(xrvdg) check the length of the roots and input
    // How to ensure that the right roots has been used. -> Typed argument for root
    // creation?

    let n = input.len();

    if n <= 1 {
        return;
    }
    assert!(n.is_power_of_two());

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
// Decimation in Time normal to reverse bit order which should be used once
// cache sized is reached.
fn dit_nr_cache(reverse_ordered_roots: &[Fr], segment: usize, input: &mut [Fr]) {
    let n = input.len();
    debug_assert!(n.is_power_of_two());

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

/// Bit reverses val given that for a given bit size
fn reverse_bits(val: usize, bits: u32) -> usize {
    // TODO(xrvdg) non-zero datatype?
    // requires 2^bits where bits>0. Because with zero this value
    val.reverse_bits() >> (usize::BITS - bits)
}

// TODO(xrvdg) Reuse the caching engine from WHIR to hide the generation
/// Precomputes the NTT roots of unity and stores them in bit-reversed order.
///
/// # Arguments
/// * `len` - The size of the NTT (must be a power of two).
///
/// # Returns
/// A vector of length `len / 2` containing the precomputed roots in
/// bit-reversed order.
///
/// # Panics
/// Panics if `len` is not a power of two or if a suitable root of unity does
/// not exist.
pub fn init_roots_reverse_ordered(len: usize) -> Vec<Fr> {
    let n = len / 2;
    match n {
        0 => vec![],
        1 => vec![Fr::ONE],
        n => {
            assert!(len.is_power_of_two());
            let root = Fr::get_root_of_unity(len as u64).unwrap();

            let mut roots = Vec::with_capacity(n);
            let uninit = roots.spare_capacity_mut();

            let mut omega_k = Fr::ONE;

            for index in 0..n {
                let rev = reverse_bits(index, n.trailing_zeros());
                uninit[rev].write(omega_k);
                omega_k *= root;
            }

            unsafe {
                roots.set_len(n);
            }

            roots
        }
    }
}

// Reorder the input in reverse bit order, allows to convert from normal order
// to reverse order or vice versa
fn reverse_order<T>(input: &mut [T]) {
    match input {
        [] | [_] => return,
        input => {
    let n = input.len();
            assert!(n.is_power_of_two());

            for index in 0..n {
                let rev = reverse_bits(index, n.trailing_zeros());
                if index < rev {
                    input.swap(index, rev);
                }
            }
        }
    }
}

/// Note: not specifically optimized
pub fn intt_rn(reverse_ordered_roots: &[Fr], input: &mut [Fr]) {
    reverse_order(input);
    intt_nr(reverse_ordered_roots, input);
    reverse_order(input);
}

// Inverse NTT
// TODO(xrvdg) How do the inverse roots of unity look like. For back conversion
pub fn intt_nr(reverse_ordered_roots: &[Fr], input: &mut [Fr]) {
    match input {
        [] => return,
        input => {
            // Reverse the input such that the roots act as inverse roots
            input[1..].reverse();
            ntt_nr(reverse_ordered_roots, input);

            let n = input.len();

            let factor = Fr::ONE / Fr::from(n as u64);

            for i in input.iter_mut() {
                *i *= factor;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{init_roots_reverse_ordered, intt_rn, ntt_nr, proptest::Vec2n, reverse_order},
        ark_bn254::Fr,
        ark_ff::BigInt,
        proptest::prelude::*,
    };
    // Generate a list that is a power of 2
    // Ensure that both above and below 1024 is triggered.
    // Compare it to a reference implementation, ideally not too slow.
    // Could also compare it to dit_cache with segment set to 0.
    // Another option is to do a inverse and check if the results are the same.
    // The crossovers make it more difficult to properly test it. On the other
    // hand make sure that it's above and belower working_size

    // Implement a strategy for power of two vector of Fr
    // Implement strategy

    // TODO(xrvdg) isn't there a more advanced proptest in block multiplier?
    prop_compose! {
        fn fr()(val in proptest::array::uniform4(0u64..)) -> Fr{
            Fr::new(BigInt(val))
        }
    }

    proptest! {
        #[test]
        fn round_trip_ntt(s in crate::proptest::vec2n(fr(), 0..3))
        {         // Convert input to field elements
            let mut s = s.0;
            let original = s.clone();
            let n = original.len();
            let roots = init_roots_reverse_ordered(n);

            // Forward NTT
            ntt_nr(&roots, &mut s);

            // Inverse NTT
            intt_rn(&roots, &mut s);

            prop_assert_eq!(s, original);
        }
    }

    proptest! {
        #[test]
        fn round_trip_reverse_order(mut v in proptest::collection::vec(any::<u32>(), 1024)){
            let original = v.clone();
            reverse_order(&mut v);
            reverse_order(&mut v);
            prop_assert_eq!(original, v)
        }
    }

    // Generate a value
    // Go to the nearest power of two
    // What is a proper way to generate the reverse bits
    // proptest! {
    //     #[test]
    //     fn round_trip_reverse_bits(){

    //     }
    // }

    // Separate test that it handles non-power of two gracefully?
    // Once proper guard is installed it could use debug asserts? Or just keep
    // using the power of two type
}
