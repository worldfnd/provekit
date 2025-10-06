use {
    crate::{Pow2OrZero, NTT},
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    rayon::{
        iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
};

// Taken from utils in noir-r1cs crate
/// Target single-thread workload size for `T`.
/// Should ideally be a multiple of a cache line (64 bytes)
/// and close to the L1 cache size (32 KB).
pub const fn workload_size<T: Sized>() -> usize {
    const CACHE_SIZE: usize = 1 << 15;
    CACHE_SIZE / size_of::<T>()
}

/// In-place Number Theoretic Transform (NTT) from normal order to reverse bit
/// order.
///
/// # Arguments
/// * `reversed_ordered_roots` - Precomputed roots of unity in reverse bit
///   order.
/// * `values` - coefficients to be transformed in place with evaluation or vice
///   versa.
pub fn ntt_nr(reversed_ordered_roots: &[Fr], values: &mut NTT<Fr>) {
    // Reversed ordered roots idea from "Inside the FFT blackbox"
    // Implementation is a DIT NR algorithm

    let input = &mut values.0;

    let n = input.len();

    if n <= 1 {
        return;
    }

    // Each unique twiddle factor within a stage is a group.
    let mut pairs_in_group = n / 2;
    let mut num_of_groups = 1;

    // For large NTTs we start with linear scans through memory and once all the
    // elements of the sub NTTs reach the size of workload_size we know that they
    // are contiguous in cache memory and we switch over to a different strategy.
    // If at the start the NTT already fits in cache memory we go directly to the
    // cache strategy strategy.
    if n > workload_size::<Fr>() {
        // These two loops could be merged together, but in microbenchmarks this split
        // performs 5% better than nesting par_iter_mut inside par_chunks_exact
        // over the ranges 2ˆ20 to 2ˆ24.

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
        });
}

fn dit_nr_cache(reverse_ordered_roots: &[Fr], segment: usize, input: &mut [Fr]) {
    let n = input.len();
    debug_assert!(n.is_power_of_two());

    let mut pairs_in_group = n / 2;
    let mut num_of_groups = 1;

    while num_of_groups < n {
        let twiddle_base = segment * num_of_groups;
        for (k, group) in input.chunks_exact_mut(2 * pairs_in_group).enumerate() {
            let twiddle = twiddle_base + k;
            let omega = reverse_ordered_roots[twiddle];
            let (evens, odds) = group.split_at_mut(pairs_in_group);
            evens.iter_mut().zip(odds).for_each(|(even, odd)| {
                (*even, *odd) = (*even + omega * *odd, *even - omega * *odd)
            });
        }
        pairs_in_group /= 2;
        num_of_groups *= 2;
    }
}

/// Bit reverses val for a given bit size
///
/// Requires:
/// - bits > 0
/// - val < 2^bits
fn reverse_bits(val: usize, bits: u32) -> usize {
    debug_assert!(val < 2_usize.pow(bits));
    debug_assert!(bits > 0);
    // shift will overflow if bits = 0
    val.reverse_bits() >> (usize::BITS - bits)
}

// TODO(xrvdg) Caching engine from WHIR
/// Precomputes the NTT roots of unity and stores them in bit-reversed order.
///
/// # Arguments
/// * `len` - The size of the NTT
///
/// # Returns
/// A vector of length `len / 2` containing the precomputed roots in
/// bit-reversed order.
pub fn init_roots_reverse_ordered(len: Pow2OrZero) -> Vec<Fr> {
    let len = len.0;
    let n = len / 2;
    match n {
        0 => vec![],
        // 1 is a separate case due to `1.trailing_zeros = 0` which reverse_bit requires >0
        1 => vec![Fr::ONE],
        n => {
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
fn reverse_order<T>(values: &mut NTT<T>) {
    match values.0.as_mut_slice() {
        [] | [_] => (),
        input => {
            let n = input.len();

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
pub fn intt_rn(reverse_ordered_roots: &[Fr], input: &mut NTT<Fr>) {
    reverse_order(input);
    intt_nr(reverse_ordered_roots, input);
    reverse_order(input);
}

// Inverse NTT
pub fn intt_nr(reverse_ordered_roots: &[Fr], input: &mut NTT<Fr>) {
    match input.0.len() {
        0 => (),
        n => {
            // Reverse the input such that the roots act as inverse roots
            input.0[1..].reverse();
            ntt_nr(reverse_ordered_roots, input);

            let factor = Fr::ONE / Fr::from(n as u64);

            for i in input.0.iter_mut() {
                *i *= factor;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{init_roots_reverse_ordered, intt_rn, ntt_nr, reverse_order},
        crate::NTT,
        ark_bn254::Fr,
        ark_ff::BigInt,
        proptest::{collection, prelude::*},
        std::fmt,
    };

    fn fr() -> impl Strategy<Value = Fr> + Clone {
        proptest::array::uniform4(0u64..).prop_map(|val| Fr::new(BigInt(val)))
    }

    /// Generates a strategy for creating `NTT<T>` instances of length 2^k,
    /// where `k` is sampled from the provided `sizes` strategy.
    ///
    /// # Arguments
    /// * `sizes` - A strategy yielding the exponent `k` such that the NTT
    ///   length is 2^k.
    /// * `elem` - A strategy for generating elements of type `T` to fill the
    ///   NTT.
    ///
    /// # Returns
    /// A strategy that produces valid `NTT<T>` instances of the specified
    /// length.
    fn ntt<T: fmt::Debug>(
        sizes: impl Strategy<Value = usize>,
        elem: impl Strategy<Value = T> + Clone,
    ) -> impl Strategy<Value = NTT<T>> {
        sizes
            .prop_map(|k| 1 << k)
            .prop_flat_map(move |len| collection::vec(elem.clone(), len..=len))
            .prop_map(|v| NTT::new(v).unwrap())
    }

    proptest! {
        #[test]
        fn round_trip_ntt(original in ntt(0_usize..15, fr()))
        {
            let mut s = original.clone();
            let roots = init_roots_reverse_ordered(original.len());

            // Forward NTT
            ntt_nr(&roots, &mut s);

            // Inverse NTT
            intt_rn(&roots, &mut s);

            prop_assert_eq!(original,s);
        }
    }

    #[test]
    // The roundtrip test doesn't test size 0.
    fn ntt_empty() {
        let mut v = NTT::new(vec![]).unwrap();
        let roots = init_roots_reverse_ordered(v.len());
        ntt_nr(&roots, &mut v);
    }

    proptest! {
        #[test]
        fn round_trip_reverse_order(original in ntt(0_usize..10, any::<u32>())){
            let mut v = original.clone();
            reverse_order(&mut v);
            reverse_order(&mut v);
            prop_assert_eq!(original, v)
        }
    }

    proptest! {
        #[test]
        fn reverse_order_noop(original in ntt(0_usize..=1, any::<u32>())) {
            let mut v = original.clone();
            reverse_order(&mut v);
            assert_eq!(original, v)
        }

    }
}
