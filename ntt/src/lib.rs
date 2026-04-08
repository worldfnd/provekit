#![feature(vec_split_at_spare)]
pub mod ntt;
pub use ntt::*;
pub mod ark_interleaved;
pub mod b51_interleaved;

/// Generates an NTT for a given element type and butterfly
/// kernel.
///
/// Usage:
/// ```ignore
/// define_ntt_loops!(interleaved_ntt_nr, Fr, ark_kernel);
/// ```
///
/// Expanding a macro rather than using a generic function avoids the ~2–3%
/// regression caused by generic boundaries inhibiting LLVM's loop/vectorisation
/// optimisations even when the kernel is monomorphised.
#[macro_export]
macro_rules! define_ntt {
    ($ntt_fn:ident, $T:ty, $kernel:ident) => {
        /// In-place Number Theoretic Transform (NTT) from normal order to
        /// reverse bit order.
        ///
        /// Use when multiple polynomials are stored interleaved:
        /// `[a0, b0, a1, b1, ...]`. Operates on all polynomials in-place
        /// without a prior transpose.
        ///
        /// * `reversed_ordered_roots` — precomputed roots of unity in reverse bit
        ///   order.
        /// * `values` — coefficients transformed in place.
        pub(crate) fn $ntt_fn(
            reversed_ordered_roots: &[$T],
            values: &mut [$T],
            codeword_size: usize,
            mut num_groups: usize,
        ) {
            use rayon::{
                iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
                slice::ParallelSliceMut,
            };

            fn dit_nr_cache(
                reverse_ordered_roots: &[$T],
                segment: usize,
                input: &mut [$T],
                size: usize,
            ) {
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
                            .for_each(|(even, odd)| $kernel(even, odd, &omega));
                    }
                    elements_in_group /= 2;
                    num_of_groups *= 2;
                }
            }

            if codeword_size <= 1 {
                return;
            }

            assert!(codeword_size.is_power_of_two());

            let mut elements_in_group = values.len() / num_groups;

            while num_groups < 32.min(codeword_size)
                && elements_in_group > $crate::workload_size::<$T>()
            {
                values
                    .chunks_exact_mut(elements_in_group)
                    .enumerate()
                    .for_each(|(k, group)| {
                        let omega = reversed_ordered_roots[k];
                        let (evens, odds) = group.split_at_mut(elements_in_group / 2);
                        evens
                            .par_iter_mut()
                            .zip(odds)
                            .for_each(|(even, odd)| $kernel(even, odd, &omega));
                    });
                elements_in_group /= 2;
                num_groups *= 2;
            }

            while num_groups < codeword_size && elements_in_group > $crate::workload_size::<$T>() {
                values
                    .par_chunks_exact_mut(elements_in_group)
                    .enumerate()
                    .for_each(|(k, group)| {
                        let omega = reversed_ordered_roots[k];
                        let (evens, odds) = group.split_at_mut(elements_in_group / 2);
                        evens
                            .iter_mut()
                            .zip(odds)
                            .for_each(|(even, odd)| $kernel(even, odd, &omega));
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
    };
}
