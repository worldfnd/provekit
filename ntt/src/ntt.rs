use {
    crate::{NTTContainer, Pow2, NTT},
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    rayon::{
        iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
    std::{
        mem::size_of,
        sync::{LazyLock, RwLock},
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

/// NTTEngine allows for reusing twiddle factors between computations
pub struct NTTEngine(Vec<Fr>);

impl NTTEngine {
    /// Initialize an NTT Engine
    ///
    /// Note: new will initialize half a L1 cache size worth of twiddle factors
    pub fn new() -> Self {
        let init = init_roots_reverse_ordered(
            Pow2::new(workload_size::<Fr>().next_power_of_two()).unwrap(),
            None,
        );
        NTTEngine(init)
    }

    /// Initialize an NTT Engine of the given order
    ///
    /// Note: with_order will initialise at least half a L1 cache size worth of
    /// twiddle factors.
    pub fn with_order(order: Pow2<usize>) -> Self {
        let init = init_roots_reverse_ordered(
            Pow2::new(workload_size::<Fr>().next_power_of_two()).unwrap(),
            Some(*order / 2),
        );
        let mut engine = NTTEngine(init);
        engine.extend_roots_table(order);
        engine
    }

    /// extend_roots_table extends the current roots table if it's smaller than
    /// the required order.
    ///
    /// When there is not enough space available in the underlying vector the
    /// old roots will be copied over and they do not have to be recomputed.
    ///
    /// The new roots are computed in parallel based on the old roots thus
    /// ensure a large enough initial root table for proper parallelization.
    fn extend_roots_table(&mut self, order: Pow2<usize>) {
        let table = &mut self.0;

        // The size of the twiddle factor table is half that of the order due to
        // symmetry under multiplication by -1.
        let old_half_order = table.len();
        let new_half_order = *order / 2;

        if new_half_order > old_half_order {
            let col_len = new_half_order / old_half_order;
            let unity = Fr::get_root_of_unity(*order as u64).unwrap();
            table.reserve_exact(new_half_order - old_half_order);
            let (init, uninit) = table.split_at_spare_mut();

            // When viewing the roots as a matrix every row is a multiple of the first row
            // row[j] = row[0] * unity^(reverse order j)

            uninit
                .par_chunks_mut(old_half_order)
                .enumerate()
                .for_each(|(i, row)| {
                    // start counting from one as 0 is init above
                    let pow = reverse_bits(1 + i, col_len.trailing_zeros());
                    let root = unity.pow([pow as u64]);
                    row.par_iter_mut().enumerate().for_each(|(j, elem)| {
                        elem.write(init[j] * root);
                    })
                });

            unsafe {
                table.set_len(new_half_order);
            }
        }
    }

    // Returns the maximum order that it supports without extention
    fn order(&self) -> Pow2<usize> {
        Pow2(self.0.len() * 2)
    }
}

static ENGINE: LazyLock<RwLock<NTTEngine>> = LazyLock::new(|| RwLock::new(NTTEngine::new()));

/// Performs an in-place, interleaved Number Theoretic Transform (NTT) in
/// normal-to-reverse bit order.
///
/// # Arguments
/// * `values` - A mutable reference to an NTT container holding the
///   coefficients to be transformed.
pub fn ntt_nr<C: NTTContainer<Fr>>(values: &mut NTT<Fr, C>) {
    let roots = ENGINE.read().unwrap();
    let new_root = if roots.order() >= values.order() {
        roots
    } else {
        // Drop read lock
        drop(roots);
        let mut roots = ENGINE.write().unwrap();
        roots.extend_roots_table(values.order());
        // Drop write lock
        drop(roots);
        ENGINE.read().unwrap()
    };

    interleaved_ntt_nr(&new_root.0, values)
}

impl Default for NTTEngine {
    fn default() -> Self {
        Self::new()
    }
}

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
fn interleaved_ntt_nr<C: NTTContainer<Fr>>(reversed_ordered_roots: &[Fr], values: &mut NTT<Fr, C>) {
    // Reversed ordered roots idea from "Inside the FFT blackbox"
    // Implementation is a DIT NR algorithm

    let n = values.len();

    // The order of the interleaved NTTs themselves
    let order = values.order().0;

    // This conditional is here because chunk_size for *chunk_exact_mut can't be 0
    if order <= 1 {
        return;
    }

    let number_of_polynomials = n / order;

    // Each unique twiddle factor within a stage is a group.
    let mut pairs_in_group = n / 2;
    let mut num_of_groups = 1;

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
    while num_of_groups < 32.min(order) && 2 * pairs_in_group > workload_size::<Fr>() {
        values
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

    while num_of_groups < order && 2 * pairs_in_group > workload_size::<Fr>() {
        values
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

    values
        .par_chunks_exact_mut(2 * pairs_in_group)
        .enumerate()
        .for_each(|(k, group)| {
            dit_nr_cache(reversed_ordered_roots, k, group, number_of_polynomials);
        });
}

fn dit_nr_cache(
    reverse_ordered_roots: &[Fr],
    segment: usize,
    input: &mut [Fr],
    num_of_polys: usize,
) {
    let n = input.len();
    debug_assert!(n.is_power_of_two());

    let mut pairs_in_group = n / 2;
    let mut num_of_groups = 1;

    let single_n = n / num_of_polys;

    while num_of_groups < single_n {
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

/// Precomputes the NTT roots of unity and stores them in bit-reversed order.
///
/// # Arguments
/// * `len` - The size of the NTT
///
/// # Returns
/// A vector of length `len / 2` containing the precomputed roots in
/// bit-reversed order.
///
/// # Parameters
/// * `order` - The order of the NTT (must be a power of 2 or zero)
/// * `capacity` - Optional capacity hint for the vector. If `None`, defaults to
///   `n`. If provided, will use `max(capacity, n)` to ensure sufficient space.
fn init_roots_reverse_ordered(order: Pow2<usize>, capacity: Option<usize>) -> Vec<Fr> {
    match *order / 2 {
        0 => vec![],
        // 1 is a separate case due to `1.trailing_zeros = 0` which reverse_bit requires >0
        1 => vec![Fr::ONE],
        n => {
            // Use provided capacity or default to n, ensuring it's at least n
            let actual_capacity = capacity.map_or(n, |cap| cap.max(n));

            let root = Fr::get_root_of_unity(*order as u64).unwrap();

            let mut roots = Vec::with_capacity(actual_capacity);
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
fn reverse_order<T, C: NTTContainer<T>>(values: &mut NTT<T, C>) {
    match *values.order() {
        0 | 1 => (),
        n => {
            for index in 0..n {
                let rev = reverse_bits(index, n.trailing_zeros());
                if index < rev {
                    values.swap(index, rev);
                }
            }
        }
    }
}

/// Note: not specifically optimized
pub fn intt_rn<C: NTTContainer<Fr>>(input: &mut NTT<Fr, C>) {
    reverse_order(input);
    intt_nr(input);
    reverse_order(input);
}

// Inverse NTT
fn intt_nr<C: NTTContainer<Fr>>(values: &mut NTT<Fr, C>) {
    match *values.order() {
        0 => (),
        n => {
            // Reverse the input such that the roots act as inverse roots
            values[1..].reverse();
            ntt_nr(values);

            let factor = Fr::ONE / Fr::from(n as u64);

            for i in values.iter_mut() {
                *i *= factor;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use proptest::prelude::*;
    use {
        super::{init_roots_reverse_ordered, reverse_order},
        crate::{
            ntt::{intt_rn, NTTEngine},
            ntt_nr, Pow2, NTT,
        },
        ark_bn254::Fr,
        ark_ff::BigInt,
        proptest::collection,
        std::{
            fmt,
            num::{NonZero, NonZeroUsize},
        },
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
        number_of_polynomials: usize,
        elem: impl Strategy<Value = T> + Clone,
    ) -> impl Strategy<Value = NTT<T, Vec<T>>> {
        sizes
            .prop_map(|k| 1 << k)
            .prop_flat_map(move |len| collection::vec(elem.clone(), len..=len))
            .prop_map(move |v| NTT::new(v, number_of_polynomials).unwrap())
    }

    /// Newtype wrapper to prevent proptest from writing the contents of an NTT
    /// to stdout. This is useful for when a test fails with a large NTTs.
    ///
    /// If the contents does have to be viewed replace [`hidden_ntt`] with
    /// [`ntt`] as the test strategy
    #[derive(Clone, PartialEq)]
    struct HiddenNTT<T>(NTT<T, Vec<T>>);

    impl<T> fmt::Debug for HiddenNTT<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "HiddenNTT(len={})", self.0.order().0)
        }
    }

    fn hidden_ntt<T: fmt::Debug>(
        sizes: impl Strategy<Value = usize>,
        number_of_polynomials: usize,
        elem: impl Strategy<Value = T> + Clone,
    ) -> impl Strategy<Value = HiddenNTT<T>> {
        ntt(sizes, number_of_polynomials, elem).prop_map(HiddenNTT)
    }

    proptest! {
        #[test]
        fn round_trip_ntt(original in hidden_ntt(0_usize..15, 1, fr()))
        {
            let mut s = original.clone();

            // Forward NTT
            ntt_nr(&mut s.0);

            // Inverse NTT
            intt_rn(&mut s.0);

            prop_assert_eq!(original,s);
        }
    }

    // TODO Replace by parallel alternative to speed up tests
    fn transpose<T: Copy>(matrix: &[T], rows: usize, columns: usize) -> Vec<T> {
        assert_eq!(matrix.len(), rows * columns);
        let mut v = Vec::with_capacity(matrix.len());
        for j in 0..columns {
            for i in 0..rows {
                v.push(matrix[i * columns + j]);
            }
        }
        v
    }

    proptest! {
        #[test]
        fn test_transpose((rows, columns, mat) in (0_usize..10, 0_usize..10)
            .prop_flat_map(|(rows, columns)| {
                // If either rows or columns is zero, the matrix is empty
                let len = rows * columns;
                (Just(rows), Just(columns), collection::vec(any::<u32>(), len..=len))
            })
        ) {
            let transposed = transpose(&mat, rows, columns);
            let double_transposed = transpose(&transposed, columns, rows);
            assert_eq!(mat, double_transposed);
        }
    }

    /// Note: because this generator is build monadicly it doesn't easily find
    /// the smallest case. it helps to manually reduce max_k to get a
    /// smaller test case
    fn interleaving_strategy(
        k: impl Strategy<Value = usize>,
    ) -> impl Strategy<
        Value = (
            // rows
            Pow2<NonZero<usize>>,
            // columns
            Pow2<NonZero<usize>>,
            HiddenNTT<Fr>,
        ),
    > {
        fn constr(exp: usize) -> Pow2<NonZero<usize>> {
            NonZeroUsize::new(2_usize.pow(exp as u32))
                .and_then(Pow2::new)
                .unwrap()
        }

        k.prop_flat_map(|len| {
            (0..=len).prop_flat_map(move |column| {
                (
                    Just(constr(len - column)),
                    Just(constr(column)),
                    hidden_ntt(len..=len, constr(column).get(), fr()),
                )
            })
        })
    }

    proptest! {
        #[test]
        fn test_interleaved((rows, columns, ntt) in interleaving_strategy(0_usize..20)) {
            let mut ntt = ntt.0;
            let mut transposed = transpose(&ntt, rows.get(), columns.get());

            for chunk in transposed.chunks_exact_mut(rows.get()){
                let mut fold = NTT::new(chunk,1).unwrap();
                ntt_nr(&mut fold);
            }

        let double_transposed = transpose(&transposed, columns.get(), rows.get());

        ntt_nr(&mut ntt);
        prop_assert!(double_transposed == ntt.into_inner());

        }
    }

    #[test]
    // The roundtrip test doesn't test size 0.
    fn ntt_empty() {
        let mut v = NTT::new(vec![], 1).unwrap();
        ntt_nr(&mut v);
    }

    // Compare direct generation of the roots vs. extending from a base set of roots
    #[test]
    fn roots_direct_vs_extended() {
        let order = Pow2::new(2_usize.pow(20)).unwrap();
        let roots = init_roots_reverse_ordered(order, None);
        let engine = NTTEngine::with_order(order);
        assert_eq!(engine.0.len(), roots.len());
        assert_eq!(engine.0, roots)
    }

    proptest! {
        #[test]
        fn round_trip_reverse_order(original in ntt(0_usize..10, 1, any::<u32>())){
            let mut v = original.clone();
            reverse_order(&mut v);
            reverse_order(&mut v);
            prop_assert_eq!(original, v)
        }
    }

    proptest! {
        #[test]
        fn reverse_order_noop(original in ntt(0_usize..=1, 1, any::<u32>())) {
            let mut v = original.clone();
            reverse_order(&mut v);
            assert_eq!(original, v)
        }

    }
}
