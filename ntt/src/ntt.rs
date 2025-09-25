use {
    crate::{Pow2OrZero, NTT},
    ark_bn254::Fr,
    ark_ff::{FftField, Field},
    rayon::{
        iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
    std::mem::size_of,
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
        let init =
            init_roots_reverse_ordered(Pow2OrZero::next_power_of_two(workload_size::<Fr>()), None);
        NTTEngine(init)
    }

    /// Initialize an NTT Engine of the given order
    ///
    /// Note: with_order will initialise at least half a L1 cache size worth of
    /// twiddle factors.
    pub fn with_order(order: Pow2OrZero) -> Self {
        let init = init_roots_reverse_ordered(
            Pow2OrZero::next_power_of_two(workload_size::<Fr>()),
            Some(order.0 / 2),
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
    fn extend_roots_table(&mut self, order: Pow2OrZero) {
        let order = order.0;
        let table = &mut self.0;

        let old_len = table.len();
        let new_len = order / 2;

        if new_len > old_len {
            let col_len = new_len / old_len;
            let unity = Fr::get_root_of_unity(order as u64).unwrap();
            // Remark: change this to reserve exact if tighter control on memory is needed
            table.reserve(new_len - old_len);
            let (init, uninit) = table.split_at_spare_mut();

            // When viewing the roots as a matrix every row is a multiple of the first row
            // row[j] = row[0] * unity^(reverse order j)

            uninit
                .par_chunks_mut(old_len)
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
                table.set_len(new_len);
            }
        }
    }

    // TODO(xrvdg) interleaving does support non-power of factors, but it needs to
    // be that the individual NTTs are power of two.
    // TODO for interleaving pow2orzero doesn't make sense. It needs to be nonzero
    pub fn interleaved_ntt_nr(&mut self, values: &mut NTT<Fr>, interleaving: Pow2OrZero) {
        self.extend_roots_table(Pow2OrZero(values.len().0 / interleaving.0));
        interleaved_ntt_nr(&self.0, values, interleaving.0);
    }

    pub fn ntt_nr(&mut self, values: &mut NTT<Fr>) {
        self.interleaved_ntt_nr(values, Pow2OrZero::next_power_of_two(1));
    }

    pub fn intt_rn(&mut self, values: &mut NTT<Fr>) {
        self.extend_roots_table(values.len());
        intt_rn(&self.0, values);
    }
}

impl Default for NTTEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ntt_nr(reverse_ordered_roots: &[Fr], values: &mut NTT<Fr>) {
    interleaved_ntt_nr(reverse_ordered_roots, values, 1);
}

/// In-place Number Theoretic Transform (NTT) from normal order to reverse bit
/// order.
///
/// # Arguments
/// * `reversed_ordered_roots` - Precomputed roots of unity in reverse bit
///   order.
/// * `values` - coefficients to be transformed in place with evaluation or vice
///   versa.
/// TODO: does interleaving work with non-power of two? -> it does but it
/// requires the folded vectors to be of the right length
pub fn interleaved_ntt_nr(
    reversed_ordered_roots: &[Fr],
    values: &mut NTT<Fr>,
    interleaving: usize,
) {
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
            dit_nr_cache(reversed_ordered_roots, k, group, interleaving);
        });
}

fn dit_nr_cache(
    reverse_ordered_roots: &[Fr],
    segment: usize,
    input: &mut [Fr],
    interleaving: usize,
) {
    let n = input.len();
    debug_assert!(n.is_power_of_two());

    let mut pairs_in_group = n / 2;
    let mut num_of_groups = 1;

    let single_n = n / interleaving;

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
fn init_roots_reverse_ordered(order: Pow2OrZero, capacity: Option<usize>) -> Vec<Fr> {
    let order = order.0;
    let n = order / 2;

    match n {
        0 => vec![],
        // 1 is a separate case due to `1.trailing_zeros = 0` which reverse_bit requires >0
        1 => vec![Fr::ONE],
        n => {
            // Use provided capacity or default to n, ensuring it's at least n
            let actual_capacity = capacity.map_or(n, |cap| cap.max(n));

            let root = Fr::get_root_of_unity(order as u64).unwrap();

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
    #[cfg(test)]
    use proptest::prelude::*;
    use {
        super::{init_roots_reverse_ordered, reverse_order},
        crate::{ntt::NTTEngine, Pow2OrZero, NTT},
        ark_bn254::Fr,
        ark_ff::{AdditiveGroup, BigInt},
        proptest::collection,
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

    // Newtype wrapper to prevent proptest from writing big NTT to stdout
    // If the contents does have to be viewed replace with regular NTT
    // TODO(xrvdg) make this take a parameter and rename
    struct HiddenNTT<T>(NTT<T>);

    impl<T> fmt::Debug for HiddenNTT<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "HiddenNTT(len={})", self.0.len().0)
        }
    }

    fn hidden_ntt<T: fmt::Debug>(
        sizes: impl Strategy<Value = usize>,
        elem: impl Strategy<Value = T> + Clone,
    ) -> impl Strategy<Value = HiddenNTT<T>> {
        ntt(sizes, elem).prop_map(HiddenNTT)
    }

    proptest! {
        #[test]
        fn round_trip_ntt(original in ntt(0_usize..15, fr()))
        {
            let mut s = original.clone();

            let mut engine = NTTEngine::new();
            // Forward NTT
            engine.ntt_nr(&mut s);

            // Inverse NTT
            engine.intt_rn(&mut s);

            prop_assert_eq!(original,s);
        }
    }

    fn transpose<T: Copy, U: AsRef<[T]>>(matrix: U, rows: usize, columns: usize) -> Vec<T> {
        let matrix = matrix.as_ref();
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

    proptest! {
        #[test]
        fn test_interleaving((rows, columns, ntt) in (0_usize..=1, 0_usize..=10).prop_flat_map(|(rows, columns)| {
            let len = rows + columns;
            (Just(2_usize.pow(rows as u32)), Just(2_usize.pow(columns as u32)), hidden_ntt(len..=len, fr()))
        })){
            let mut ntt = ntt.0;
            let s = ntt.clone();
            let transposed = transpose(s, rows, columns);
            let mut engine = NTTEngine::new();
            // This requires an into clone and then will make it harder to transpose back
            let mut ntts = Vec::with_capacity(columns);
            // Vec should be able to go underlying array and give that instead
            // solve for to_owned
            for chunk in transposed.chunks_exact(rows){
                let mut fold = NTT(chunk.to_owned());
                engine.ntt_nr(&mut fold);
                ntts.push(fold);
            }
            let mut collect = vec![Fr::ZERO; transposed.len()];

        // All the memory would still be near eachother but lost parts
        for (ntt, chunk) in ntts.iter().zip(collect.chunks_mut(rows)) {
            let slice = ntt.as_ref();
            chunk.copy_from_slice(slice);
        }

        let double_transposed = NTT::new(transpose(collect, columns, rows)).unwrap();

        engine.interleaved_ntt_nr(&mut ntt, Pow2OrZero(columns));
        prop_assert!(double_transposed == ntt, "rows: {}, columns: {}", rows, columns);



        }
    }

    #[test]
    // The roundtrip test doesn't test size 0.
    fn ntt_empty() {
        let mut v = NTT::new(vec![]).unwrap();
        let mut engine = NTTEngine::new();
        engine.ntt_nr(&mut v);
    }

    // Compare direct generation of the roots vs. extending from a base set of roots
    #[test]
    fn roots_direct_vs_extended() {
        let order = Pow2OrZero::next_power_of_two(2_usize.pow(20));
        let roots = init_roots_reverse_ordered(order, None);
        let engine = NTTEngine::with_order(order);
        assert_eq!(engine.0.len(), roots.len());
        assert_eq!(engine.0, roots)
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
