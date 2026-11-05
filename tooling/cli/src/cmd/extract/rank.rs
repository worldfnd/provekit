use {
    super::{
        matrix::{DenseMatrix, DirectSparseMatrix},
        Core, MbpLayer,
    },
    ark_ff::Field,
    tracing::{info, instrument},
};

#[cfg(test)]
type Row<F> = Vec<(usize, F)>;

impl<F: Field> MbpLayer<F> {
    /// Exact rank factorization of a vertical or horizontal stack. Sparse
    /// inputs are eliminated as sparse rows, with no dense input allocation.
    #[instrument(skip_all)]
    pub(super) fn rank_factor(&self, vertically: bool) -> (Core<F>, Core<F>) {
        if self.matrices.iter().all(Core::is_sparse) {
            self.sparse_rank_factor(vertically)
        } else {
            self.dense_rank_factor(vertically)
        }
    }

    fn dense_rank_factor(&self, vertically: bool) -> (Core<F>, Core<F>) {
        let (left, right) = DenseMatrix::stack(self, vertically).rank_factor();
        (Core::from_dense(left), Core::from_dense(right))
    }

    fn sparse_rank_factor(&self, vertically: bool) -> (Core<F>, Core<F>) {
        let height = self.matrices[0].num_rows();
        let width = self.matrices[0].num_cols();
        assert_eq!(
            (self.matrices[1].num_rows(), self.matrices[1].num_cols()),
            (height, width)
        );
        let num_rows = if vertically { 2 * height } else { height };
        let num_cols = if vertically { width } else { 2 * width };
        let dense_bytes = num_rows
            .saturating_mul(num_cols)
            .saturating_mul(size_of::<F>());
        let mut degrees = vec![0usize; num_cols];
        let mut order: Vec<_> = (0..num_rows)
            .map(|row| {
                let mut nnz = 0;
                self.visit_stack_row(row, vertically, |column, _| {
                    degrees[column] += 1;
                    nnz += 1;
                });
                (nnz, row)
            })
            .collect();
        // Sparse rows first; preserve original row indices in the left factor.
        order.sort_unstable();
        let mut owners: Vec<Option<usize>> = vec![None; num_cols];
        let mut pivot_columns: Vec<usize> = Vec::new();
        let mut basis = DirectSparseMatrix::<F>::new(num_cols);
        let mut left = DirectSparseMatrix::<F>::new(0);
        let mut workspace = Accumulator::<F>::new(num_cols, num_rows.min(num_cols));
        let mut eliminations = 0usize;
        let mut updates = 0usize;
        for &(_, original_row) in &order {
            self.visit_stack_row(original_row, vertically, |column, value| {
                workspace.set(column, value, &owners)
            });
            let mut coefficients = Vec::new();
            // Basis row j is zero at all earlier pivot columns. Processing
            // active pivots in creation order therefore never revisits a pivot.
            while let Some(pivot) = workspace.pivots.first() {
                let column = pivot_columns[pivot];
                let coefficient = workspace.values[column];
                workspace.set(column, F::ZERO, &owners);
                let positive = coefficient == F::ONE;
                let negative = coefficient == -F::ONE;
                for (column, value) in basis.iter_row(pivot) {
                    if column == pivot_columns[pivot] {
                        continue;
                    }
                    let scaled = if positive {
                        value
                    } else if negative {
                        -value
                    } else {
                        coefficient * value
                    };
                    workspace.set(column, workspace.values[column] - scaled, &owners);
                    updates += 1;
                }
                coefficients.push((pivot, coefficient));
                eliminations += 1;
            }
            let new_column = workspace.columns.iter().min_by_key(|&column| {
                (
                    degrees[column],
                    workspace.values[column] != F::ONE && workspace.values[column] != -F::ONE,
                    column,
                )
            });
            if let Some(column) = new_column {
                let coefficient = workspace.values[column];
                let pivot = basis.num_rows();
                owners[column] = Some(pivot);
                pivot_columns.push(column);
                coefficients.push((pivot, coefficient));
                let inverse = if coefficient == F::ONE {
                    F::ONE
                } else if coefficient == -F::ONE {
                    -F::ONE
                } else {
                    coefficient.inverse().expect("nonzero sparse pivot")
                };
                let positive = inverse == F::ONE;
                let negative = inverse == -F::ONE;
                basis.push_row(workspace.columns.iter().map(|column| {
                    let value = workspace.values[column];
                    (
                        column,
                        if positive {
                            value
                        } else if negative {
                            -value
                        } else {
                            value * inverse
                        },
                    )
                }));
                workspace.clear();
            }
            coefficients.sort_unstable_by_key(|&(pivot, _)| pivot);
            left.push_row(coefficients.into_iter());
            let sparse_bytes = basis
                .values
                .capacity()
                .saturating_add(left.values.capacity())
                .saturating_mul(size_of::<F>())
                .saturating_add(
                    basis
                        .columns
                        .capacity()
                        .saturating_add(left.columns.capacity())
                        .saturating_mul(size_of::<u32>()),
                );
            if sparse_bytes > dense_bytes {
                info!(
                    "Sparse rank factorization switching to dense after {} rows.",
                    left.num_rows()
                );
                drop(left);
                drop(basis);
                drop(workspace);
                drop(owners);
                return self.dense_rank_factor(vertically);
            }
        }
        let rank = basis.num_rows();
        left.num_cols = rank;
        if order
            .iter()
            .enumerate()
            .any(|(position, &(_, row))| position != row)
        {
            let mut inverse = vec![0; num_rows];
            for (position, &(_, row)) in order.iter().enumerate() {
                inverse[row] = position;
            }
            let mut restored = DirectSparseMatrix::new(rank);
            restored.values.reserve(left.values.len());
            restored.columns.reserve(left.columns.len());
            for position in inverse {
                restored.push_row(left.iter_row(position));
            }
            left = restored;
        }
        info!(
            "Sparse rank factorization {}x{}: rank {}, factor nnz ({}, {}), {} eliminations, {} \
             coefficient updates.",
            num_rows,
            num_cols,
            rank,
            left.values.len(),
            basis.values.len(),
            eliminations,
            updates
        );
        (Core::from_direct(left), Core::from_direct(basis))
    }

    fn visit_stack_row(&self, row: usize, vertically: bool, mut visit: impl FnMut(usize, F)) {
        let height = self.matrices[0].num_rows();
        let width = self.matrices[0].num_cols();
        if vertically {
            let bit = usize::from(row >= height);
            for (column, value) in self.matrices[bit].iter_row(row - bit * height) {
                visit(column, value);
            }
        } else {
            for (bit, core) in self.matrices.iter().enumerate() {
                for (column, value) in core.iter_row(row) {
                    visit(column + bit * width, value);
                }
            }
        }
    }

    #[cfg(test)]
    fn sparse_stack_row(&self, row: usize, vertically: bool) -> Row<F> {
        let mut entries = Vec::new();
        self.visit_stack_row(row, vertically, |column, value| {
            entries.push((column, value))
        });
        entries
    }
    #[cfg(test)]
    fn reference_rank_factor(&self, vertically: bool) -> (Core<F>, Core<F>) {
        let height = self.matrices[0].num_rows();
        let width = self.matrices[0].num_cols();
        assert_eq!(
            (self.matrices[1].num_rows(), self.matrices[1].num_cols()),
            (height, width)
        );
        let num_rows = if vertically { 2 * height } else { height };
        let num_cols = if vertically { width } else { 2 * width };
        let dense_bytes = num_rows
            .saturating_mul(num_cols)
            .saturating_mul(size_of::<F>());
        let mut pivots = vec![None; num_cols];
        let mut basis: Vec<Row<F>> = Vec::new();
        let mut left = Vec::with_capacity(num_rows);
        let mut scratch = Vec::new();
        let mut basis_nnz = 0usize;
        let mut left_nnz = 0usize;

        for row_index in 0..num_rows {
            let mut row = self.sparse_stack_row(row_index, vertically);
            let mut coefficients = Vec::new();
            while let Some(&(column, coefficient)) = row.first() {
                if let Some(pivot) = pivots[column] {
                    // Normalized basis rows have leading coefficient one.
                    subtract_scaled(&mut row, &basis[pivot], coefficient, &mut scratch);
                    coefficients.push((pivot, coefficient));
                } else {
                    let pivot = basis.len();
                    pivots[column] = Some(pivot);
                    if coefficient != F::ONE {
                        let inverse = coefficient.inverse().expect("nonzero sparse pivot");
                        for (_, value) in &mut row {
                            *value *= inverse;
                        }
                    }
                    basis_nnz += row.len();
                    basis.push(row);
                    coefficients.push((pivot, coefficient));
                    break;
                }
            }
            // Pivot columns increase during reduction, but basis IDs follow
            // creation order. Sorting yields canonical sparse output rows.
            coefficients.sort_unstable_by_key(|&(pivot, _)| pivot);
            left_nnz += coefficients.len();
            left.push(coefficients);

            // Fill-in can erase the memory advantage of sparse elimination.
            // Restart the existing dense algorithm only once sparse factors
            // exceed the payload of the full dense input. Drop work first.
            let sparse_bytes = basis_nnz
                .saturating_add(left_nnz)
                .saturating_mul(size_of::<(usize, F)>());
            if sparse_bytes > dense_bytes {
                info!(
                    "Sparse rank factorization switching to dense after {} rows ({} factor nnz).",
                    row_index + 1,
                    basis_nnz + left_nnz
                );
                drop(left);
                drop(basis);
                drop(pivots);
                drop(scratch);
                return self.dense_rank_factor(vertically);
            }
        }

        // Every input row was expressed in the independent normalized basis.
        // Thus A = L R, and each newly introduced basis row supplies a nonzero
        // triangular pivot in L. Full RREF/back substitution is unnecessary.
        let rank = basis.len();
        info!(
            "Sparse rank factorization {}x{}: rank {}, factor nnz ({}, {}).",
            num_rows, num_cols, rank, left_nnz, basis_nnz
        );
        (
            Core::from_rows(rank, left),
            Core::from_rows(num_cols, basis),
        )
    }
}

/// Two-level bitset: the summary finds active words without scanning the
/// whole column range at each pivot. It stores only O(width) bits.
struct ActiveSet {
    words:   Vec<u64>,
    summary: Vec<u64>,
}

impl ActiveSet {
    fn new(len: usize) -> Self {
        let words = len.div_ceil(64);
        Self {
            words:   vec![0; words],
            summary: vec![0; words.div_ceil(64)],
        }
    }
    fn set(&mut self, index: usize, active: bool) {
        let word = index / 64;
        let bit = 1u64 << (index % 64);
        if active {
            self.words[word] |= bit;
        } else {
            self.words[word] &= !bit;
        }
        let summary_bit = 1u64 << (word % 64);
        if self.words[word] == 0 {
            self.summary[word / 64] &= !summary_bit;
        } else {
            self.summary[word / 64] |= summary_bit;
        }
    }
    fn first(&self) -> Option<usize> {
        self.iter().next()
    }
    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.summary
            .iter()
            .copied()
            .enumerate()
            .flat_map(move |(group, mut active)| {
                std::iter::from_fn(move || {
                    if active == 0 {
                        return None;
                    }
                    let word = group * 64 + active.trailing_zeros() as usize;
                    active &= active - 1;
                    Some(word)
                })
                .flat_map(move |word| {
                    let mut bits = self.words[word];
                    std::iter::from_fn(move || {
                        if bits == 0 {
                            return None;
                        }
                        let index = word * 64 + bits.trailing_zeros() as usize;
                        bits &= bits - 1;
                        Some(index)
                    })
                })
            })
    }
}

/// One reusable field accumulator. Elimination touches only the pivot support;
/// it never copies the unaffected remainder of the current sparse row.
struct Accumulator<F> {
    values:  Vec<F>,
    columns: ActiveSet,
    pivots:  ActiveSet,
}
impl<F: Field> Accumulator<F> {
    fn new(columns: usize, pivots: usize) -> Self {
        Self {
            values:  vec![F::ZERO; columns],
            columns: ActiveSet::new(columns),
            pivots:  ActiveSet::new(pivots),
        }
    }
    fn set(&mut self, column: usize, value: F, owners: &[Option<usize>]) {
        let was_active = !self.values[column].is_zero();
        self.values[column] = value;
        let active = !value.is_zero();
        if active != was_active {
            self.columns.set(column, active);
            if let Some(pivot) = owners[column] {
                self.pivots.set(pivot, active);
            }
        }
    }
    fn clear(&mut self) {
        for column in self.columns.iter() {
            self.values[column] = F::ZERO;
        }
        self.columns.words.fill(0);
        self.columns.summary.fill(0);
        debug_assert!(self.pivots.first().is_none());
    }
}

#[cfg(test)]
/// Merge sorted supports, dropping exact cancellations and reusing scratch.
fn subtract_scaled<F: Field>(
    row: &mut Row<F>,
    basis: &Row<F>,
    coefficient: F,
    scratch: &mut Row<F>,
) {
    scratch.clear();
    let mut i = 0;
    let mut j = 0;
    let scale = |value: F| {
        if coefficient == F::ONE {
            value
        } else if coefficient == -F::ONE {
            -value
        } else {
            coefficient * value
        }
    };
    while i < row.len() || j < basis.len() {
        if j == basis.len() || (i < row.len() && row[i].0 < basis[j].0) {
            scratch.push(row[i]);
            i += 1;
        } else if i == row.len() || basis[j].0 < row[i].0 {
            scratch.push((basis[j].0, -scale(basis[j].1)));
            j += 1;
        } else {
            let value = row[i].1 - scale(basis[j].1);
            if !value.is_zero() {
                scratch.push((row[i].0, value));
            }
            i += 1;
            j += 1;
        }
    }
    std::mem::swap(row, scratch);
}

#[cfg(test)]
mod tests {
    use {super::*, provekit_backend_bn254::FieldElement as F};

    fn dense(core: &Core<F>) -> DenseMatrix<F> {
        let mut matrix = DenseMatrix::zeros(core.num_rows(), core.num_cols());
        for ((row, column), value) in core.iter() {
            matrix[(row, column)] = value;
        }
        matrix
    }

    fn assert_factorization(layer: &MbpLayer<F>, vertically: bool) {
        let original = DenseMatrix::stack(layer, vertically);
        let (_, reference) = original.clone().rank_factor();
        let (left, right) = layer.rank_factor(vertically);
        assert_eq!(
            (left.num_rows(), left.num_cols()),
            (original.num_rows, reference.num_rows)
        );
        assert_eq!(
            (right.num_rows(), right.num_cols()),
            (reference.num_rows, original.num_cols)
        );
        assert_eq!(dense(&left).multiply(&dense(&right)), original);
    }

    #[test]
    fn active_sets_handle_word_boundaries_and_cancellation() {
        let indices = [0, 1, 63, 64, 65, 4095, 4096, 4999];
        let mut set = ActiveSet::new(5000);
        for index in indices {
            set.set(index, true);
        }
        assert_eq!(set.iter().collect::<Vec<_>>(), indices);
        for index in indices {
            assert_eq!(set.first(), Some(index));
            set.set(index, false);
        }
        assert!(set.first().is_none());
        let mut owners = vec![None; 5000];
        owners[63] = Some(0);
        owners[4096] = Some(1);
        let mut accumulator = Accumulator::<F>::new(5000, 2);
        accumulator.set(4096, F::from(7u64), &owners);
        accumulator.set(63, F::from(3u64), &owners);
        assert_eq!(accumulator.pivots.first(), Some(0));
        accumulator.set(63, F::from(0u64), &owners);
        assert_eq!(accumulator.pivots.first(), Some(1));
        accumulator.set(4096, F::from(0u64), &owners);
        accumulator.set(4999, F::from(9u64), &owners);
        accumulator.clear();
        assert!(accumulator.columns.first().is_none());
        assert!(accumulator
            .values
            .iter()
            .all(|value| *value == F::from(0u64)));
    }

    #[test]
    fn row_and_column_ordering_reduce_hub_fill_in() {
        let matrices = std::array::from_fn(|bit| {
            let rows = (0..32)
                .map(|row| {
                    let index = row + bit * 32;
                    let mut values = vec![(0, F::from(1u64)), (index + 1, F::from(2u64))];
                    if index % 3 == 0 {
                        values.push((100, F::from((index + 3) as u64)));
                    }
                    values
                })
                .collect();
            Core::from_rows(128, rows)
        });
        let layer = MbpLayer { matrices };
        let (old_left, old_right) = layer.reference_rank_factor(true);
        let (left, right) = layer.rank_factor(true);
        assert_eq!(right.num_rows(), old_right.num_rows());
        assert!(left.nnz() + right.nnz() < old_left.nnz() + old_right.nnz());
        assert_eq!(
            dense(&left).multiply(&dense(&right)),
            DenseMatrix::stack(&layer, true)
        );
    }

    #[test]
    #[ignore = "manual comparison with the previous merge-based sparse algorithm"]
    fn benchmark_sparse_rank_fill_in() {
        use std::time::Instant;
        for case in ["hub", "hub-tail", "coupled"] {
            let matrices = std::array::from_fn(|bit| {
                let rows = (0..256)
                    .map(|row| {
                        let index = row + bit * 256;
                        if case == "coupled" {
                            let mut state = index as u64 + 1;
                            let mut entries = std::collections::BTreeMap::new();
                            for _ in 0..32 {
                                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                                entries.insert(
                                    (state >> 32) as usize % 256,
                                    F::from((state % 31 + 1) as u64),
                                );
                            }
                            return entries.into_iter().collect();
                        }
                        let mut entries = vec![
                            (0, F::from((index % 13 + 1) as u64)),
                            (index + 1, F::from(1u64)),
                        ];
                        if case == "hub-tail" {
                            for offset in 0..16 {
                                entries.push((
                                    2048 + ((index * 17 + offset * 31) % 512),
                                    F::from(((index + offset) % 31 + 1) as u64),
                                ));
                            }
                        }
                        entries.sort_unstable_by_key(|&(column, _)| column);
                        entries
                    })
                    .collect();
                Core::from_rows(4096, rows)
            });
            let layer = MbpLayer { matrices };
            for previous in [true, false] {
                #[cfg(feature = "profiling-allocator")]
                let (base, count) = (crate::ALLOCATOR.reset_max(), crate::ALLOCATOR.count());
                let start = Instant::now();
                let (left, right) = if previous {
                    layer.reference_rank_factor(true)
                } else {
                    layer.rank_factor(true)
                };
                let elapsed = start.elapsed();
                #[cfg(feature = "profiling-allocator")]
                let (peak, allocations) = (
                    crate::ALLOCATOR.max().saturating_sub(base),
                    crate::ALLOCATOR.count() - count,
                );
                eprintln!(
                    "{case}, {}: {elapsed:?}, rank {}, nnz ({}, {})",
                    if previous { "previous" } else { "new" },
                    right.num_rows(),
                    left.nnz(),
                    right.nnz()
                );
                #[cfg(feature = "profiling-allocator")]
                eprintln!("peak additional heap {peak} bytes, {allocations} allocations");
                let product = left.multiply(&right);
                for row in 0..512 {
                    assert_eq!(
                        product.iter_row(row).collect::<Vec<_>>(),
                        layer.sparse_stack_row(row, true)
                    );
                }
            }
        }
    }

    #[test]
    fn sparse_factorizations_match_dense_rank_for_all_small_ternary_inputs() {
        // Wide padding keeps elimination sparse. Scrambled nonzero columns
        // exercise basis IDs introduced in a different order from pivot columns.
        for mut code in 0..729 {
            let mut matrix = DenseMatrix::zeros(2, 11);
            for row in 0..2 {
                for column in [9, 2, 5] {
                    matrix[(row, column)] = F::from((code % 3) as i64 - 1);
                    code /= 3;
                }
            }
            let layer = MbpLayer {
                matrices: std::array::from_fn(|_| Core::force_sparse(matrix.clone())),
            };
            for vertically in [false, true] {
                assert_factorization(&layer, vertically);
            }
        }
    }

    #[test]
    fn nonunit_pivots_mixed_storage_fill_in_and_empty_shapes() {
        for (height, width) in [(0, 0), (0, 5), (5, 0), (3, 17), (32, 32)] {
            let mut seed = 29u64;
            let matrices = std::array::from_fn(|_| {
                let mut matrix = DenseMatrix::zeros(height, width);
                for value in &mut matrix.values {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *value = F::from(((seed >> 32) % 17) as i64 - 8);
                }
                matrix
            });
            let sparse = MbpLayer {
                matrices: matrices
                    .each_ref()
                    .map(|matrix| Core::force_sparse(matrix.clone())),
            };
            let [first, second] = matrices;
            let mixed = MbpLayer {
                matrices: [Core::force_sparse(first), Core::Dense(second)],
            };
            for vertically in [false, true] {
                assert_factorization(&sparse, vertically);
                assert_factorization(&mixed, vertically);
            }
        }
    }

    #[test]
    #[ignore = "manual sparse versus dense rank-factorization comparison"]
    fn benchmark_sparse_rank_factorization() {
        use std::time::Instant;
        let matrices = std::array::from_fn(|bit| {
            let rows = (0..64)
                .map(|row| vec![(0, F::from(1u64)), (1 + row + bit * 64, F::from(2u64))])
                .collect();
            Core::from_rows(4096, rows)
        });
        let layer = MbpLayer { matrices };
        assert!(layer.matrices.iter().all(Core::is_sparse));
        let start = Instant::now();
        let (left, right) = layer.rank_factor(true);
        let sparse_time = start.elapsed();
        let start = Instant::now();
        let original = DenseMatrix::stack(&layer, true);
        let (reference_left, reference_right) = original.clone().rank_factor();
        let dense_time = start.elapsed();
        assert_eq!(right.num_rows(), reference_right.num_rows);
        assert_eq!(dense(&left.multiply(&right)), original);
        assert_eq!(reference_left.multiply(&reference_right), original);
        eprintln!(
            "sparse rank {sparse_time:?}, dense including stack {dense_time:?}; rank {}, factor \
             nnz ({}, {}); avoided input {} bytes",
            right.num_rows(),
            left.nnz(),
            right.nnz(),
            128 * 4096 * size_of::<F>()
        );
    }
}
