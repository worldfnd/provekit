//! Exact, greedy sparsification with ternary internal cores. The first core
//! carries arbitrary A/B/C coefficients and is exempt from the alphabet check,
//! but its nonzeros are included in every cost comparison.
use {
    super::{Core, MatrixBranchingProgram, MbpLayer},
    ark_ff::Field,
    tracing::{info, instrument},
};

mod patterns;

type SparseVector<F> = Vec<(usize, F)>;

fn ternary<F: Field>(value: F) -> bool {
    value.is_zero() || value == F::ONE || value == -F::ONE
}

fn layer_nnz<F: Field>(layer: &MbpLayer<F>) -> usize {
    layer.matrices.iter().map(Core::nnz).sum()
}

fn layer_is_ternary<F: Field>(layer: &MbpLayer<F>) -> bool {
    layer
        .matrices
        .iter()
        .all(|core| core.value_counts()[2] == 0)
}

impl<F: Field> MatrixBranchingProgram<F> {
    /// Minimize (total nnz, sum of internal widths) by guarded rank proposals,
    /// paired elementary basis changes, and shared-pattern extraction. Every
    /// accepted rewrite is exact. Sharing may increase width while reducing
    /// nnz. This is a local heuristic, not a minimum-rank or minimum-nnz
    /// guarantee.
    ///
    /// Each direction scans every cut once. Pair trials use sparse vectors;
    /// a dense worst-case scan takes O(k W^3) field operations. Further sweeps
    /// are needed until the strictly decreasing integer cost stabilizes.
    /// Rank proposals retain the existing rank factorizer's workspace costs.
    #[instrument(skip_all)]
    pub(super) fn minimize_ternary(&mut self) {
        assert!(
            self.layers.iter().skip(1).all(layer_is_ternary),
            "ternary minimization requires ternary internal input cores"
        );
        let cuts = self.layers.len().saturating_sub(1);
        if cuts == 0 {
            return;
        }
        for sweep in 1usize.. {
            let mut changed = false;
            for forward in [true, false] {
                for index in 0..cuts {
                    let cut = if forward { index } else { cuts - 1 - index };
                    let before = self.ternary_cut_cost(cut);
                    changed |= self.try_ternary_rank(cut, forward);
                    changed |= self.sparsify_ternary_cut(cut);
                    let after = self.ternary_cut_cost(cut);
                    info!(
                        "Ternary sweep {sweep}, cut {cut}, forward={forward}: nnz {} -> {}, width \
                         {} -> {}.",
                        before.0, after.0, before.1, after.1
                    );
                }
                let direction = if forward { "forward" } else { "backward" };
                self.log_stats(&format!("Ternary sweep {sweep} {direction}"));
            }
            if !changed {
                break;
            }
        }
    }

    fn ternary_cut_cost(&self, cut: usize) -> (usize, usize) {
        (
            layer_nnz(&self.layers[cut]) + layer_nnz(&self.layers[cut + 1]),
            self.layers[cut].matrices[0].num_cols(),
        )
    }

    fn try_ternary_rank(&mut self, cut: usize, forward: bool) -> bool {
        let (left, right) = if forward {
            let rows = self.layers[cut].matrices[0].num_rows();
            let (l, r) = self.layers[cut].rank_factor(true);
            let rank = r.num_rows();
            let left = MbpLayer {
                matrices: std::array::from_fn(|bit| l.block(bit * rows, rows, 0, rank)),
            };
            if cut != 0 && !layer_is_ternary(&left) {
                return false;
            }
            let right = MbpLayer {
                matrices: self.layers[cut + 1]
                    .matrices
                    .each_ref()
                    .map(|core| r.multiply(core)),
            };
            (left, right)
        } else {
            let cols = self.layers[cut + 1].matrices[0].num_cols();
            let (l, r) = self.layers[cut + 1].rank_factor(false);
            let rank = l.num_cols();
            let right = MbpLayer {
                matrices: std::array::from_fn(|bit| r.block(0, rank, bit * cols, cols)),
            };
            if !layer_is_ternary(&right) {
                return false;
            }
            let left = MbpLayer {
                matrices: self.layers[cut]
                    .matrices
                    .each_ref()
                    .map(|core| core.multiply(&l)),
            };
            (left, right)
        };
        let cost = (
            layer_nnz(&left) + layer_nnz(&right),
            left.matrices[0].num_cols(),
        );
        // Check emitted cores, including the absorbed transfer matrix.
        if cost >= self.ternary_cut_cost(cut)
            || (cut != 0 && !layer_is_ternary(&left))
            || !layer_is_ternary(&right)
        {
            return false;
        }
        self.layers[cut] = left;
        self.layers[cut + 1] = right;
        true
    }

    fn sparsify_ternary_cut(&mut self, cut: usize) -> bool {
        let mut pair = Cut::new(&self.layers[cut], &self.layers[cut + 1]);
        let mut changed = pair.remove_dead();
        let width = pair.incoming.len();
        // Keep deleted slots empty during the scan, so indices remain stable.
        // A later sweep revisits moves exposed after their position was passed.
        for p in 0..width {
            for q in 0..width {
                if p == q {
                    continue;
                }
                for subtract in [false, true] {
                    changed |= pair.try_shear(p, q, subtract, cut != 0);
                }
            }
        }
        // New shared states are eligible for shears on the next sweep.
        changed |= pair.extract_shared_patterns(cut != 0) != 0;
        if changed {
            let (left, right) = pair.into_layers();
            self.layers[cut] = left;
            self.layers[cut + 1] = right;
        }
        changed
    }
}

/// Columns of A = [M_i0; M_i1] and rows of B = [M_(i+1)0 M_(i+1)1].
/// Both orientations are sparse; no dense pair of cores is materialized.
struct Cut<F: Field> {
    incoming:   Vec<SparseVector<F>>,
    outgoing:   Vec<SparseVector<F>>,
    left_rows:  usize,
    right_cols: usize,
}

impl<F: Field> Cut<F> {
    fn new(left: &MbpLayer<F>, right: &MbpLayer<F>) -> Self {
        let width = left.matrices[0].num_cols();
        let left_rows = left.matrices[0].num_rows();
        let right_cols = right.matrices[0].num_cols();
        let mut incoming = vec![Vec::new(); width];
        let mut outgoing = vec![Vec::new(); width];
        for bit in 0..2 {
            assert_eq!(left.matrices[bit].num_rows(), left_rows);
            assert_eq!(left.matrices[bit].num_cols(), width);
            assert_eq!(right.matrices[bit].num_rows(), width);
            assert_eq!(right.matrices[bit].num_cols(), right_cols);
            for ((row, col), value) in left.matrices[bit].iter() {
                incoming[col].push((bit * left_rows + row, value));
            }
            for ((row, col), value) in right.matrices[bit].iter() {
                outgoing[row].push((bit * right_cols + col, value));
            }
        }
        Self {
            incoming,
            outgoing,
            left_rows,
            right_cols,
        }
    }

    fn remove_dead(&mut self) -> bool {
        let mut changed = false;
        for (incoming, outgoing) in self.incoming.iter_mut().zip(&mut self.outgoing) {
            if incoming.is_empty() || outgoing.is_empty() {
                // Even a state with no edges consumes width.
                changed = true;
                incoming.clear();
                outgoing.clear();
            }
        }
        changed
    }

    /// A[:,q] += s*A[:,p], B[p,:] -= s*B[q,:], where s is +/-1.
    /// The two cross terms cancel, so every two-bit core product is unchanged.
    /// Score without allocating; only materialize the two sums on acceptance.
    fn try_shear(&mut self, p: usize, q: usize, subtract: bool, ternary_left: bool) -> bool {
        if self.incoming[p].is_empty() || self.incoming[q].is_empty() {
            return false;
        }
        let sides = [
            (&self.incoming[q], &self.incoming[p], subtract, ternary_left),
            (&self.outgoing[p], &self.outgoing[q], !subtract, true),
        ];
        let totals = sides.map(|(lhs, rhs, ..)| lhs.len() + rhs.len());
        let before = totals[0] + totals[1];
        // If the new incoming column is zero, delete outgoing[q]; if the new
        // outgoing row is zero, delete incoming[p]. Include those savings in
        // every bound, so profitable state deletions are never pruned.
        let retained = [self.outgoing[q].len(), self.incoming[p].len()];
        let cost = |nnz: [usize; 2]| {
            nnz[0]
                + nnz[1]
                + if nnz[0] == 0 { 0 } else { retained[0] }
                + if nnz[1] == 0 { 0 } else { retained[1] }
        };
        let mut nnz = sides.map(|(lhs, rhs, ..)| combined_nnz_lower_bound(lhs, rhs));
        if cost(nnz) >= before {
            return false;
        }

        // Check the shorter side first. BDD outgoing rows are usually much
        // shorter than incoming columns, and can reject an expensive trial.
        let first = usize::from(totals[1] < totals[0]);
        for side in [first, 1 - first] {
            if nnz[side] == totals[side] {
                continue; // Disjoint index ranges: the bound is exact.
            }
            let other = 1 - side;
            let base = nnz[other] + if nnz[other] == 0 { 0 } else { retained[other] };
            // cost(nnz) < before implies base < before. A zero sum deletes
            // its paired vector; a nonzero sum must also pay retained[side].
            let limit = (before - base - 1).saturating_sub(retained[side]);
            let (lhs, rhs, subtract, require_ternary) = sides[side];
            let Some(count) = combined_nnz(lhs, rhs, subtract, require_ternary, limit) else {
                return false;
            };
            nnz[side] = count;
        }
        debug_assert!(cost(nnz) < before);

        let incoming = if nnz[0] == 0 {
            Vec::new()
        } else {
            combine(&self.incoming[q], &self.incoming[p], subtract, ternary_left)
                .expect("scored incoming sum")
        };
        let outgoing = if nnz[1] == 0 {
            Vec::new()
        } else {
            combine(&self.outgoing[p], &self.outgoing[q], !subtract, true)
                .expect("scored outgoing sum")
        };
        self.incoming[q] = incoming;
        self.outgoing[p] = outgoing;
        if self.outgoing[p].is_empty() {
            self.incoming[p].clear();
        }
        if self.incoming[q].is_empty() {
            self.outgoing[q].clear();
        }
        true
    }

    fn into_layers(self) -> (MbpLayer<F>, MbpLayer<F>) {
        let mut left_rows = vec![Vec::new(); 2 * self.left_rows];
        let mut right_rows: [Vec<SparseVector<F>>; 2] = [Vec::new(), Vec::new()];
        let mut width = 0;
        for (incoming, outgoing) in self.incoming.into_iter().zip(self.outgoing) {
            if incoming.is_empty() || outgoing.is_empty() {
                continue;
            }
            for (row, value) in incoming {
                left_rows[row].push((width, value));
            }
            let mut rows: [SparseVector<F>; 2] = [Vec::new(), Vec::new()];
            for (column, value) in outgoing {
                // With zero right width all outgoing vectors are empty.
                rows[column / self.right_cols].push((column % self.right_cols, value));
            }
            for (dest, row) in right_rows.iter_mut().zip(rows) {
                dest.push(row);
            }
            width += 1;
        }
        let high_rows = left_rows.split_off(self.left_rows);
        (
            MbpLayer {
                matrices: [left_rows, high_rows].map(|rows| Core::from_rows(width, rows)),
            },
            MbpLayer {
                matrices: right_rows.map(|rows| Core::from_rows(self.right_cols, rows)),
            },
        )
    }
}

/// O(1) lower bound on the support size of a sum or difference. Exact when
/// either input is empty or their sorted index ranges do not overlap.
fn combined_nnz_lower_bound<F>(lhs: &[(usize, F)], rhs: &[(usize, F)]) -> usize {
    if lhs.is_empty()
        || rhs.is_empty()
        || lhs[lhs.len() - 1].0 < rhs[0].0
        || rhs[rhs.len() - 1].0 < lhs[0].0
    {
        lhs.len() + rhs.len()
    } else {
        lhs.len().abs_diff(rhs.len())
    }
}

/// Score a sparse sum without storing it. Inputs have sorted unique indices,
/// nonzero entries, and are already ternary when require_ternary is true.
/// Only intersecting entries need field arithmetic or alphabet checks.
/// Reject as soon as the finalized prefix alone exceeds the nonzero budget.
fn combined_nnz<F: Field>(
    lhs: &[(usize, F)],
    rhs: &[(usize, F)],
    subtract: bool,
    require_ternary: bool,
    limit: usize,
) -> Option<usize> {
    let (mut i, mut j, mut nnz) = (0, 0, 0);
    while i < lhs.len() && j < rhs.len() {
        match lhs[i].0.cmp(&rhs[j].0) {
            std::cmp::Ordering::Less => {
                i += 1;
                nnz += 1;
            }
            std::cmp::Ordering::Greater => {
                j += 1;
                nnz += 1;
            }
            std::cmp::Ordering::Equal => {
                let value = if subtract {
                    lhs[i].1 - rhs[j].1
                } else {
                    lhs[i].1 + rhs[j].1
                };
                if require_ternary && !ternary(value) {
                    return None;
                }
                nnz += usize::from(!value.is_zero());
                i += 1;
                j += 1;
            }
        }
        if nnz > limit {
            return None;
        }
    }
    nnz += lhs.len() - i + rhs.len() - j;
    (nnz <= limit).then_some(nnz)
}

/// Merge two sorted sparse vectors, rejecting forbidden emitted coefficients.
fn combine<F: Field>(
    lhs: &[(usize, F)],
    rhs: &[(usize, F)],
    subtract: bool,
    require_ternary: bool,
) -> Option<SparseVector<F>> {
    let mut result = Vec::with_capacity(lhs.len() + rhs.len());
    let (mut i, mut j) = (0, 0);
    while i < lhs.len() || j < rhs.len() {
        let column = match (lhs.get(i), rhs.get(j)) {
            (Some(a), Some(b)) => a.0.min(b.0),
            (Some(a), None) => a.0,
            (None, Some(b)) => b.0,
            (None, None) => unreachable!(),
        };
        let mut value = F::ZERO;
        if i < lhs.len() && lhs[i].0 == column {
            value += lhs[i].1;
            i += 1;
        }
        if j < rhs.len() && rhs[j].0 == column {
            value += if subtract { -rhs[j].1 } else { rhs[j].1 };
            j += 1;
        }
        if require_ternary && !ternary(value) {
            return None;
        }
        if !value.is_zero() {
            result.push((column, value));
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{extract, extract_cqbdd, matrix::DenseMatrix, MinimizeStrategy},
            *,
        },
        ark_ff::AdditiveGroup,
        provekit_backend_bn254::FieldElement as F,
        provekit_common::R1CS,
    };

    // Previous eager implementation, retained only as a test/benchmark oracle.
    impl Cut<F> {
        fn reference_try_shear(
            &mut self,
            p: usize,
            q: usize,
            subtract: bool,
            ternary_left: bool,
        ) -> bool {
            if self.incoming[p].is_empty() || self.incoming[q].is_empty() {
                return false;
            }
            let Some(incoming) =
                combine(&self.incoming[q], &self.incoming[p], subtract, ternary_left)
            else {
                return false;
            };
            let Some(outgoing) = combine(&self.outgoing[p], &self.outgoing[q], !subtract, true)
            else {
                return false;
            };
            let before = self.incoming[p].len()
                + self.incoming[q].len()
                + self.outgoing[p].len()
                + self.outgoing[q].len();
            let after = incoming.len()
                + outgoing.len()
                + if outgoing.is_empty() {
                    0
                } else {
                    self.incoming[p].len()
                }
                + if incoming.is_empty() {
                    0
                } else {
                    self.outgoing[q].len()
                };
            if after >= before {
                return false;
            }
            self.incoming[q] = incoming;
            self.outgoing[p] = outgoing;
            if self.outgoing[p].is_empty() {
                self.incoming[p].clear();
            }
            if self.incoming[q].is_empty() {
                self.outgoing[q].clear();
            }
            true
        }
    }

    fn matrix(rows: usize, cols: usize, values: &[i64]) -> DenseMatrix<F> {
        assert_eq!(values.len(), rows * cols);
        DenseMatrix {
            num_rows: rows,
            num_cols: cols,
            values:   values.iter().copied().map(F::from).collect(),
        }
    }

    fn dense_layer(rows: usize, cols: usize, values: [&[i64]; 2]) -> MbpLayer<F> {
        MbpLayer {
            matrices: values.map(|values| Core::Dense(matrix(rows, cols, values))),
        }
    }

    // Independent evaluation of every assignment, without using the rewrites.
    fn table(program: &MatrixBranchingProgram<F>) -> Vec<Vec<F>> {
        (0..1usize << program.layers.len())
            .map(|assignment| {
                if let Some(values) = program.constant {
                    return values.to_vec();
                }
                let mut values = vec![F::ONE];
                for (level, layer) in program.layers.iter().enumerate().rev() {
                    let core = &layer.matrices[(assignment >> level) & 1];
                    assert_eq!(core.num_cols(), values.len());
                    let mut next = vec![F::ZERO; core.num_rows()];
                    for ((row, column), value) in core.iter() {
                        next[row] += value * values[column];
                    }
                    values = next;
                }
                values
            })
            .collect()
    }

    fn cost(program: &MatrixBranchingProgram<F>) -> (usize, usize) {
        (
            program.layers.iter().map(layer_nnz).sum(),
            program
                .layers
                .iter()
                .take(program.layers.len().saturating_sub(1))
                .map(|layer| layer.matrices[0].num_cols())
                .sum(),
        )
    }

    fn assert_optimized(program: &mut MatrixBranchingProgram<F>) {
        let expected = table(program);
        let before = cost(program);
        let variables = program.layers.len();
        let constant = program.constant;
        program.minimize_ternary();
        assert_eq!(table(program), expected);
        assert_eq!(program.layers.len(), variables);
        assert_eq!(program.constant, constant);
        assert!(program.layers.iter().skip(1).all(layer_is_ternary));
        assert!(cost(program) <= before);
    }

    #[test]
    fn exhaustive_equivalence_for_generated_cores_and_storage_formats() {
        for seed in 0..48u64 {
            let mut state = seed + 1;
            let mut next = || {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                state >> 32
            };
            let widths = [3, 1 + seed as usize % 5, 4, 3, 1];
            let layers = widths
                .windows(2)
                .enumerate()
                .map(|(level, dims)| MbpLayer {
                    matrices: std::array::from_fn(|bit| {
                        let mut dense = DenseMatrix::zeros(dims[0], dims[1]);
                        for value in &mut dense.values {
                            *value = if level == 0 {
                                F::from((next() % 7) as i64 - 3)
                            } else {
                                match next() % 4 {
                                    0 => F::ONE,
                                    1 => -F::ONE,
                                    _ => F::ZERO,
                                }
                            };
                        }
                        match (seed as usize + level + bit) % 3 {
                            0 => Core::Dense(dense),
                            1 => Core::force_sparse(dense),
                            _ => Core::force_direct(dense),
                        }
                    }),
                })
                .collect();
            let mut program = MatrixBranchingProgram {
                index_bits: 2,
                layers,
                constant: None,
            };
            assert_optimized(&mut program);
            // A second invocation must already be at a fixed point.
            let optimized = cost(&program);
            assert_optimized(&mut program);
            assert_eq!(cost(&program), optimized);
        }
    }

    #[test]
    fn rejects_rank_proposal_when_absorbed_transfer_is_not_ternary() {
        let mut program = MatrixBranchingProgram {
            index_bits: 1,
            layers:     vec![
                dense_layer(3, 2, [&[1, 1, 0, 0, 0, 0], &[0; 6]]),
                dense_layer(2, 1, [&[1, 1], &[1, 1]]),
            ],
            constant:   None,
        };
        // Forward factorization combines the two outgoing rows into [2, 2].
        let expected = table(&program);
        let before = cost(&program);
        assert!(!program.try_ternary_rank(0, true));
        assert_eq!(cost(&program), before);
        assert_eq!(table(&program), expected);

        // Backward factorization can instead absorb the 2 into the weighted
        // boundary. That is permitted, and reduces the number of nonzeros.
        assert!(program.try_ternary_rank(0, false));
        assert_eq!(table(&program), expected);
        assert!(cost(&program) < before);
        assert!(layer_is_ternary(&program.layers[1]));
        assert!(!layer_is_ternary(&program.layers[0]));
    }

    #[test]
    fn rejects_ternary_rank_reduction_that_increases_total_nonzeros() {
        let mut program = MatrixBranchingProgram {
            index_bits: 2,
            layers:     vec![
                dense_layer(3, 3, [&[1, 0, 1, 0, 1, 1, 0, 0, 0], &[0; 9]]),
                dense_layer(3, 2, [&[0, 0, 0, 0, 1, 1], &[0, 0, 0, 0, 1, 1]]),
                dense_layer(2, 1, [&[1, 1], &[0, 1]]),
            ],
            constant:   None,
        };
        // The third incoming column is the sum of the first two. Eliminating
        // it saves two incoming entries but duplicates four outgoing entries.
        assert_eq!(program.ternary_cut_cost(0), (8, 3));
        let expected = table(&program);
        assert!(!program.try_ternary_rank(0, true));
        assert_eq!(program.ternary_cut_cost(0), (8, 3));
        assert_eq!(table(&program), expected);
    }

    fn cut_product(cut: &Cut<F>) -> DenseMatrix<F> {
        let mut result = DenseMatrix::zeros(2 * cut.left_rows, 2 * cut.right_cols);
        for (incoming, outgoing) in cut.incoming.iter().zip(&cut.outgoing) {
            for &(row, a) in incoming {
                for &(column, b) in outgoing {
                    result[(row, column)] += a * b;
                }
            }
        }
        result
    }

    fn pair_cost(cut: &Cut<F>) -> usize {
        cut.incoming.iter().chain(&cut.outgoing).map(Vec::len).sum()
    }

    fn copy_cut(cut: &Cut<F>) -> Cut<F> {
        Cut {
            incoming:   cut.incoming.clone(),
            outgoing:   cut.outgoing.clone(),
            left_rows:  cut.left_rows,
            right_cols: cut.right_cols,
        }
    }

    fn sparse_vectors(alphabet: &[i64], width: usize) -> Vec<SparseVector<F>> {
        (0..alphabet.len().pow(width as u32))
            .map(|mut code| {
                (0..width)
                    .filter_map(|column| {
                        let value = alphabet[code % alphabet.len()];
                        code /= alphabet.len();
                        (value != 0).then_some((column, F::from(value)))
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn bounded_scoring_matches_materialized_sums_exhaustively() {
        for (alphabet, require_ternary) in
            [(&[-1, 0, 1][..], true), (&[-2, -1, 0, 1, 2][..], false)]
        {
            let vectors = sparse_vectors(alphabet, 3);
            for lhs in &vectors {
                for rhs in &vectors {
                    for subtract in [false, true] {
                        let expected = combine(lhs, rhs, subtract, require_ternary);
                        for limit in 0..=6 {
                            assert_eq!(
                                combined_nnz(lhs, rhs, subtract, require_ternary, limit),
                                expected.as_ref().map(Vec::len).filter(|&nnz| nnz <= limit)
                            );
                        }
                        if let Some(expected) = expected {
                            assert!(combined_nnz_lower_bound(lhs, rhs) <= expected.len());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn lazy_shear_matches_eager_acceptance_and_state_exhaustively() {
        let outgoing = sparse_vectors(&[-1, 0, 1], 2);
        for ternary_left in [false, true] {
            let incoming = if ternary_left {
                sparse_vectors(&[-1, 0, 1], 2)
            } else {
                sparse_vectors(&[-2, -1, 0, 1, 2], 2)
            };
            for ap in &incoming {
                for aq in &incoming {
                    for bp in &outgoing {
                        for bq in &outgoing {
                            for subtract in [false, true] {
                                let mut actual = Cut {
                                    incoming:   vec![ap.clone(), aq.clone()],
                                    outgoing:   vec![bp.clone(), bq.clone()],
                                    left_rows:  1,
                                    right_cols: 1,
                                };
                                let mut expected = copy_cut(&actual);
                                assert_eq!(
                                    actual.try_shear(0, 1, subtract, ternary_left),
                                    expected.reference_try_shear(0, 1, subtract, ternary_left)
                                );
                                assert_eq!(actual.incoming, expected.incoming);
                                assert_eq!(actual.outgoing, expected.outgoing);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "manual rejected-shear benchmark; run with --test-threads=1 --nocapture"]
    fn benchmark_rejected_shears() {
        use std::{hint::black_box, time::Instant};

        fn vector(start: usize, step: usize, count: usize, value: i64) -> SparseVector<F> {
            (0..count)
                .map(|i| (start + step * i, F::from(value)))
                .collect()
        }

        let cases = [
            (
                "disjoint ranges",
                [vector(0, 1, 64, 1), vector(64, 1, 64, 1)],
                [vector(0, 1, 64, 1), vector(64, 1, 64, 1)],
            ),
            (
                "interleaved disjoint supports",
                [vector(0, 2, 64, 1), vector(1, 2, 64, 1)],
                [vector(0, 2, 64, 1), vector(1, 2, 64, 1)],
            ),
            (
                "early ternary conflict",
                [vector(0, 1, 64, 1), vector(0, 1, 64, 1)],
                [vector(0, 2, 64, 1), vector(1, 2, 64, 1)],
            ),
            (
                "short outgoing conflict",
                [vector(0, 2, 512, 1), vector(1, 2, 512, 1)],
                [vector(0, 1, 2, 1), vector(0, 1, 2, -1)],
            ),
            (
                "length bound",
                [vector(0, 2, 512, 1), vector(1, 2, 8, 1)],
                [vector(0, 2, 8, 1), vector(1, 2, 512, 1)],
            ),
            ("cost tie", [vector(0, 1, 1, 1), vector(1, 1, 1, 1)], [
                vector(0, 1, 2, 1),
                vector(0, 1, 1, 1),
            ]),
            (
                "one-entry conflict",
                [vector(0, 1, 1, 1), vector(0, 1, 1, 1)],
                [vector(0, 1, 1, 1), vector(1, 1, 1, 1)],
            ),
        ];
        for (name, incoming, outgoing) in cases {
            let mut cut = Cut {
                incoming:   incoming.into(),
                outgoing:   outgoing.into(),
                left_rows:  512,
                right_cols: 512,
            };
            for (strategy, trial) in [
                (
                    "eager",
                    Cut::reference_try_shear as fn(&mut Cut<F>, usize, usize, bool, bool) -> bool,
                ),
                ("scored", Cut::try_shear),
            ] {
                for _ in 0..100 {
                    assert!(!trial(black_box(&mut cut), 0, 1, false, true));
                }
                #[cfg(feature = "profiling-allocator")]
                let count = crate::ALLOCATOR.count();
                let start = Instant::now();
                for _ in 0..100_000 {
                    assert!(!trial(black_box(&mut cut), 0, 1, false, true));
                }
                let elapsed = start.elapsed();
                #[cfg(feature = "profiling-allocator")]
                let allocations = crate::ALLOCATOR.count() - count;
                eprintln!("{name}, {strategy}: {elapsed:?} per 100,000 rejected trials");
                #[cfg(feature = "profiling-allocator")]
                eprintln!("  {allocations} allocations");
            }
        }
    }

    #[test]
    fn paired_shear_reduces_nonzeros_without_changing_two_bit_products() {
        for subtract in [false, true] {
            let sign = if subtract { -F::ONE } else { F::ONE };
            let mut cut = Cut {
                incoming:   vec![vec![(0, F::ONE)], vec![(1, F::ONE)]],
                outgoing:   vec![vec![(0, sign), (1, sign), (2, F::ONE)], vec![
                    (0, F::ONE),
                    (1, F::ONE),
                ]],
                left_rows:  1,
                right_cols: 2,
            };
            let expected = cut_product(&cut);
            assert_eq!(pair_cost(&cut), 7);
            assert!(cut.try_shear(0, 1, subtract, true));
            assert_eq!(pair_cost(&cut), 6);
            assert_eq!(cut_product(&cut), expected);
            let (left, right) = cut.into_layers();
            assert!(layer_is_ternary(&left));
            assert!(layer_is_ternary(&right));
            assert_eq!(cut_product(&Cut::new(&left, &right)), expected);
        }
    }

    #[test]
    fn shear_rejects_nonternary_emissions_and_moves_without_savings() {
        let mut cut = Cut {
            incoming:   vec![vec![(0, F::ONE)], vec![(0, F::ONE)]],
            outgoing:   vec![vec![(0, F::ONE), (1, F::ONE)]; 2],
            left_rows:  1,
            right_cols: 1,
        };
        let expected = cut_product(&cut);
        assert!(!cut.try_shear(0, 1, false, true)); // Incoming 2.
        assert_eq!(cut_product(&cut), expected);
        assert_eq!(pair_cost(&cut), 6);
        assert!(cut.try_shear(0, 1, false, false)); // Allowed at the boundary.
        assert_eq!(cut_product(&cut), expected);
        assert!(cut.incoming[0].is_empty());
        let (left, right) = cut.into_layers();
        assert_eq!(left.matrices[0].num_cols(), 1);
        assert!(!layer_is_ternary(&left));
        assert!(layer_is_ternary(&right));

        let mut cut = Cut {
            incoming:   vec![vec![(0, F::ONE)], vec![(1, F::ONE)]],
            outgoing:   vec![vec![(0, F::ONE)], vec![(0, -F::ONE)]],
            left_rows:  1,
            right_cols: 1,
        };
        assert!(!cut.try_shear(0, 1, false, true)); // Outgoing 2.
        cut.outgoing[1] = vec![(1, F::ONE)];
        assert!(!cut.try_shear(0, 1, false, true)); // Adds nonzeros.
    }

    #[test]
    fn removes_dead_states_and_handles_zero_widths_and_constants() {
        let mut program = MatrixBranchingProgram {
            index_bits: 1,
            layers:     vec![
                dense_layer(3, 2, [&[1, 1, 2, 2, 3, 3]; 2]),
                dense_layer(2, 1, [&[1, -1]; 2]),
            ],
            constant:   None,
        };
        assert_optimized(&mut program);
        assert_eq!(cost(&program), (0, 0));
        assert_optimized(&mut program);

        let mut cut = Cut {
            incoming:   vec![vec![], vec![(0, F::ONE)], vec![]],
            outgoing:   vec![vec![(0, F::ONE)], vec![], vec![]],
            left_rows:  1,
            right_cols: 1,
        };
        assert!(cut.remove_dead());
        let (left, right) = cut.into_layers();
        assert_eq!(left.matrices[0].num_cols(), 0);
        assert_eq!(right.matrices[0].num_rows(), 0);

        let mut constant = MatrixBranchingProgram {
            index_bits: 0,
            layers:     vec![],
            constant:   Some([F::from(7u64); 3]),
        };
        assert_optimized(&mut constant);
        let mut single = MatrixBranchingProgram {
            index_bits: 0,
            layers:     vec![dense_layer(3, 1, [&[2, 3, 4], &[-5, 0, 7]])],
            constant:   None,
        };
        assert_optimized(&mut single);
    }

    #[test]
    fn ternary_extraction_preserves_r1cs_coefficients_and_padded_domain() {
        let mut r1cs = R1CS::<F>::new();
        r1cs.add_witnesses(7);
        for row in 0..5usize {
            let a: Vec<_> = (0..7)
                .map(|col| (F::from(((row + 1) * (col + 1)) as u64), col))
                .collect();
            r1cs.add_constraint(&a, &[(F::from(-3i64), row)], &[(
                F::from(7u64),
                (row + 1) % 7,
            )]);
        }
        let original = extract_cqbdd(&r1cs).to_mbp();
        let optimized = extract(&r1cs, MinimizeStrategy::Ternary);
        assert!(cost(&optimized) <= cost(&original));
        assert!(optimized.layers.iter().skip(1).all(layer_is_ternary));
        for (assignment, values) in table(&optimized).into_iter().enumerate() {
            let mut row = 0;
            let mut col = 0;
            for bit in 0..3 {
                row |= ((assignment >> (2 * bit)) & 1) << bit;
                col |= ((assignment >> (2 * bit + 1)) & 1) << bit;
            }
            let expected = [&r1cs.a, &r1cs.b, &r1cs.c].map(|matrix| {
                if row < matrix.num_rows && col < matrix.num_cols {
                    matrix
                        .get(row, col)
                        .map_or(F::ZERO, |value| r1cs.interner.get(value).unwrap())
                } else {
                    F::ZERO
                }
            });
            assert_eq!(values, expected, "row {row}, column {col}");
        }
        let empty = extract(&R1CS::<F>::new(), MinimizeStrategy::Ternary);
        assert_eq!(empty.constant, Some([F::ZERO; 3]));
        let mut constant = R1CS::<F>::new();
        constant.add_witnesses(1);
        constant.add_constraint(&[(F::from(7u64), 0)], &[], &[]);
        assert_eq!(
            extract(&constant, MinimizeStrategy::Ternary).constant,
            Some([F::from(7u64), F::ZERO, F::ZERO])
        );
    }
}
