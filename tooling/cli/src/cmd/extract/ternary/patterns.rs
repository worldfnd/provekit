//! Share signed subexpressions across a cut:
//! L R = [L, L t] [R - t h; h]. The transpose shares incoming columns.
//! Candidate enumeration is bounded; every accepted rewrite is scored exactly.
use {
    super::{ternary, Cut, SparseVector},
    ark_ff::Field,
    std::{
        cmp::Reverse,
        collections::{hash_map::Entry, HashMap},
    },
    tracing::{info, instrument},
};

// At most C(8,2) + C(8,3) = 84 candidates per live state. Prefer coordinates
// used by many states; break ties by coordinate for deterministic discovery.
const MAX_PATTERN_ENTRIES: usize = 8;

/// Sorted coordinates with first coefficient +1; remaining signs are relative
/// to the first. Pairs leave their last coordinate/sign zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Pattern {
    columns:  [usize; 3],
    negative: u8,
    len:      u8,
}

impl Pattern {
    fn new(entries: &[(usize, bool)]) -> Self {
        let mut pattern = Self {
            columns:  [0; 3],
            negative: 0,
            len:      entries.len() as u8,
        };
        for (i, &(column, negative)) in entries.iter().enumerate() {
            pattern.columns[i] = column;
            pattern.negative |= u8::from(negative ^ entries[0].1) << i;
        }
        pattern
    }

    fn columns(&self) -> &[usize] {
        &self.columns[..usize::from(self.len)]
    }

    fn value<F: Field>(&self, index: usize) -> F {
        if self.negative & (1 << index) == 0 {
            F::ONE
        } else {
            -F::ONE
        }
    }

    fn matches<F: Field>(&self, vector: &[(usize, F)], negative: bool) -> bool {
        self.columns().iter().enumerate().all(|(i, column)| {
            let Ok(index) = vector.binary_search_by_key(column, |&(column, _)| column) else {
                return false;
            };
            let expected = self.value::<F>(i);
            vector[index].1 == if negative { -expected } else { expected }
        })
    }

    fn vector<F: Field>(&self) -> SparseVector<F> {
        self.columns()
            .iter()
            .enumerate()
            .map(|(i, &column)| (column, self.value(i)))
            .collect()
    }
}

#[derive(Clone, Copy)]
struct Occurrence {
    state:    usize,
    negative: bool,
}

/// Avoid a heap allocation for every pattern that occurs only once.
enum Occurrences {
    One(Occurrence),
    Many(Vec<Occurrence>),
}

fn record(table: &mut HashMap<Pattern, Occurrences>, entries: &[(usize, bool)], state: usize) {
    let occurrence = Occurrence {
        state,
        negative: entries[0].1,
    };
    match table.entry(Pattern::new(entries)) {
        Entry::Vacant(entry) => {
            entry.insert(Occurrences::One(occurrence));
        }
        Entry::Occupied(mut entry) => {
            let value = entry.get_mut();
            match value {
                Occurrences::One(previous) => {
                    *value = Occurrences::Many(vec![*previous, occurrence]);
                }
                Occurrences::Many(occurrences) => occurrences.push(occurrence),
            }
        }
    }
}

fn candidates<F: Field>(
    source: &[SparseVector<F>],
    other: &[SparseVector<F>],
    dimension: usize,
) -> Vec<(Pattern, Vec<Occurrence>)> {
    let mut frequencies = vec![0usize; dimension];
    for (row, opposite) in source.iter().zip(other) {
        if opposite.is_empty() {
            continue;
        }
        for &(column, value) in row {
            if value == F::ONE || value == -F::ONE {
                frequencies[column] += 1;
            }
        }
    }
    let mut table = HashMap::new();
    let mut entries = Vec::new();
    for (state, (row, opposite)) in source.iter().zip(other).enumerate() {
        if opposite.is_empty() {
            continue;
        }
        entries.clear();
        entries.extend(row.iter().filter_map(|&(column, value)| {
            (frequencies[column] > 1 && (value == F::ONE || value == -F::ONE))
                .then_some((column, value != F::ONE))
        }));
        if entries.len() > MAX_PATTERN_ENTRIES {
            entries.select_nth_unstable_by_key(MAX_PATTERN_ENTRIES, |&(column, _)| {
                (Reverse(frequencies[column]), column)
            });
            entries.truncate(MAX_PATTERN_ENTRIES);
        }
        entries.sort_unstable_by_key(|&(column, _)| column);
        for i in 0..entries.len() {
            for j in i + 1..entries.len() {
                record(&mut table, &[entries[i], entries[j]], state);
                for k in j + 1..entries.len() {
                    record(&mut table, &[entries[i], entries[j], entries[k]], state);
                }
            }
        }
    }
    let mut candidates: Vec<_> = table
        .into_iter()
        .filter_map(|(pattern, occurrences)| match occurrences {
            Occurrences::One(_) => None,
            Occurrences::Many(occurrences) => Some((pattern, occurrences)),
        })
        .collect();
    // Prefer larger potential reuse. This is only a priority, not the actual
    // gain: the opposite-side sum and dead-state savings are scored below.
    candidates.sort_unstable_by_key(|(pattern, occurrences)| {
        (
            Reverse((occurrences.len() - 1) * usize::from(pattern.len)),
            *pattern,
        )
    });
    candidates
}

/// Reusable accumulator for sums of signed sparse vectors. Only touched slots
/// are cleared. Check the final sum: a partial +/-2 may subsequently cancel.
struct Sum<F: Field> {
    values:  Vec<F>,
    marked:  Vec<bool>,
    touched: Vec<usize>,
}

impl<F: Field> Sum<F> {
    fn new(dimension: usize) -> Self {
        Self {
            values:  vec![F::ZERO; dimension],
            marked:  vec![false; dimension],
            touched: Vec::new(),
        }
    }

    fn add(&mut self, vector: &[(usize, F)], negative: bool) {
        for &(column, value) in vector {
            if !self.marked[column] {
                self.marked[column] = true;
                self.touched.push(column);
            }
            self.values[column] += if negative { -value } else { value };
        }
    }

    fn nnz(&self, require_ternary: bool) -> Option<usize> {
        let mut nnz = 0;
        for &column in &self.touched {
            let value = self.values[column];
            if require_ternary && !ternary(value) {
                return None;
            }
            nnz += usize::from(!value.is_zero());
        }
        Some(nnz)
    }

    fn clear(&mut self) {
        for column in self.touched.drain(..) {
            self.values[column] = F::ZERO;
            self.marked[column] = false;
        }
    }

    fn take(&mut self, nnz: usize) -> SparseVector<F> {
        let mut result = Vec::with_capacity(nnz);
        self.touched.sort_unstable();
        for column in self.touched.drain(..) {
            let value = std::mem::replace(&mut self.values[column], F::ZERO);
            self.marked[column] = false;
            if !value.is_zero() {
                result.push((column, value));
            }
        }
        result
    }
}

impl<F: Field> Cut<F> {
    /// One discovery pass per orientation. New states and newly exposed
    /// patterns are reconsidered by the enclosing optimizer's next sweep.
    /// Each accepted extraction strictly reduces nnz, even if width grows.
    #[instrument(skip_all)]
    pub(super) fn extract_shared_patterns(&mut self, ternary_left: bool) -> usize {
        let outgoing = extract(
            &mut self.outgoing,
            &mut self.incoming,
            2 * self.right_cols,
            2 * self.left_rows,
            ternary_left,
            "outgoing",
        );
        let incoming = extract(
            &mut self.incoming,
            &mut self.outgoing,
            2 * self.left_rows,
            2 * self.right_cols,
            true,
            "incoming",
        );
        outgoing + incoming
    }
}

/// Factor patterns out of source vectors and combine their opposite vectors.
/// The transpose uses the identical algebra. Source residuals only lose
/// entries, so only the new opposite vector can violate the coefficient
/// alphabet.
fn extract<F: Field>(
    source: &mut Vec<SparseVector<F>>,
    other: &mut Vec<SparseVector<F>>,
    source_dimension: usize,
    other_dimension: usize,
    require_ternary: bool,
    direction: &str,
) -> usize {
    let candidates = candidates(source, other, source_dimension);
    let count = candidates.len();
    if count == 0 {
        return 0;
    }
    let mut sum = Sum::new(other_dimension);
    let (mut accepted, mut saved) = (0, 0);
    for (pattern, mut occurrences) in candidates {
        // Earlier extractions may have removed shared entries or entire states.
        // State IDs stay stable until Cut::into_layers compacts them.
        occurrences.retain(|occurrence| {
            !other[occurrence.state].is_empty()
                && pattern.matches(&source[occurrence.state], occurrence.negative)
        });
        if occurrences.len() < 2 {
            continue;
        }
        let size = usize::from(pattern.len);
        let mut removed = size * occurrences.len();
        for occurrence in &occurrences {
            sum.add(&other[occurrence.state], occurrence.negative);
            if source[occurrence.state].len() == size {
                removed += other[occurrence.state].len();
            }
        }
        let Some(nnz) = sum.nnz(require_ternary) else {
            sum.clear();
            continue;
        };
        // A zero sum needs no helper state at all.
        let added = if nnz == 0 { 0 } else { size + nnz };
        if added >= removed {
            sum.clear();
            continue;
        }
        for occurrence in occurrences {
            source[occurrence.state].retain(|&(column, _)| !pattern.columns().contains(&column));
            if source[occurrence.state].is_empty() {
                other[occurrence.state].clear();
            }
        }
        if nnz == 0 {
            sum.clear();
        } else {
            source.push(pattern.vector());
            other.push(sum.take(nnz));
        }
        accepted += 1;
        saved += removed - added;
    }
    info!(
        "Shared {direction} patterns: {count} candidates, {accepted} accepted, {saved} nonzeros \
         removed."
    );
    saved
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_ff::{AdditiveGroup, Zero},
        provekit_backend_bn254::FieldElement as F,
    };

    fn vector(entries: &[(usize, i64)]) -> SparseVector<F> {
        entries
            .iter()
            .map(|&(column, value)| (column, F::from(value)))
            .collect()
    }

    fn example() -> Cut<F> {
        Cut {
            incoming:   (0..3).map(|i| vec![(i, F::ONE)]).collect(),
            outgoing:   (0..3)
                .map(|i| vector(&[(0, 1), (1, 1), (i + 2, 1)]))
                .collect(),
            left_rows:  2,
            right_cols: 3,
        }
    }

    fn transpose(cut: Cut<F>) -> Cut<F> {
        Cut {
            incoming:   cut.outgoing,
            outgoing:   cut.incoming,
            left_rows:  cut.right_cols,
            right_cols: cut.left_rows,
        }
    }

    fn nnz(cut: &Cut<F>) -> usize {
        cut.incoming.iter().chain(&cut.outgoing).map(Vec::len).sum()
    }

    fn product(cut: &Cut<F>) -> Vec<Vec<F>> {
        let mut result = vec![vec![F::ZERO; 2 * cut.right_cols]; 2 * cut.left_rows];
        for (incoming, outgoing) in cut.incoming.iter().zip(&cut.outgoing) {
            for &(row, a) in incoming {
                for &(column, b) in outgoing {
                    result[row][column] += a * b;
                }
            }
        }
        result
    }

    fn check(cut: &mut Cut<F>, ternary_left: bool) -> usize {
        let before = nnz(cut);
        let expected = product(cut);
        let saved = cut.extract_shared_patterns(ternary_left);
        assert_eq!(product(cut), expected);
        assert_eq!(nnz(cut) + saved, before);
        assert_eq!(cut.incoming.len(), cut.outgoing.len());
        for side in [&cut.incoming, &cut.outgoing] {
            for row in side {
                assert!(row.windows(2).all(|pair| pair[0].0 < pair[1].0));
                assert!(row.iter().all(|&(_, value)| !value.is_zero()));
            }
        }
        assert!(cut
            .outgoing
            .iter()
            .flatten()
            .all(|&(_, value)| ternary(value)));
        if ternary_left {
            assert!(cut
                .incoming
                .iter()
                .flatten()
                .all(|&(_, value)| ternary(value)));
        }
        saved
    }

    #[test]
    fn shared_pair_escapes_single_shear_plateau_in_both_orientations() {
        for reverse in [false, true] {
            let mut cut = if reverse {
                transpose(example())
            } else {
                example()
            };
            for p in 0..3 {
                for q in 0..3 {
                    if p != q {
                        for subtract in [false, true] {
                            assert!(!cut.try_shear(p, q, subtract, true));
                        }
                    }
                }
            }
            assert_eq!(nnz(&cut), 12);
            assert_eq!(check(&mut cut, true), 1);
            assert_eq!(cut.incoming.len(), 4);
            assert_eq!(nnz(&cut), 11);
            let expected = product(&cut);
            let (left, right) = cut.into_layers();
            assert_eq!(left.matrices[0].num_cols(), 4);
            assert_eq!(product(&Cut::new(&left, &right)), expected);
        }
    }

    #[test]
    fn signed_triples_are_shared_when_pairs_would_only_tie() {
        let mut cut = Cut {
            incoming:   vec![vector(&[(0, 1)]), vector(&[(1, 1)])],
            outgoing:   vec![
                vector(&[(0, 1), (1, -1), (2, 1), (3, 1)]),
                vector(&[(0, -1), (1, 1), (2, -1), (4, 1)]),
            ],
            left_rows:  1,
            right_cols: 3,
        };
        assert_eq!(nnz(&cut), 10);
        assert_eq!(check(&mut cut, true), 1);
        assert_eq!(cut.outgoing[2], vector(&[(0, 1), (1, -1), (2, 1)]));
        assert_eq!(cut.incoming[2], vector(&[(0, 1), (1, -1)]));
    }

    #[test]
    fn scores_opposite_side_and_respects_boundary_exemption() {
        let mut tie = example();
        tie.incoming.pop();
        tie.outgoing.pop();
        assert_eq!(check(&mut tie, true), 0);

        let mut conflict = example();
        conflict.incoming = vec![vector(&[(0, 1)]); 3];
        assert_eq!(check(&mut conflict, true), 0);
        assert_eq!(check(&mut conflict, false), 3);
        assert_eq!(conflict.incoming[3], vector(&[(0, 3)]));

        let mut transposed = example();
        transposed.incoming = vec![vector(&[(0, 1)]); 3];
        let mut transposed = transpose(transposed);
        // Only the incoming (weighted) boundary can contain a general value;
        // a shared incoming pattern may not introduce 3 on the outgoing side.
        assert_eq!(check(&mut transposed, false), 0);

        let mut weighted = example();
        weighted.incoming = vec![vector(&[(0, 2)]), vector(&[(0, 3)]), vector(&[(0, -7)])];
        assert_eq!(check(&mut weighted, false), 3);
        assert_eq!(weighted.incoming[3], vector(&[(0, -2)]));
    }

    #[test]
    fn checks_final_sum_after_cancellation_and_omits_zero_helpers() {
        let mut cut = example();
        cut.incoming = vec![vector(&[(0, 1)]), vector(&[(0, 1)]), vector(&[(0, -1)])];
        assert_eq!(check(&mut cut, true), 3); // Partial sum 2, final sum 1.
        assert_eq!(cut.incoming[3], vector(&[(0, 1)]));

        let mut cut = example();
        cut.incoming = vec![vector(&[(0, 1)]), vector(&[(0, -1)])];
        cut.outgoing.pop();
        assert_eq!(check(&mut cut, true), 4);
        assert_eq!(cut.incoming.len(), 2); // No zero helper appended.
    }

    #[test]
    fn accounts_for_dead_states_and_rechecks_overlapping_candidates() {
        let mut cut = example();
        for row in &mut cut.outgoing {
            row.pop();
        }
        assert_eq!(check(&mut cut, true), 4);
        assert_eq!(nnz(&cut), 5);
        let expected = product(&cut);
        let (left, right) = cut.into_layers();
        assert_eq!(left.matrices[0].num_cols(), 1);
        assert_eq!(product(&Cut::new(&left, &right)), expected);

        let mut cut = example();
        cut.outgoing = vec![vector(&[(0, 1), (1, 1), (2, 1), (3, 1)]); 3];
        // Removing one triple invalidates the other overlapping triples/pairs.
        assert_eq!(check(&mut cut, true), 3);
        assert_eq!(check(&mut cut, true), 0);
    }

    #[test]
    fn discovery_is_bounded_and_prefers_frequent_coordinates() {
        let source = vec![(0..20).map(|i| (i, F::ONE)).collect::<Vec<_>>(); 3];
        let other = (0..3).map(|i| vec![(i, F::ONE)]).collect::<Vec<_>>();
        let found = candidates(&source, &other, 20);
        assert_eq!(found.len(), 84);
        assert!(found.iter().all(|(_, occurrences)| occurrences.len() == 3));

        let mut source: Vec<_> = (0..3)
            .map(|state| {
                (0..20)
                    .map(|i| (state * 20 + i, F::ONE))
                    .collect::<Vec<_>>()
            })
            .collect();
        for row in &mut source {
            row.extend([(60, F::ONE), (61, -F::ONE), (62, F::ONE)]);
        }
        let found = candidates(&source, &other, 63);
        assert_eq!(found.len(), 4); // Three pairs plus the shared triple.
        assert!(found
            .iter()
            .any(|(p, _)| p.len == 3 && p.columns == [60, 61, 62]));
    }

    #[test]
    fn generated_cuts_preserve_every_two_bit_product_and_reach_a_fixed_point() {
        let mut state = 1u64;
        for case in 0..96 {
            let mut random = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                state >> 32
            };
            let width = case % 7;
            let ternary_left = case % 2 == 0;
            let mut vectors = |dimension, weighted| {
                (0..width)
                    .map(|_| {
                        (0..dimension)
                            .filter_map(|column| {
                                let value = if weighted {
                                    F::from((random() % 9) as i64 - 4)
                                } else {
                                    F::from((random() % 3) as i64 - 1)
                                };
                                (!value.is_zero()).then_some((column, value))
                            })
                            .collect()
                    })
                    .collect()
            };
            let mut cut = Cut {
                incoming:   vectors(6, !ternary_left),
                outgoing:   vectors(8, false),
                left_rows:  3,
                right_cols: 4,
            };
            cut.remove_dead();
            let expected = product(&cut);
            let bound = nnz(&cut);
            let mut stopped = false;
            for _ in 0..=bound {
                if check(&mut cut, ternary_left) == 0 {
                    stopped = true;
                    break;
                }
            }
            assert!(stopped);
            let (left, right) = cut.into_layers();
            assert_eq!(product(&Cut::new(&left, &right)), expected);
        }
    }

    #[test]
    #[ignore = "manual shared-pattern throughput; run with --test-threads=1 --nocapture"]
    fn benchmark_shared_patterns() {
        use std::time::Instant;

        let groups = 10_000;
        let width = 3 * groups;
        let mut cut = Cut {
            incoming:   (0..width).map(|i| vec![(i, F::ONE)]).collect(),
            outgoing:   (0..width)
                .map(|i| vector(&[(2 * (i / 3), 1), (2 * (i / 3) + 1, 1), (2 * groups + i, 1)]))
                .collect(),
            left_rows:  width / 2,
            right_cols: (2 * groups + width) / 2,
        };
        let before = nnz(&cut);
        #[cfg(feature = "profiling-allocator")]
        let (base, count) = (crate::ALLOCATOR.reset_max(), crate::ALLOCATOR.count());
        let start = Instant::now();
        let saved = cut.extract_shared_patterns(true);
        let elapsed = start.elapsed();
        #[cfg(feature = "profiling-allocator")]
        let (peak, allocations) = (
            crate::ALLOCATOR.max().saturating_sub(base),
            crate::ALLOCATOR.count() - count,
        );
        assert_eq!(saved, groups);
        assert_eq!(before - nnz(&cut), saved);
        assert_eq!(cut.incoming.len(), width + groups);
        eprintln!(
            "shared patterns: {elapsed:?}, width {width} -> {}, nnz {before} -> {}",
            cut.incoming.len(),
            nnz(&cut)
        );
        #[cfg(feature = "profiling-allocator")]
        eprintln!("peak additional heap {peak} bytes, {allocations} allocations");
    }
}
