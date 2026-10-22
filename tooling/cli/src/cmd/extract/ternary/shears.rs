//! Exact candidate pruning for the ordered shear scan.
//!
//! A profitable shear must shrink either A[:,q] or B[p,:]. For ternary
//! vectors, shrinking dst +/- src requires overlap with more than half of
//! src's support. Every such overlap hits any ceil(|src|/2) source entries;
//! choose rare entries as anchors to avoid high-degree coordinates.
//!
//! At the weighted boundary A need not be ternary, but shrinking still
//! requires at least one exact cancellation. Index (coordinate, +/-value)
//! there instead. Both filters are necessary conditions, never heuristics.

use {
    super::{Cut, SparseVector},
    ark_ff::Field,
    std::{
        collections::{BTreeSet, HashMap},
        hash::Hash,
        time::Instant,
    },
    tracing::info,
};

/// Sorted postings preserve the original p, q, sign trial order. Keys are
/// cached per state so an accepted rewrite can update just the affected lists.
struct Index<K> {
    postings: HashMap<K, BTreeSet<usize>>,
    keys:     Vec<Vec<K>>,
}

impl<K: Copy + Eq + Hash + Ord> Index<K> {
    fn new(keys: Vec<Vec<K>>) -> Self {
        let mut postings = HashMap::<K, BTreeSet<usize>>::new();
        for (state, keys) in keys.iter().enumerate() {
            for &key in keys {
                postings.entry(key).or_default().insert(state);
            }
        }
        Self { postings, keys }
    }

    fn replace(&mut self, state: usize, keys: Vec<K>) {
        if self.keys[state] == keys {
            return;
        }
        for key in &self.keys[state] {
            let states = self.postings.get_mut(key).expect("indexed key");
            states.remove(&state);
            if states.is_empty() {
                self.postings.remove(key);
            }
        }
        for &key in &keys {
            self.postings.entry(key).or_default().insert(state);
        }
        self.keys[state] = keys;
    }

    fn extend(&self, keys: &[K], from: usize, pending: &mut BTreeSet<usize>) {
        for key in keys {
            if let Some(states) = self.postings.get(key) {
                pending.extend(states.range(from..).copied());
            }
        }
    }

    fn anchors(&self, state: usize, ternary: bool) -> Vec<K> {
        let mut keys = self.keys[state].clone();
        if ternary {
            let count = keys.len().div_ceil(2);
            if count < keys.len() {
                keys.select_nth_unstable_by_key(count, |key| (self.postings[key].len(), *key));
                keys.truncate(count);
            }
        }
        keys
    }
}

fn outgoing_anchors<F: Field>(vector: &SparseVector<F>, degrees: &[usize]) -> Vec<usize> {
    let mut keys: Vec<_> = vector.iter().map(|&(column, _)| column).collect();
    let count = keys.len().div_ceil(2);
    if count < keys.len() {
        keys.select_nth_unstable_by_key(count, |&column| (degrees[column], column));
        keys.truncate(count);
    }
    keys.sort_unstable();
    keys
}

/// Coordinates already queried cannot expose a new future q: its anchors
/// stay fixed throughout this p scan. Only newly added support needs a query.
/// In particular, deleting entries from a large hub causes no posting walks.
fn extend_added<F: Field>(
    index: &Index<usize>,
    before: &[(usize, F)],
    after: &[(usize, F)],
    from: usize,
    pending: &mut BTreeSet<usize>,
) {
    let mut old = 0;
    for &(column, _) in after {
        while old < before.len() && before[old].0 < column {
            old += 1;
        }
        if old == before.len() || before[old].0 != column {
            index.extend(&[column], from, pending);
        }
    }
}

impl<F: Field> Cut<F> {
    pub(super) fn shear_sweep(&mut self, ternary_left: bool) -> bool {
        // Tiny cuts are cheaper to scan directly than to index.
        if self.incoming.len() < 32 {
            return self.shear_sweep_all_pairs(ternary_left);
        }
        self.shear_sweep_indexed(ternary_left)
    }

    fn shear_sweep_all_pairs(&mut self, ternary_left: bool) -> bool {
        let mut changed = false;
        for p in 0..self.incoming.len() {
            for q in 0..self.incoming.len() {
                if p != q {
                    for subtract in [false, true] {
                        changed |= self.try_shear(p, q, subtract, ternary_left);
                    }
                }
            }
        }
        changed
    }

    fn shear_sweep_indexed(&mut self, ternary_left: bool) -> bool {
        if ternary_left {
            self.shear_sweep_with_keys(true, |column, _| column)
        } else {
            self.shear_sweep_with_keys(false, |column, value: F| (column, value.min(-value)))
        }
    }

    fn shear_sweep_with_keys<K: Copy + Eq + Hash + Ord>(
        &mut self,
        ternary_left: bool,
        key: impl Fn(usize, F) -> K,
    ) -> bool {
        let start = Instant::now();
        let keys = |vector: &SparseVector<F>| {
            vector
                .iter()
                .map(|&(column, value)| key(column, value))
                .collect()
        };
        let width = self.incoming.len();
        let mut incoming = Index::new(self.incoming.iter().map(keys).collect());
        // Fixed degrees suffice: rarity affects efficiency, not coverage.
        let mut degrees = vec![0usize; 2 * self.right_cols];
        for vector in &self.outgoing {
            for &(column, _) in vector {
                degrees[column] += 1;
            }
        }
        let mut outgoing = Index::new(
            self.outgoing
                .iter()
                .map(|v| outgoing_anchors(v, &degrees))
                .collect(),
        );
        let mut pending = BTreeSet::new();
        let (mut trials, mut accepted) = (0usize, 0usize);
        for p in 0..width {
            if self.incoming[p].is_empty() {
                continue;
            }
            pending.clear();
            incoming.extend(&incoming.anchors(p, ternary_left), 0, &mut pending);
            // Reverse query: outgoing[q] is the source of B[p] -= s B[q].
            for &(column, _) in &self.outgoing[p] {
                outgoing.extend(&[column], 0, &mut pending);
            }
            let mut changed_p = false;
            while let Some(q) = pending.pop_first() {
                if p == q || self.incoming[q].is_empty() {
                    continue;
                }
                let mut changed_q = false;
                for subtract in [false, true] {
                    trials += 1;
                    if self.try_shear_with(p, q, subtract, ternary_left, |before, after| {
                        extend_added(&outgoing, before, after, q + 1, &mut pending);
                    }) {
                        accepted += 1;
                        changed_q = true;
                    }
                }
                if !changed_q {
                    continue;
                }
                changed_p = true;
                incoming.replace(q, keys(&self.incoming[q]));
                if self.incoming[q].is_empty() {
                    outgoing.replace(q, Vec::new());
                }
                if self.incoming[p].is_empty() {
                    incoming.replace(p, Vec::new());
                    break;
                }
                // A[:,p] and future A[:,q] are unchanged. The acceptance
                // callback already enqueued any new B[p,:] candidates.
            }
            if changed_p {
                outgoing.replace(p, outgoing_anchors(&self.outgoing[p], &degrees));
            }
        }
        info!(
            "Shear scan: {trials} of {} signed trials, {accepted} accepted, {:?}.",
            width
                .saturating_mul(width.saturating_sub(1))
                .saturating_mul(2),
            start.elapsed()
        );
        accepted != 0
    }
}

#[cfg(test)]
mod tests {
    use {super::*, provekit_backend_bn254::FieldElement as F};

    fn copy_cut(cut: &Cut<F>) -> Cut<F> {
        Cut {
            incoming:   cut.incoming.clone(),
            outgoing:   cut.outgoing.clone(),
            left_rows:  cut.left_rows,
            right_cols: cut.right_cols,
        }
    }

    fn compare(mut cut: Cut<F>, ternary_left: bool) {
        cut.remove_dead();
        let mut expected = copy_cut(&cut);
        for _ in 0..3 {
            assert_eq!(
                cut.shear_sweep_indexed(ternary_left),
                expected.shear_sweep_all_pairs(ternary_left)
            );
            assert_eq!(cut.incoming, expected.incoming, "different incoming cores");
            assert_eq!(cut.outgoing, expected.outgoing, "different outgoing cores");
        }
    }

    fn vectors(alphabet: &[i64]) -> Vec<SparseVector<F>> {
        alphabet
            .iter()
            .flat_map(|&x| {
                alphabet.iter().map(move |&y| {
                    [x, y]
                        .into_iter()
                        .enumerate()
                        .filter_map(|(column, value)| {
                            (value != 0).then_some((column, F::from(value)))
                        })
                        .collect()
                })
            })
            .collect()
    }

    #[test]
    fn indexed_scan_matches_all_pairs_exhaustively() {
        let outgoing = vectors(&[-1, 0, 1]);
        for ternary_left in [false, true] {
            let incoming = vectors(if ternary_left {
                &[-1, 0, 1]
            } else {
                &[-2, -1, 0, 1, 2]
            });
            for ap in &incoming {
                for aq in &incoming {
                    for bp in &outgoing {
                        for bq in &outgoing {
                            compare(
                                Cut {
                                    incoming:   vec![ap.clone(), aq.clone()],
                                    outgoing:   vec![bp.clone(), bq.clone()],
                                    left_rows:  1,
                                    right_cols: 1,
                                },
                                ternary_left,
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn indexed_scan_matches_mutating_scans_with_hubs_and_general_boundary() {
        let mut seed = 783837_u64;
        let mut random = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            seed >> 32
        };
        for _ in 0..2000 {
            let width = 2 + random() as usize % 18;
            let dimension = 2 * (1 + random() as usize % 8);
            let ternary_left = random() % 2 == 0;
            let mut vectors = |general| {
                (0..width)
                    .map(|_| {
                        (0..dimension)
                            .filter_map(|column| {
                                let sample = random();
                                let value = if general {
                                    (sample % 9) as i64 - 4
                                } else {
                                    (sample % 3) as i64 - 1
                                };
                                (value != 0 && (column == 0 || sample % 5 < 2))
                                    .then_some((column, F::from(value)))
                            })
                            .collect()
                    })
                    .collect()
            };
            compare(
                Cut {
                    incoming:   vectors(!ternary_left),
                    outgoing:   vectors(false),
                    left_rows:  dimension / 2,
                    right_cols: dimension / 2,
                },
                ternary_left,
            );
        }
    }

    #[test]
    fn index_updates_remove_old_keys_and_keep_postings_ordered() {
        let mut index = Index::new(vec![vec![1, 4], vec![1, 2], vec![2, 3]]);
        index.replace(1, vec![3, 4]);
        index.replace(0, Vec::new());
        let mut pending = BTreeSet::new();
        index.extend(&[1, 2, 3, 4], 1, &mut pending);
        assert_eq!(pending.into_iter().collect::<Vec<_>>(), [1, 2]);
        assert!(!index.postings.contains_key(&1));
        assert_eq!(index.postings[&4].iter().copied().collect::<Vec<_>>(), [1]);
    }

    #[test]
    fn outgoing_refresh_queries_only_added_coordinates_and_future_states() {
        let index = Index::new(vec![vec![3], vec![1], vec![2], vec![3]]);
        let before = vec![(1, F::ONE), (2, F::ONE)];
        let after = vec![(2, -F::ONE), (3, F::ONE)];
        let mut pending = BTreeSet::new();
        extend_added(&index, &before, &after, 1, &mut pending);
        assert_eq!(pending.into_iter().collect::<Vec<_>>(), [3]);
    }

    #[test]
    #[ignore = "manual real-cut comparison; set PROVEKIT_BENCH_VERIFIER and optionally \
                PROVEKIT_BENCH_CUT"]
    fn benchmark_target_shear_cut() {
        use {
            crate::cmd::extract::extract_cqbdd, provekit_backend_bn254::Verifier,
            provekit_common::file::read,
        };
        provekit_backend_bn254::register();
        let path = std::env::var("PROVEKIT_BENCH_VERIFIER").expect("path to a prepared PKV");
        let cut: usize = std::env::var("PROVEKIT_BENCH_CUT")
            .unwrap_or_else(|_| "7".into())
            .parse()
            .unwrap();
        let verifier: Verifier = read(std::path::Path::new(&path)).unwrap();
        let mut program = extract_cqbdd(&verifier.r1cs).to_mbp();
        program.try_ternary_rank(cut, true);
        let mut original = Cut::new(&program.layers[cut], &program.layers[cut + 1]);
        original.remove_dead();
        let mut indexed = copy_cut(&original);
        let start = Instant::now();
        let changed = original.shear_sweep_all_pairs(cut != 0);
        let baseline = start.elapsed();
        let start = Instant::now();
        assert_eq!(indexed.shear_sweep_indexed(cut != 0), changed);
        eprintln!(
            "Real cut {cut}, width {}: all-pairs {baseline:?}, indexed {:?}",
            original.incoming.len(),
            start.elapsed()
        );
        assert_eq!(indexed.incoming, original.incoming);
        assert_eq!(indexed.outgoing, original.outgoing);
    }

    #[test]
    #[ignore = "manual sparse scan benchmark; run with --test-threads=1 --nocapture"]
    fn benchmark_sparse_shear_scan() {
        // A large weighted boundary with distinct coefficients, as in the
        // first sha256_35 cut. Outgoing rows have disjoint supports.
        let width = 20_000;
        let cut = Cut {
            incoming:   (0..width)
                .map(|i| vec![(0, F::from((i + 1) as u64))])
                .collect(),
            outgoing:   (0..width)
                .map(|i| vec![(2 * i, F::ONE), (2 * i + 1, F::ONE)])
                .collect(),
            left_rows:  1,
            right_cols: width,
        };
        for indexed in [false, true] {
            let mut actual = copy_cut(&cut);
            let start = Instant::now();
            let changed = if indexed {
                actual.shear_sweep_indexed(false)
            } else {
                actual.shear_sweep_all_pairs(false)
            };
            eprintln!("indexed={indexed}, width={width}: {:?}", start.elapsed());
            assert!(!changed);
            assert_eq!(actual.incoming, cut.incoming);
            assert_eq!(actual.outgoing, cut.outgoing);
        }
    }
}
