//! Reduce the coefficient alphabet before extracting coefficient-triplet sets.
//!
//! Row scaling preserves the constraint because
//! `(alpha A w)(beta B w) - alpha beta C w = alpha beta (Aw Bw - Cw)`.
//! No witness or witness-builder changes are required. Run after GE and before
//! constructing any scheme/preprocessing data from the R1CS.

use {
    ark_ff::Field,
    provekit_common::R1CS,
    std::collections::{HashMap, HashSet},
    tracing::info,
};

/// Bound candidate generation independently of the size of a row.
const MAX_PIVOTS: usize = 3;
const MAX_SWEEPS: usize = 8;

#[derive(Debug, Default)]
pub struct RowScalingStats {
    pub triplets_before: usize,
    pub triplets_after:  usize,
    pub rows_scaled:     usize,
    pub sweeps:          usize,
}

#[derive(Clone)]
struct Term<F: Field> {
    value:       [F; 3],
    /// Number of occupied coordinates with this triplet across the group.
    occurrences: usize,
}

struct Group<F: Field> {
    /// Distinct triplets, shared by every row in the group.
    terms:  Vec<Term<F>>,
    /// Cumulative multipliers for A, B and C.
    scales: [F; 3],
}

/// Greedily reduce the global number of distinct nonzero `(a, b, c)` triplets.
///
/// Rows with the same triplet palette are scaled together. A bounded candidate
/// search normalizes frequent A/B, A/C or B/C coefficients to +/-1. Accepted
/// moves strictly improve `(distinct triplets, non-ternary matrix entries)`;
/// this is a heuristic, not a minimum guarantee. Equal scores retain the
/// current representation. Search stops at a fixed point or after eight sweeps.
///
/// With N occupied coordinates, P distinct row palettes, and K <= 160 scale
/// candidates per palette, each sweep takes expected O(K N) field/hash
/// operations, plus cached field inversions. Initial grouping additionally
/// sorts each row's triplet IDs. Storage is O(N + P + number of rows).
///
/// Only matrix coefficients change. Dimensions, sparsity, witness indices,
/// public inputs and virtual witnesses are preserved.
pub fn minimize_coefficient_triplets<F: Field>(r1cs: &mut R1CS<F>) -> RowScalingStats {
    let (mut groups, row_groups) = collect_groups(r1cs);
    // Count groups containing each triplet, not entries: removing an entire
    // repeated-row group can then release a triplet in a single move.
    let mut counts = HashMap::<[F; 3], usize>::new();
    for group in &groups {
        for term in &group.terms {
            *counts.entry(term.value).or_default() += 1;
        }
    }
    let mut stats = RowScalingStats {
        triplets_before: counts.len(),
        ..RowScalingStats::default()
    };
    let mut inverses = HashMap::from([(F::ONE, F::ONE), (-F::ONE, -F::ONE)]);

    for sweep in 1..=MAX_SWEEPS {
        let mut accepted = 0;
        for group in &mut groups {
            accepted += usize::from(optimize_group(group, &mut counts, &mut inverses));
        }
        stats.sweeps = sweep;
        info!(
            "R1CS row scaling sweep {sweep}: {} unique triplets, {accepted} palette updates",
            counts.len()
        );
        if accepted == 0 {
            break;
        }
    }
    stats.triplets_after = counts.len();
    assert!(stats.triplets_after <= stats.triplets_before);

    // Apply only the final composed scales; rejected candidates never enter
    // the R1CS interner and no intermediate R1CS copies are needed.
    let mut entries = Vec::new();
    for (row, &group) in row_groups.iter().enumerate() {
        let scales = groups[group].scales;
        if scales == [F::ONE; 3] {
            continue;
        }
        stats.rows_scaled += 1;
        for (matrix, scale) in [&mut r1cs.a, &mut r1cs.b, &mut r1cs.c]
            .into_iter()
            .zip(scales)
        {
            if scale == F::ONE {
                continue;
            }
            entries.clear();
            entries.extend(matrix.iter_row(row).map(|(column, coefficient)| {
                let value = r1cs
                    .interner
                    .get(coefficient)
                    .expect("interned coefficient");
                (column, r1cs.interner.intern(value * scale))
            }));
            matrix.replace_row(row, &entries);
        }
    }
    info!(
        "R1CS row scaling: {} -> {} unique triplets, {} of {} rows scaled",
        stats.triplets_before,
        stats.triplets_after,
        stats.rows_scaled,
        r1cs.num_constraints()
    );
    stats
}

/// Merge the sorted A/B/C rows, then group by their sets of triplet IDs.
/// Column positions and multiplicities do not affect the primary objective;
/// multiplicities are retained for the exact non-ternary-entry tie-break.
fn collect_groups<F: Field>(r1cs: &R1CS<F>) -> (Vec<Group<F>>, Vec<usize>) {
    let matrices = [r1cs.a(), r1cs.b(), r1cs.c()];
    let mut values = Vec::new();
    let mut triplet_ids = HashMap::new();
    let mut palettes = HashMap::<Vec<usize>, usize>::new();
    let mut groups: Vec<Group<F>> = Vec::new();
    let mut row_groups = Vec::with_capacity(r1cs.num_constraints());
    let mut ids = Vec::new();
    let mut terms = Vec::<(usize, usize)>::new();

    for row in 0..r1cs.num_constraints() {
        ids.clear();
        let mut streams = matrices
            .each_ref()
            .map(|matrix| matrix.iter_row(row).peekable());
        while let Some(column) = streams
            .iter_mut()
            .filter_map(|stream| stream.peek().map(|&(column, _)| column))
            .min()
        {
            let value = streams.each_mut().map(|stream| {
                stream
                    .next_if(|&(index, _)| index == column)
                    .map_or(F::ZERO, |(_, value)| value)
            });
            if value == [F::ZERO; 3] {
                continue;
            }
            let id = *triplet_ids.entry(value).or_insert_with(|| {
                values.push(value);
                values.len() - 1
            });
            ids.push(id);
        }
        ids.sort_unstable();
        terms.clear();
        for &id in &ids {
            if let Some((last_id, count)) = terms.last_mut().filter(|(last, _)| *last == id) {
                debug_assert_eq!(*last_id, id);
                *count += 1;
            } else {
                terms.push((id, 1));
            }
        }
        ids.dedup();
        let group = if let Some(&group) = palettes.get(&ids) {
            for (term, &(_, count)) in groups[group].terms.iter_mut().zip(&terms) {
                term.occurrences += count;
            }
            group
        } else {
            let group = groups.len();
            palettes.insert(ids.clone(), group);
            groups.push(Group {
                terms:  terms
                    .iter()
                    .map(|&(id, occurrences)| Term {
                        value: values[id],
                        occurrences,
                    })
                    .collect(),
                scales: [F::ONE; 3],
            });
            group
        };
        row_groups.push(group);
    }
    (groups, row_groups)
}

fn nonternary<F: Field>(value: [F; 3]) -> usize {
    value
        .into_iter()
        .filter(|&x| x != F::ZERO && x != F::ONE && x != -F::ONE)
        .count()
}

fn scale_triplet<F: Field>(value: [F; 3], scales: [F; 3]) -> [F; 3] {
    std::array::from_fn(|i| value[i] * scales[i])
}

fn optimize_group<F: Field>(
    group: &mut Group<F>,
    counts: &mut HashMap<[F; 3], usize>,
    inverses: &mut HashMap<F, F>,
) -> bool {
    let exclusive = group
        .terms
        .iter()
        .filter(|term| counts[&term.value] == 1)
        .count();
    let nonternary = group
        .terms
        .iter()
        .map(|term| nonternary(term.value) * term.occurrences)
        .sum();
    let mut best_score = (exclusive, nonternary);
    if best_score == (0, 0) {
        return false;
    }

    // Temporarily leave only the other groups in the dictionary.
    for term in &group.terms {
        let count = counts.get_mut(&term.value).expect("counted triplet");
        *count -= 1;
        if *count == 0 {
            counts.remove(&term.value);
        }
    }
    let mut best = [F::ONE; 3];
    for scales in candidates(&group.terms, inverses) {
        if let Some(score) = score_candidate(&group.terms, scales, counts, best_score) {
            best_score = score;
            best = scales;
            if score == (0, 0) {
                break;
            }
        }
    }
    for term in &mut group.terms {
        term.value = scale_triplet(term.value, best);
        *counts.entry(term.value).or_default() += 1;
    }
    group.scales = scale_triplet(group.scales, best);
    best != [F::ONE; 3]
}

/// Scaling by nonzero elements is injective on triplets, so candidates do not
/// need their own deduplication set. Reject as soon as this monotone partial
/// score cannot beat the incumbent.
fn score_candidate<F: Field>(
    terms: &[Term<F>],
    scales: [F; 3],
    others: &HashMap<[F; 3], usize>,
    incumbent: (usize, usize),
) -> Option<(usize, usize)> {
    let mut score = (0, 0);
    for term in terms {
        let value = scale_triplet(term.value, scales);
        score.0 += usize::from(!others.contains_key(&value));
        score.1 += nonternary(value) * term.occurrences;
        if score >= incumbent {
            return None;
        }
    }
    (score < incumbent).then_some(score)
}

fn inverse<F: Field>(value: F, cache: &mut HashMap<F, F>) -> F {
    *cache
        .entry(value)
        .or_insert_with(|| value.inverse().expect("nonzero pivot"))
}

/// Deterministic frequency order, with field order breaking ties.
fn pivots<F: Field>(terms: &[Term<F>], component: usize) -> Vec<F> {
    let mut frequencies = HashMap::<F, usize>::new();
    for term in terms {
        let value = term.value[component];
        if value != F::ZERO {
            *frequencies.entry(value).or_default() += term.occurrences;
        }
    }
    let mut values: Vec<_> = frequencies.into_iter().collect();
    let compare = |(a, ca): &(F, usize), (b, cb): &(F, usize)| cb.cmp(ca).then(a.cmp(b));
    if values.len() > MAX_PIVOTS {
        values.select_nth_unstable_by(MAX_PIVOTS, compare);
        values.truncate(MAX_PIVOTS);
    }
    values.sort_unstable_by(compare);
    values.into_iter().map(|(value, _)| value).collect()
}

fn candidates<F: Field>(terms: &[Term<F>], inverses: &mut HashMap<F, F>) -> Vec<[F; 3]> {
    let mut factors = [vec![F::ONE, -F::ONE], vec![F::ONE, -F::ONE]];
    for (component, factors) in factors.iter_mut().enumerate() {
        for value in pivots(terms, component) {
            let reciprocal = inverse(value, inverses);
            factors.extend([reciprocal, -reciprocal]);
        }
        factors.sort_unstable();
        factors.dedup();
    }
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |alpha, beta| {
        if [alpha, beta] != [F::ONE; 2] && seen.insert([alpha, beta]) {
            result.push([alpha, beta, alpha * beta]);
        }
    };
    // A/B anchors. In particular this includes independent sign flips.
    for &alpha in &factors[0] {
        for &beta in &factors[1] {
            add(alpha, beta);
        }
    }
    // A/C and B/C anchors also handle purely linear C rows.
    for value in pivots(terms, 2) {
        let reciprocal = inverse(value, inverses);
        for gamma in [reciprocal, -reciprocal] {
            for &alpha in &factors[0] {
                add(alpha, gamma * inverse(alpha, inverses));
            }
            for &beta in &factors[1] {
                add(gamma * inverse(beta, inverses), beta);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use {super::*, ark_ff::AdditiveGroup, provekit_backend_bn254::FieldElement as F};

    fn f(value: i64) -> F {
        if value < 0 {
            -F::from(value.unsigned_abs())
        } else {
            F::from(value as u64)
        }
    }

    fn add_row(r1cs: &mut R1CS<F>, entries: &[[i64; 3]]) {
        let components: [Vec<_>; 3] = std::array::from_fn(|component| {
            entries
                .iter()
                .enumerate()
                .filter_map(|(column, entry)| {
                    (entry[component] != 0).then_some((f(entry[component]), column))
                })
                .collect()
        });
        r1cs.add_constraint(&components[0], &components[1], &components[2]);
    }

    fn triplets(r1cs: &R1CS<F>) -> HashSet<[F; 3]> {
        let (groups, _) = collect_groups(r1cs);
        groups
            .into_iter()
            .flat_map(|group| group.terms.into_iter().map(|t| t.value))
            .collect()
    }

    fn matrix_row(r1cs: &R1CS<F>, row: usize, component: usize) -> Vec<(usize, F)> {
        [r1cs.a(), r1cs.b(), r1cs.c()][component]
            .iter_row(row)
            .collect()
    }

    /// Verify the whole row transformation, not just satisfiability on one
    /// witness: A and B scales must multiply to the C scale. Empty factors
    /// leave the corresponding free scaling unconstrained.
    fn assert_equivalent(before: &R1CS<F>, after: &R1CS<F>) {
        assert_eq!(before.num_constraints(), after.num_constraints());
        assert_eq!(before.num_witnesses(), after.num_witnesses());
        assert_eq!(before.num_public_inputs, after.num_public_inputs);
        assert_eq!(before.num_virtual, after.num_virtual);
        for row in 0..before.num_constraints() {
            let mut scales = [None; 3];
            for (component, scale) in scales.iter_mut().enumerate() {
                let a = matrix_row(before, row, component);
                let b = matrix_row(after, row, component);
                assert_eq!(a.len(), b.len());
                for (&(i, x), &(j, y)) in a.iter().zip(&b) {
                    assert_eq!(i, j);
                    assert_ne!(y, F::ZERO);
                    let ratio = y / x;
                    assert_eq!(*scale.get_or_insert(ratio), ratio);
                }
            }
            if let [Some(a), Some(b), Some(c)] = scales {
                assert_eq!(a * b, c);
            }
            // Also check the residual identity for several witnesses,
            // including invalid ones, using a free nonzero factor if needed.
            let residual_scale = scales[2]
                .unwrap_or_else(|| scales[0].unwrap_or(F::ONE) * scales[1].unwrap_or(F::ONE));
            for seed in 0..8 {
                let witness: Vec<_> = (0..before.num_witnesses())
                    .map(|column| F::from((seed * 17 + column * 3) as u64))
                    .collect();
                let residual = |r1cs: &R1CS<F>| {
                    let products: [F; 3] = std::array::from_fn(|component| {
                        matrix_row(r1cs, row, component)
                            .into_iter()
                            .map(|(column, value)| value * witness[column])
                            .sum()
                    });
                    products[0] * products[1] - products[2]
                };
                assert_eq!(residual(after), residual_scale * residual(before));
            }
        }
    }

    #[test]
    fn merges_scaled_rows_and_preserves_the_constraints() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(4);
        r1cs.num_public_inputs = 2;
        r1cs.num_virtual = 3;
        add_row(&mut r1cs, &[[1, 0, 0], [0, 1, 0], [0, 0, 1], [1, 1, 1]]);
        add_row(&mut r1cs, &[[2, 0, 0], [0, 3, 0], [0, 0, 6], [2, 3, 6]]);
        let before = r1cs.clone();
        let stats = minimize_coefficient_triplets(&mut r1cs);
        assert_eq!((stats.triplets_before, stats.triplets_after), (8, 4));
        assert!(stats.rows_scaled > 0);
        assert_eq!(triplets(&r1cs).len(), stats.triplets_after);
        assert_equivalent(&before, &r1cs);
    }

    #[test]
    fn scales_repeated_palettes_together_even_at_different_columns() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3);
        add_row(&mut r1cs, &[[1, 1, 1]]);
        for _ in 0..20 {
            add_row(&mut r1cs, &[[0, 0, 0], [2, 3, 6], [2, 3, 6]]);
        }
        let before = r1cs.clone();
        let (groups, rows) = collect_groups(&r1cs);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[rows[1]].terms[0].occurrences, 40);
        let stats = minimize_coefficient_triplets(&mut r1cs);
        assert_eq!((stats.triplets_before, stats.triplets_after), (2, 1));
        assert_eq!(stats.rows_scaled, 20);
        assert_equivalent(&before, &r1cs);
    }

    #[test]
    fn ternary_tie_break_seeds_a_shared_palette() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3);
        add_row(&mut r1cs, &[[2, 0, 0], [0, 3, 0], [0, 0, 6]]);
        add_row(&mut r1cs, &[[5, 0, 0], [0, 7, 0], [0, 0, 35]]);
        let before = r1cs.clone();
        let stats = minimize_coefficient_triplets(&mut r1cs);
        assert_eq!((stats.triplets_before, stats.triplets_after), (6, 3));
        assert!(triplets(&r1cs).into_iter().all(|t| nonternary(t) == 0));
        assert_equivalent(&before, &r1cs);
    }

    #[test]
    fn preserves_the_c_over_ab_invariant() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(1);
        add_row(&mut r1cs, &[[1, 1, 1]]);
        add_row(&mut r1cs, &[[2, 3, 12]]);
        let before = r1cs.clone();
        let stats = minimize_coefficient_triplets(&mut r1cs);
        assert_eq!(stats.triplets_after, 2);
        assert_equivalent(&before, &r1cs);
    }

    #[test]
    fn handles_empty_and_linear_rows() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(2);
        add_row(&mut r1cs, &[]);
        add_row(&mut r1cs, &[[0, 0, 1]]);
        add_row(&mut r1cs, &[[0, 0, -9], [0, 0, -9]]);
        add_row(&mut r1cs, &[[7, 0, 0], [0, 0, 14]]);
        add_row(&mut r1cs, &[[0, 5, 0], [0, 0, 15]]);
        let before = r1cs.clone();
        let stats = minimize_coefficient_triplets(&mut r1cs);
        assert!(stats.triplets_after < stats.triplets_before);
        assert_equivalent(&before, &r1cs);
        let mut empty = R1CS::<F>::new();
        let stats = minimize_coefficient_triplets(&mut empty);
        assert_eq!(stats.triplets_after, 0);
        assert_eq!(stats.rows_scaled, 0);
    }

    #[test]
    fn rejected_candidates_do_not_pollute_the_interner() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(3);
        // All 26 nonzero ternary triples in one row: any non-sign scale
        // worsens the secondary objective, and sign flips only tie.
        let mut entries = Vec::new();
        for a in -1..=1 {
            for b in -1..=1 {
                for c in -1..=1 {
                    if [a, b, c] != [0; 3] {
                        entries.push([a, b, c]);
                    }
                }
            }
        }
        r1cs.grow_matrices(0, entries.len());
        add_row(&mut r1cs, &entries);
        let before = r1cs.clone();
        let stats = minimize_coefficient_triplets(&mut r1cs);
        assert_eq!(stats.rows_scaled, 0);
        assert_eq!(before, r1cs);
    }

    #[test]
    fn candidate_scoring_matches_materialized_union() {
        let terms = vec![
            Term {
                value:       [f(2), f(0), f(0)],
                occurrences: 10,
            },
            Term {
                value:       [f(0), f(3), f(0)],
                occurrences: 2,
            },
            Term {
                value:       [f(2), f(3), f(6)],
                occurrences: 4,
            },
        ];
        let others = HashMap::from([
            ([F::ONE, F::ZERO, F::ZERO], 2),
            ([F::ZERO, F::ONE, F::ZERO], 1),
            ([f(2), f(3), f(6)], 3),
        ]);
        let mut inverses = HashMap::new();
        let choices = candidates(&terms, &mut inverses);
        assert!(choices.len() <= 160);
        assert_eq!(
            choices.iter().copied().collect::<HashSet<_>>().len(),
            choices.len()
        );
        for scales in choices {
            assert_ne!(scales[0], F::ZERO);
            assert_ne!(scales[1], F::ZERO);
            assert_eq!(scales[2], scales[0] * scales[1]);
            let mut union: HashSet<_> = others.keys().copied().collect();
            let mut complexity = 0;
            for term in &terms {
                let value = scale_triplet(term.value, scales);
                union.insert(value);
                complexity += nonternary(value) * term.occurrences;
            }
            let expected = (union.len() - others.len(), complexity);
            for missing in 0..=4 {
                for cost in [0, 1, 2, 10, 50] {
                    let incumbent = (missing, cost);
                    assert_eq!(
                        score_candidate(&terms, scales, &others, incumbent),
                        (expected < incumbent).then_some(expected)
                    );
                }
            }
        }
    }

    #[test]
    fn candidates_cover_c_normalization_and_stay_bounded() {
        let terms: Vec<_> = (1..=30)
            .map(|x| Term {
                value:       [f(x), f(x + 30), f(x + 60)],
                occurrences: x as usize,
            })
            .collect();
        let mut cache = HashMap::new();
        let choices = candidates(&terms, &mut cache);
        assert!(choices.len() <= 160);
        assert!(choices
            .iter()
            .any(|&[a, b, c]| { a * f(30) == F::ONE && c * f(90) == F::ONE && b == c / a }));
    }

    #[test]
    fn random_systems_preserve_residuals_support_and_serialization() {
        let mut seed = 123456789_u64;
        for _ in 0..32 {
            let mut r1cs = R1CS::new();
            r1cs.add_witnesses(7);
            for _ in 0..12 {
                let entries: Vec<_> = (0..7)
                    .map(|_| {
                        std::array::from_fn(|_| {
                            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                            ((seed >> 32) % 9) as i64 - 4
                        })
                    })
                    .collect();
                add_row(&mut r1cs, &entries);
            }
            let before = r1cs.clone();
            let mut repeat = before.clone();
            let stats = minimize_coefficient_triplets(&mut r1cs);
            minimize_coefficient_triplets(&mut repeat);
            assert_eq!(r1cs, repeat, "hash iteration must not affect output");
            assert_eq!(triplets(&r1cs).len(), stats.triplets_after);
            assert!(stats.triplets_after <= stats.triplets_before);
            assert_equivalent(&before, &r1cs);
            let bytes = postcard::to_stdvec(&r1cs).unwrap();
            let restored: R1CS<F> = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(restored, r1cs);
        }
    }
}
