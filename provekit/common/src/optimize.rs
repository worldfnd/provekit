//! Gaussian elimination optimization pass for R1CS.
//!
//! Inspired by Circom's `-O2` substitution-based sparse elimination:
//!   1. Identify linear constraints (where A or B is constant)
//!   2. For each linear constraint, pick a pivot variable (fewest occurrences,
//!      not forbidden)
//!   3. Express pivot as linear combination of remaining variables
//!   4. Substitute into all other constraints
//!   5. Remove eliminated constraints
//!   6. Remove dead witness columns and prune unreachable witness builders

use {
    crate::{
        witness::{DependencyInfo, SumTerm, WitnessBuilder},
        FieldElement, InternedFieldElement, SparseMatrix, R1CS,
    },
    ark_ff::Field,
    ark_std::{One, Zero},
    std::collections::{HashMap, HashSet, VecDeque},
    tracing::info,
};

/// A substitution: pivot_col = sum of (coeff * col) for each entry.
/// The pivot column does NOT appear in the terms.
struct Substitution {
    pivot_col: usize,
    /// (coefficient, column_index) — the pivot equals the negation of the
    /// linear expression, so these coefficients already account for the sign
    /// flip and division by the pivot coefficient.
    terms:     Vec<(FieldElement, usize)>,
}

/// Statistics from the optimization pass.
pub struct OptimizationStats {
    pub constraints_before:      usize,
    pub constraints_after:       usize,
    pub witnesses_before:        usize,
    pub witnesses_after:         usize,
    pub eliminated:              usize,
    pub builders_removed:        usize,
    pub builders_rewritten:      usize,
    pub new_sum_builders:        usize,
    /// Zero-occurrence columns in A/B/C matrices (excl. col 0 and public
    /// inputs).
    pub zero_occurrence_cols:    usize,
    /// Zero-occurrence cols pinned by the ACIR witness map.
    pub blocked_by_acir:         usize,
    /// Zero-occurrence cols whose producing builder is still transitively live.
    pub blocked_by_live_builder: usize,
    /// Columns actually removed after all blocking checks.
    pub columns_removed:         usize,
}

impl OptimizationStats {
    pub fn constraint_reduction_percent(&self) -> f64 {
        if self.constraints_before == 0 {
            return 0.0;
        }
        (self.constraints_before - self.constraints_after) as f64 / self.constraints_before as f64
            * 100.0
    }

    pub fn witness_reduction_percent(&self) -> f64 {
        if self.witnesses_before == 0 {
            return 0.0;
        }
        (self.witnesses_before - self.witnesses_after) as f64 / self.witnesses_before as f64 * 100.0
    }
}

/// Run the Gaussian elimination optimization on an R1CS instance.
///
/// Identifies linear constraints (where at least one of A or B is constant),
/// picks pivots, substitutes into remaining constraints, and removes the
/// eliminated rows.
///
/// `num_public_inputs` columns (1..=num_public_inputs) and column 0 (constant
/// one) are never chosen as pivots.
pub fn optimize_r1cs(
    r1cs: &mut R1CS,
    witness_builders: &mut Vec<WitnessBuilder>,
    witness_map: &mut [Option<std::num::NonZeroU32>],
) -> OptimizationStats {
    let constraints_before = r1cs.num_constraints();
    let witnesses_before = r1cs.num_witnesses();

    // Columns that must not be eliminated:
    // - Column 0: constant one
    // - Columns 1..=num_public_inputs: public inputs
    let mut forbidden: HashSet<usize> = HashSet::new();
    forbidden.insert(0);
    for i in 1..=r1cs.num_public_inputs {
        forbidden.insert(i);
    }

    // Phase 1: Identify all linear constraints
    let mut linear_rows: Vec<usize> = Vec::new();
    for row in 0..r1cs.num_constraints() {
        if r1cs.is_linear_constraint(row) {
            linear_rows.push(row);
        }
    }

    info!(
        "Gaussian elimination: found {} linear constraints out of {}",
        linear_rows.len(),
        constraints_before
    );

    // Phase 2: For each linear constraint, try to find a pivot and build a
    // substitution
    let mut substitutions: Vec<Substitution> = Vec::new();
    let mut eliminated_rows: Vec<usize> = Vec::new();
    let mut eliminated_cols: HashSet<usize> = HashSet::new();

    // Build occurrence counts across all three matrices for pivot selection
    // heuristic
    let mut occurrence_counts = build_occurrence_counts(r1cs);

    // Also track pivot_col -> substitution index for chain resolution
    let mut sub_map_phase2: HashMap<usize, usize> = HashMap::new();

    for &row in &linear_rows {
        // Extract the linear expression from C[row]: sum of (coeff * w_i) = 0
        let expr = r1cs.extract_linear_expression(row);
        if expr.is_empty() {
            continue;
        }

        // Pick pivot: non-forbidden, non-already-eliminated, fewest occurrences
        let pivot = expr
            .iter()
            .filter(|(_, col)| !forbidden.contains(col) && !eliminated_cols.contains(col))
            .min_by_key(|(_, col)| occurrence_counts[*col]);

        let (pivot_coeff, pivot_col) = match pivot {
            Some(&(coeff, col)) => (coeff, col),
            None => continue, // All columns forbidden or already eliminated
        };

        // pivot_coeff * w_pivot + sum(other_coeff_i * w_i) = 0
        // => w_pivot = -sum(other_coeff_i / pivot_coeff * w_i)
        let pivot_inv = pivot_coeff.inverse().expect("pivot coefficient is zero");

        let raw_terms: Vec<(FieldElement, usize)> = expr
            .iter()
            .filter(|(_, col)| *col != pivot_col)
            .map(|(coeff, col)| {
                let new_coeff = -(*coeff) * pivot_inv;
                (new_coeff, *col)
            })
            .collect();

        // Resolve forward chains: if any term references a previously
        // eliminated pivot, inline that pivot's substitution.
        let mut resolved: HashMap<usize, FieldElement> = HashMap::new();
        for (coeff, col) in &raw_terms {
            if let Some(&prev_idx) = sub_map_phase2.get(col) {
                // This column is a previously eliminated pivot — inline it
                for (prev_coeff, prev_col) in &substitutions[prev_idx].terms {
                    *resolved.entry(*prev_col).or_insert_with(FieldElement::zero) +=
                        *coeff * prev_coeff;
                }
            } else {
                *resolved.entry(*col).or_insert_with(FieldElement::zero) += *coeff;
            }
        }

        // Handle self-reference: chain resolution may reintroduce the
        // current pivot (happens when a previous substitution's terms
        // contain it). Algebraically:
        //   w_p = r_p * w_p + other  =>  (1 - r_p) * w_p = other
        // If 1 - r_p != 0, rescale. Otherwise this constraint doesn't
        // actually depend on the pivot — skip.
        if let Some(self_coeff) = resolved.remove(&pivot_col) {
            if !self_coeff.is_zero() {
                let denom = FieldElement::one() - self_coeff;
                match denom.inverse() {
                    Some(scale) => {
                        for v in resolved.values_mut() {
                            *v *= scale;
                        }
                    }
                    None => continue, // degenerate — skip this elimination
                }
            }
        }

        let terms: Vec<(FieldElement, usize)> = resolved
            .into_iter()
            .filter(|(_, v)| !v.is_zero())
            .map(|(col, val)| (val, col))
            .collect();

        // Decrement occurrence counts for all columns in this row (they're being
        // removed)
        for (_, col) in &expr {
            if occurrence_counts[*col] > 0 {
                occurrence_counts[*col] -= 1;
            }
        }

        let sub_idx = substitutions.len();
        substitutions.push(Substitution { pivot_col, terms });
        sub_map_phase2.insert(pivot_col, sub_idx);
        eliminated_rows.push(row);
        eliminated_cols.insert(pivot_col);
    }

    info!(
        "Gaussian elimination: {} substitutions found",
        substitutions.len()
    );

    if substitutions.is_empty() {
        return OptimizationStats {
            constraints_before,
            constraints_after: constraints_before,
            witnesses_before,
            witnesses_after: witnesses_before,
            eliminated: 0,
            builders_removed: 0,
            builders_rewritten: 0,
            new_sum_builders: 0,
            zero_occurrence_cols: 0,
            blocked_by_acir: 0,
            blocked_by_live_builder: 0,
            columns_removed: 0,
        };
    }

    // Phase 2b: Resolve backward chains.
    // Forward chain resolution in Phase 2 ensured each substitution's terms
    // don't reference *earlier* pivots. But they may still reference *later*
    // pivots (built after them). Process substitutions in reverse order so
    // each substitution's terms are fully resolved when inlined by earlier ones.
    for i in (0..substitutions.len()).rev() {
        let needs_resolution = substitutions[i]
            .terms
            .iter()
            .any(|(_, col)| sub_map_phase2.contains_key(col) && *col != substitutions[i].pivot_col);

        if !needs_resolution {
            continue;
        }

        let mut resolved: HashMap<usize, FieldElement> = HashMap::new();
        for (coeff, col) in &substitutions[i].terms {
            if let Some(&later_idx) = sub_map_phase2.get(col) {
                if later_idx != i {
                    for (sub_coeff, sub_col) in &substitutions[later_idx].terms {
                        *resolved.entry(*sub_col).or_insert_with(FieldElement::zero) +=
                            *coeff * sub_coeff;
                    }
                    continue;
                }
            }
            *resolved.entry(*col).or_insert_with(FieldElement::zero) += *coeff;
        }

        substitutions[i].terms = resolved
            .into_iter()
            .filter(|(_, v)| !v.is_zero())
            .map(|(col, val)| (val, col))
            .collect();
    }

    // Phase 3: Apply substitutions to all remaining (non-eliminated) constraints
    let eliminated_row_set: HashSet<usize> = eliminated_rows.iter().copied().collect();

    // Build a lookup: pivot_col -> substitution index
    let mut sub_map: HashMap<usize, usize> = HashMap::new();
    for (idx, sub) in substitutions.iter().enumerate() {
        sub_map.insert(sub.pivot_col, idx);
    }

    for row in 0..r1cs.num_constraints() {
        if eliminated_row_set.contains(&row) {
            continue;
        }
        apply_substitutions_to_row(
            &mut r1cs.a,
            row,
            &substitutions,
            &sub_map,
            &mut r1cs.interner,
        );
        apply_substitutions_to_row(
            &mut r1cs.b,
            row,
            &substitutions,
            &sub_map,
            &mut r1cs.interner,
        );
        apply_substitutions_to_row(
            &mut r1cs.c,
            row,
            &substitutions,
            &sub_map,
            &mut r1cs.interner,
        );
    }

    // Phase 4: Remove eliminated constraint rows
    let mut sorted_rows = eliminated_rows.clone();
    sorted_rows.sort();
    r1cs.remove_constraints(&sorted_rows);

    let constraints_after = r1cs.num_constraints();
    let eliminated = substitutions.len();

    // Phase 4b: Rewrite Sum/SpreadBitExtract builders to inline GE substitutions,
    // severing the dependency chains that prevent dead-column removal.
    //
    // Cycle detection must run first (on the unmodified dependency graph) to
    // identify builders that cannot be safely rewritten.  Counts are collected
    // before the rewrite so the log reflects the original state.
    let blocked_builders = compute_rewrite_blocked(witness_builders, &substitutions);

    let pivot_cols: HashSet<usize> = substitutions.iter().map(|s| s.pivot_col).collect();
    let mut total_candidates = 0usize;
    let mut blocked_candidates = 0usize;
    for (idx, builder) in witness_builders.iter().enumerate() {
        let reads_pivot = match builder {
            WitnessBuilder::Sum(_, terms) => {
                terms.iter().any(|SumTerm(_, col)| pivot_cols.contains(col))
            }
            WitnessBuilder::SpreadBitExtract { sum_terms, .. } => sum_terms
                .iter()
                .any(|SumTerm(_, col)| pivot_cols.contains(col)),
            _ => false,
        };
        if reads_pivot {
            total_candidates += 1;
            if blocked_builders.contains(&idx) {
                blocked_candidates += 1;
            }
        }
    }

    let builders_rewritten =
        rewrite_builders_for_substitutions(witness_builders, &substitutions, &blocked_builders);

    info!(
        "Builder rewrite: {}/{} candidates rewritten, {} blocked by cycle detection",
        builders_rewritten, total_candidates, blocked_candidates,
    );

    // Phase 4c: Restore a valid topological execution order.
    //
    // Phase 4b may have changed dependencies: builder X now reads w50/w60
    // instead of pivot P.  If producer(w50) sits later in the Vec than X,
    // the old order is no longer valid.  Re-sort so every builder comes after
    // all the builders whose outputs it reads.  This is required by
    // WitnessSplitter and provides a consistent starting point for
    // LayerScheduler.
    if builders_rewritten > 0 {
        topological_reorder(witness_builders);
    }

    // Phase 5: Remove dead witness columns and prune unreachable builders
    let col_stats = remove_dead_columns(r1cs, witness_builders, witness_map);

    let stats = OptimizationStats {
        constraints_before,
        constraints_after,
        witnesses_before,
        witnesses_after: col_stats.witnesses_after,
        eliminated,
        builders_removed: col_stats.builders_removed,
        builders_rewritten,
        new_sum_builders: 0,
        zero_occurrence_cols: col_stats.zero_occurrence_cols,
        blocked_by_acir: col_stats.blocked_by_acir,
        blocked_by_live_builder: col_stats.blocked_by_live_builder,
        columns_removed: col_stats.columns_removed,
    };

    info!(
        "Gaussian elimination: {} -> {} constraints ({:.1}% reduction), {} substitutions",
        constraints_before,
        constraints_after,
        stats.constraint_reduction_percent(),
        eliminated
    );
    info!(
        "Column removal: {} -> {} witnesses ({:.1}% reduction), {} builders pruned",
        witnesses_before,
        stats.witnesses_after,
        stats.witness_reduction_percent(),
        stats.builders_removed
    );

    stats
}

/// Expands every `SumTerm` that references a pivot column by substituting the
/// GE-derived linear expression for that pivot inline.
///
/// For a term `coeff_b * P` where `P = Σ (c_i * col_i)`:
///   - Produces `Σ (coeff_b * c_i) * col_i` (one new term per substitution
///     entry)
///   - `coeff_b = None` is treated as the multiplicative identity (1)
///   - If the substitution for P has no terms (P = 0), the term drops out
///     entirely
///
/// Terms that do not reference any pivot column pass through unchanged.
fn inline_sum_terms(
    terms: &[SumTerm],
    pivot_to_terms: &HashMap<usize, &Vec<(FieldElement, usize)>>,
) -> Vec<SumTerm> {
    let mut out: Vec<SumTerm> = Vec::with_capacity(terms.len());
    for SumTerm(coeff, col) in terms {
        match pivot_to_terms.get(col) {
            None => {
                // Not a pivot — copy through unchanged.
                out.push(SumTerm(*coeff, *col));
            }
            Some(sub_terms) => {
                // Inline: replace this single term with the full expansion.
                // If sub_terms is empty the pivot equals zero; the term drops out.
                let b: FieldElement = coeff.unwrap_or_else(|| One::one());
                for (c_i, col_i) in sub_terms.iter() {
                    out.push(SumTerm(Some(b * *c_i), *col_i));
                }
            }
        }
    }
    out
}

/// Rewrites every non-blocked `Sum` and `SpreadBitExtract` builder by inlining
/// GE substitutions for any pivot column they reference.
///
/// Builders in `blocked_builders` are skipped (cycle detection determined that
/// inlining would create a dependency cycle in the witness execution graph).
/// All other builder variants are left untouched — non-linear builders cannot
/// be algebraically inlined regardless.
///
/// Returns the number of builders that were actually modified.
fn rewrite_builders_for_substitutions(
    witness_builders: &mut Vec<WitnessBuilder>,
    substitutions: &[Substitution],
    blocked_builders: &HashSet<usize>,
) -> usize {
    if substitutions.is_empty() {
        return 0;
    }

    let pivot_to_terms: HashMap<usize, &Vec<(FieldElement, usize)>> = substitutions
        .iter()
        .map(|s| (s.pivot_col, &s.terms))
        .collect();

    let mut rewritten = 0usize;

    for builder_idx in 0..witness_builders.len() {
        if blocked_builders.contains(&builder_idx) {
            continue;
        }

        // Peek at the builder to decide if any rewrite is needed, then clone
        // only when we will actually modify it (avoids cloning the majority of
        // builders that read no pivot columns at all).
        let needs_rewrite = match &witness_builders[builder_idx] {
            WitnessBuilder::Sum(_, terms) => terms
                .iter()
                .any(|SumTerm(_, col)| pivot_to_terms.contains_key(col)),
            WitnessBuilder::SpreadBitExtract { sum_terms, .. } => sum_terms
                .iter()
                .any(|SumTerm(_, col)| pivot_to_terms.contains_key(col)),
            _ => false,
        };
        if !needs_rewrite {
            continue;
        }

        // Clone to release the immutable borrow before the mutable assignment.
        let old = witness_builders[builder_idx].clone();
        witness_builders[builder_idx] = match old {
            WitnessBuilder::Sum(idx, terms) => {
                WitnessBuilder::Sum(idx, inline_sum_terms(&terms, &pivot_to_terms))
            }
            WitnessBuilder::SpreadBitExtract {
                output_start,
                chunk_bits,
                sum_terms,
                extract_even,
            } => WitnessBuilder::SpreadBitExtract {
                output_start,
                chunk_bits,
                sum_terms: inline_sum_terms(&sum_terms, &pivot_to_terms),
                extract_even,
            },
            // needs_rewrite above only returns true for Sum / SpreadBitExtract.
            _ => unreachable!(),
        };
        rewritten += 1;
    }

    rewritten
}

/// BFS from `start` following forward (producer→consumer) edges in
/// `adjacency_list`.
///
/// Returns all builder indices transitively reachable from `start`, i.e. all
/// builders that directly or indirectly depend on `start`'s outputs.
/// `start` itself is NOT included.
///
/// Note: `adjacency_list` may contain duplicate consumer entries when a single
/// producer feeds multiple witnesses to the same consumer.  The `visited` set
/// ensures each node is enqueued at most once.
fn forward_reachable(adjacency_list: &[Vec<usize>], start: usize) -> HashSet<usize> {
    let mut visited: HashSet<usize> = HashSet::new();
    // Seed the stack with start's direct consumers; start itself is excluded.
    let mut stack: Vec<usize> = adjacency_list[start].clone();
    while let Some(node) = stack.pop() {
        if visited.insert(node) {
            stack.extend_from_slice(&adjacency_list[node]);
        }
    }
    visited
}

/// Returns the set of builder indices that **cannot** be safely rewritten by
/// inlining GE substitution terms into their `SumTerm` reads.
///
/// # Safety condition
///
/// When we inline a substitution `P = c₁·w₅₀ + c₂·w₆₀` into builder B (which
/// currently reads P), we are adding new dependency edges "B reads w₅₀" and
/// "B reads w₆₀".  In the must-come-before graph that means:
///
///   producer(w₅₀) must run before B
///   producer(w₆₀) must run before B
///
/// If producer(w₅₀) — call it Y — is already a *transitive consumer* of B
/// (i.e. B →…→ Y exists in the current forward graph), then adding
/// "Y must come before B" closes a cycle.  We detect this by checking whether
/// Y is reachable from B following forward (producer→consumer) edges.
///
/// # What gets checked
///
/// Only `Sum` and `SpreadBitExtract` builders are ever candidates for
/// algebraic inlining; all other variants are skipped.  A candidate is
/// blocked if **any** pivot column it reads has **any** substitution term
/// whose producer is forward-reachable from the candidate.
///
/// # Complexity
///
/// O(C × (B + E)) where C is the number of candidate builders (Sum /
/// SpreadBitExtract that read at least one pivot), B is the total number of
/// builders, and E is the total number of dependency edges.  In practice C
/// is a small fraction of B, so this is fast.
fn compute_rewrite_blocked(
    witness_builders: &[WitnessBuilder],
    substitutions: &[Substitution],
) -> HashSet<usize> {
    if substitutions.is_empty() {
        return HashSet::new();
    }

    // pivot_col → substitution terms (already fully resolved by Phase 2b)
    let pivot_to_terms: HashMap<usize, &Vec<(FieldElement, usize)>> = substitutions
        .iter()
        .map(|s| (s.pivot_col, &s.terms))
        .collect();

    let dep_info = DependencyInfo::new(witness_builders);

    let mut blocked: HashSet<usize> = HashSet::new();

    for (builder_idx, builder) in witness_builders.iter().enumerate() {
        // Collect pivot columns this builder reads via SumTerms.
        // Non-linear builders (Product, Inverse, DigitalDecomposition, …)
        // cannot be algebraically inlined so they are always skipped.
        let pivot_cols_read: Vec<usize> = match builder {
            WitnessBuilder::Sum(_, terms) => terms
                .iter()
                .filter_map(|SumTerm(_, col)| pivot_to_terms.contains_key(col).then_some(*col))
                .collect(),
            WitnessBuilder::SpreadBitExtract { sum_terms, .. } => sum_terms
                .iter()
                .filter_map(|SumTerm(_, col)| pivot_to_terms.contains_key(col).then_some(*col))
                .collect(),
            // Every other variant reads pivots through non-linear operations;
            // inlining is not possible for them regardless.
            _ => continue,
        };

        if pivot_cols_read.is_empty() {
            continue;
        }

        // All builders that transitively consume B's outputs.
        // If any substitution-term producer Y is in this set, adding the edge
        // "B reads from Y" would create a cycle (B →…→ Y →…→ B).
        let forward_consumers = forward_reachable(&dep_info.adjacency_list, builder_idx);

        // Check every pivot this builder reads and every term of each pivot.
        // A single unsafe term is enough to block the whole builder because
        // rewriting is all-or-nothing per builder: we cannot partially inline
        // one pivot and leave another.
        'check_pivots: for pivot_col in pivot_cols_read {
            for (_, term_col) in pivot_to_terms[&pivot_col] {
                // term_col may be a constant / public input column with no
                // producer — those are always safe.
                if let Some(&producer) = dep_info.witness_producer.get(term_col) {
                    if forward_consumers.contains(&producer) {
                        // B →…→ producer exists; inlining closes a cycle.
                        blocked.insert(builder_idx);
                        break 'check_pivots;
                    }
                }
            }
        }
    }

    blocked
}

/// Reorders `witness_builders` into a valid topological execution order.
///
/// After Phase 4b rewrites, builder X may now read w50/w60 instead of pivot P.
/// This changes X's dependencies: X must now run after producer(w50) and
/// producer(w60). If producer(w50) currently sits later in the Vec than X, the
/// old ordering is no longer valid.
///
/// A correct topological order is required by:
/// - `WitnessSplitter` — its backward/forward reachability walks use
///   `DependencyInfo` built from the builders, but the final split index lists
///   it returns are resolved into sub-Vecs by position.  An out-of-order Vec
///   can cause a w1 builder to be extracted before its dependency.
/// - `remove_dead_columns` — it walks `builder_reads_from` which is
///   position-indexed; a consistent ordering avoids double-counting.
/// - The prover (via `LayerScheduler`) — correctly reorders on its own, but
///   starting from a valid topological order speeds up scheduling.
///
/// Uses Kahn's BFS algorithm on the dependency graph built by
/// `DependencyInfo::new`.  If the graph has a cycle (should not happen for a
/// correctly constructed circuit), unreachable builders are appended at the
/// end unchanged.
fn topological_reorder(witness_builders: &mut Vec<WitnessBuilder>) {
    let n = witness_builders.len();
    if n == 0 {
        return;
    }

    let dep_info = DependencyInfo::new(witness_builders);

    // Kahn's algorithm: start with all nodes that have no remaining dependencies.
    // `DependencyInfo::in_degrees` may contain duplicate-inflated counts (one
    // increment per read-witness, not per unique producer).  This is consistent
    // with `adjacency_list` which also has the same duplicates, so the algorithm
    // remains correct: each duplicate edge decrements the count exactly once
    // when its producer is processed.
    let mut in_degrees = dep_info.in_degrees.clone();
    let mut queue: VecDeque<usize> = (0..n).filter(|&i| in_degrees[i] == 0).collect();
    let mut order: Vec<usize> = Vec::with_capacity(n);

    while let Some(node) = queue.pop_front() {
        order.push(node);
        for &consumer in &dep_info.adjacency_list[node] {
            // saturating_sub prevents underflow if duplicate edges were
            // already fully consumed by an earlier iteration.
            in_degrees[consumer] = in_degrees[consumer].saturating_sub(1);
            if in_degrees[consumer] == 0 {
                queue.push_back(consumer);
            }
        }
    }

    // Fallback: append any nodes that Kahn's did not reach (genuine cycle or
    // isolated node not reachable from in-degree-0 roots).
    if order.len() != n {
        let reached: HashSet<usize> = order.iter().copied().collect();
        for i in 0..n {
            if !reached.contains(&i) {
                order.push(i);
            }
        }
    }

    // Apply the permutation using mem::swap to avoid cloning every builder.
    // Build a mapping: new_position → old_index, then pull builders out by
    // consuming the Vec into an indexed Option<> array and re-filling in order.
    let mut indexed: Vec<Option<WitnessBuilder>> = witness_builders.drain(..).map(Some).collect();
    witness_builders.reserve(n);
    for old_idx in order {
        witness_builders.push(indexed[old_idx].take().expect("each builder visited once"));
    }
}

/// Build combined occurrence counts across A, B, C matrices.
fn build_occurrence_counts(r1cs: &R1CS) -> Vec<usize> {
    let num_cols = r1cs.num_witnesses();
    let mut counts = vec![0usize; num_cols];
    let a_counts = r1cs.a.column_occurrence_count();
    let b_counts = r1cs.b.column_occurrence_count();
    let c_counts = r1cs.c.column_occurrence_count();
    for i in 0..num_cols {
        counts[i] = a_counts[i] + b_counts[i] + c_counts[i];
    }
    counts
}

/// Counts collected during dead-column removal, returned alongside the updated
/// witness count so callers can surface them in diagnostics.
struct ColumnRemovalStats {
    witnesses_after:         usize,
    builders_removed:        usize,
    /// Zero-occurrence columns in A/B/C matrices (excluding col 0 and public
    /// inputs).
    zero_occurrence_cols:    usize,
    /// Zero-occurrence cols pinned by the ACIR witness map and therefore kept.
    blocked_by_acir:         usize,
    /// Zero-occurrence cols whose producing builder is transitively live
    /// (some other live builder still reads one of its other outputs).
    blocked_by_live_builder: usize,
    /// Columns actually removed (zero-occurrence, not pinned, producer dead).
    columns_removed:         usize,
}

/// Phase 5: Remove dead witness columns from matrices and prune unreachable
/// witness builders.
///
/// After GE, some columns have zero occurrences across all remaining
/// constraints in A, B, and C. These are "dead" columns. This function:
///
/// 1. Identifies dead columns (zero occurrences in all three matrices)
/// 2. Builds a dependency graph of witness builders
/// 3. Finds which builders are transitively reachable from "live" columns
///    (columns still referenced by constraints)
/// 4. Prunes unreachable builders (Phase B+C cascading)
/// 5. Remaps matrix column indices to close gaps
/// 6. Remaps remaining builder witness indices
fn remove_dead_columns(
    r1cs: &mut R1CS,
    witness_builders: &mut Vec<WitnessBuilder>,
    witness_map: &mut [Option<std::num::NonZeroU32>],
) -> ColumnRemovalStats {
    let num_cols = r1cs.num_witnesses();
    if num_cols == 0 || witness_builders.is_empty() {
        return ColumnRemovalStats {
            witnesses_after:         num_cols,
            builders_removed:        0,
            zero_occurrence_cols:    0,
            blocked_by_acir:         0,
            blocked_by_live_builder: 0,
            columns_removed:         0,
        };
    }

    // Step 1: Find dead columns (zero occurrence across A, B, C)
    // Also collect columns referenced by the ACIR witness map — these are
    // entry points for witness data and must stay alive.
    let occurrence_counts = build_occurrence_counts(r1cs);
    let mut acir_referenced: HashSet<usize> = HashSet::new();
    for entry in witness_map.iter() {
        if let Some(nz) = entry {
            acir_referenced.insert(nz.get() as usize);
        }
    }

    let mut dead_cols: HashSet<usize> = HashSet::new();
    for col in 0..num_cols {
        // Never remove column 0 (constant one) or public input columns
        if col == 0 || col <= r1cs.num_public_inputs {
            continue;
        }
        // Never remove columns referenced by the ACIR witness map
        if acir_referenced.contains(&col) {
            continue;
        }
        if occurrence_counts[col] == 0 {
            dead_cols.insert(col);
        }
    }

    if dead_cols.is_empty() {
        return ColumnRemovalStats {
            witnesses_after:         num_cols,
            builders_removed:        0,
            zero_occurrence_cols:    0,
            blocked_by_acir:         0,
            blocked_by_live_builder: 0,
            columns_removed:         0,
        };
    }

    // Diagnostic: count how many zero-occurrence cols are blocked by each mechanism
    let zero_occ_total = (0..num_cols)
        .filter(|&c| c > r1cs.num_public_inputs && occurrence_counts[c] == 0)
        .count();
    let blocked_by_acir = (0..num_cols)
        .filter(|&c| {
            c > r1cs.num_public_inputs && occurrence_counts[c] == 0 && acir_referenced.contains(&c)
        })
        .count();
    info!(
        "Column removal: {} zero-occurrence cols (excl public), {} blocked by ACIR witness map, \
         {} truly dead",
        zero_occ_total,
        blocked_by_acir,
        dead_cols.len()
    );

    info!(
        "Column removal: {} dead columns found out of {} total",
        dead_cols.len(),
        num_cols
    );

    // Step 2: Build witness builder dependency graph and find reachable builders.
    // A builder is "live" if any of its output columns is NOT dead, OR if a
    // live builder reads any of its output columns.
    // We use the existing DependencyInfo infrastructure.
    let live_cols: HashSet<usize> = (0..num_cols).filter(|c| !dead_cols.contains(c)).collect();

    // Map: witness column -> builder index
    let mut col_to_builder: HashMap<usize, usize> = HashMap::new();
    for (builder_idx, builder) in witness_builders.iter().enumerate() {
        for col in DependencyInfo::extract_writes(builder) {
            col_to_builder.insert(col, builder_idx);
        }
    }

    // Build adjacency: which builders does each builder depend on?
    // (reverse of the normal dependency graph: we want "builder X reads from
    // builder Y")
    let mut builder_reads_from: Vec<HashSet<usize>> = vec![HashSet::new(); witness_builders.len()];
    for (builder_idx, builder) in witness_builders.iter().enumerate() {
        let reads = DependencyInfo::extract_reads(builder);
        for read_col in reads {
            if let Some(&producer_idx) = col_to_builder.get(&read_col) {
                if producer_idx != builder_idx {
                    builder_reads_from[builder_idx].insert(producer_idx);
                }
            }
        }
    }

    // Step 3: BFS/DFS from live builders to find all transitively reachable
    // builders. A builder is live if any of its output columns is live
    // (referenced by constraints).
    let mut live_builders: HashSet<usize> = HashSet::new();
    let mut queue: Vec<usize> = Vec::new();

    for (builder_idx, builder) in witness_builders.iter().enumerate() {
        let writes = DependencyInfo::extract_writes(builder);
        let is_directly_live = writes.iter().any(|c| live_cols.contains(c));
        if is_directly_live {
            if live_builders.insert(builder_idx) {
                queue.push(builder_idx);
            }
        }
    }

    // BFS: if a live builder reads from another builder, that builder is also live
    while let Some(builder_idx) = queue.pop() {
        for &dep_idx in &builder_reads_from[builder_idx] {
            if live_builders.insert(dep_idx) {
                queue.push(dep_idx);
            }
        }
    }

    info!(
        "Column removal: {} total builders, {} live (directly or transitively), {} dead",
        witness_builders.len(),
        live_builders.len(),
        witness_builders.len() - live_builders.len()
    );

    // Count dead cols blocked by live builder deps
    let blocked_by_bfs = dead_cols
        .iter()
        .filter(|&&col| {
            col_to_builder
                .get(&col)
                .map_or(false, |&b| live_builders.contains(&b))
        })
        .count();
    info!(
        "Column removal: of {} dead cols, {} blocked by live builder BFS, {} removable",
        dead_cols.len(),
        blocked_by_bfs,
        dead_cols.len() - blocked_by_bfs
    );

    // Step 4: Determine which columns to actually remove.
    // A column is removable if:
    //   - It's dead in matrices (zero occurrences) AND
    //   - Its producing builder is NOT live (not transitively reachable)
    let mut removable_cols: HashSet<usize> = HashSet::new();
    for &col in &dead_cols {
        let producer_is_live = col_to_builder
            .get(&col)
            .map_or(false, |&b| live_builders.contains(&b));
        if !producer_is_live {
            removable_cols.insert(col);
        }
    }

    if removable_cols.is_empty() {
        info!(
            "Column removal: all {} dead columns are transitively needed by live builders",
            dead_cols.len()
        );
        return ColumnRemovalStats {
            witnesses_after: num_cols,
            builders_removed: 0,
            zero_occurrence_cols: zero_occ_total,
            blocked_by_acir,
            blocked_by_live_builder: blocked_by_bfs,
            columns_removed: 0,
        };
    }

    info!(
        "Column removal: {} columns removable ({} dead, {} kept for live builder deps)",
        removable_cols.len(),
        dead_cols.len(),
        dead_cols.len() - removable_cols.len()
    );

    // Step 5: Build remap table (old_col -> new_col)
    let mut remap: Vec<Option<usize>> = vec![None; num_cols];
    let mut next_col = 0;
    for col in 0..num_cols {
        if !removable_cols.contains(&col) {
            remap[col] = Some(next_col);
            next_col += 1;
        }
    }
    let new_num_cols = next_col;

    // Step 6: Remap matrices
    r1cs.a = r1cs.a.remove_columns(&remap);
    r1cs.b = r1cs.b.remove_columns(&remap);
    r1cs.c = r1cs.c.remove_columns(&remap);

    // Step 6b: Remap ACIR witness map (ACIR index -> R1CS column)
    for entry in witness_map.iter_mut() {
        if let Some(nz) = entry {
            let old_col = nz.get() as usize;
            let new_col = remap[old_col].unwrap_or_else(|| {
                panic!(
                    "ACIR witness map references removed column {} (should be live)",
                    old_col
                )
            });
            *nz = std::num::NonZeroU32::new(new_col as u32)
                .expect("Remapped ACIR witness index should be non-zero");
        }
    }

    // Step 7: Prune dead builders and remap surviving ones
    let builders_before = witness_builders.len();
    let mut new_builders: Vec<WitnessBuilder> = Vec::with_capacity(live_builders.len());
    for (idx, builder) in witness_builders.drain(..).enumerate() {
        if live_builders.contains(&idx) {
            new_builders.push(remap_builder_columns(&builder, &remap));
        }
    }
    *witness_builders = new_builders;
    let builders_removed = builders_before - witness_builders.len();

    info!(
        "Column removal: {} -> {} witnesses, {} builders pruned",
        num_cols, new_num_cols, builders_removed
    );

    ColumnRemovalStats {
        witnesses_after: new_num_cols,
        builders_removed,
        zero_occurrence_cols: zero_occ_total,
        blocked_by_acir,
        blocked_by_live_builder: blocked_by_bfs,
        columns_removed: removable_cols.len(),
    }
}

/// Remap all witness column references inside a builder using the given
/// remap table. This mirrors `WitnessIndexRemapper::remap_builder` but uses
/// a Vec<Option<usize>> remap table instead of HashMap.
fn remap_builder_columns(builder: &WitnessBuilder, remap: &[Option<usize>]) -> WitnessBuilder {
    let r = |idx: usize| -> usize {
        remap[idx].unwrap_or_else(|| {
            panic!(
                "Witness index {} not in remap table (expected live column)",
                idx
            )
        })
    };

    let rc =
        |val: &crate::witness::ConstantOrR1CSWitness| -> crate::witness::ConstantOrR1CSWitness {
            match val {
                crate::witness::ConstantOrR1CSWitness::Constant(c) => {
                    crate::witness::ConstantOrR1CSWitness::Constant(*c)
                }
                crate::witness::ConstantOrR1CSWitness::Witness(w) => {
                    crate::witness::ConstantOrR1CSWitness::Witness(r(*w))
                }
            }
        };

    use crate::witness::*;
    match builder {
        WitnessBuilder::Constant(ConstantTerm(idx, val)) => {
            WitnessBuilder::Constant(ConstantTerm(r(*idx), *val))
        }
        WitnessBuilder::Acir(idx, acir_idx) => WitnessBuilder::Acir(r(*idx), *acir_idx),
        WitnessBuilder::Sum(idx, terms) => {
            let new_terms = terms
                .iter()
                .map(|SumTerm(coeff, operand_idx)| SumTerm(*coeff, r(*operand_idx)))
                .collect();
            WitnessBuilder::Sum(r(*idx), new_terms)
        }
        WitnessBuilder::Product(idx, a, b) => WitnessBuilder::Product(r(*idx), r(*a), r(*b)),
        WitnessBuilder::MultiplicitiesForRange(start, range, values) => {
            let new_values = values.iter().map(|&v| r(v)).collect();
            WitnessBuilder::MultiplicitiesForRange(r(*start), *range, new_values)
        }
        WitnessBuilder::Challenge(idx) => WitnessBuilder::Challenge(r(*idx)),
        WitnessBuilder::IndexedLogUpDenominator(
            idx,
            sz,
            WitnessCoefficient(coeff, index),
            rs,
            value,
        ) => WitnessBuilder::IndexedLogUpDenominator(
            r(*idx),
            r(*sz),
            WitnessCoefficient(*coeff, r(*index)),
            r(*rs),
            r(*value),
        ),
        WitnessBuilder::Inverse(idx, operand) => WitnessBuilder::Inverse(r(*idx), r(*operand)),
        WitnessBuilder::ProductLinearOperation(
            idx,
            ProductLinearTerm(x, a, b),
            ProductLinearTerm(y, c, d),
        ) => WitnessBuilder::ProductLinearOperation(
            r(*idx),
            ProductLinearTerm(r(*x), *a, *b),
            ProductLinearTerm(r(*y), *c, *d),
        ),
        WitnessBuilder::LogUpDenominator(idx, sz, WitnessCoefficient(coeff, value)) => {
            WitnessBuilder::LogUpDenominator(r(*idx), r(*sz), WitnessCoefficient(*coeff, r(*value)))
        }
        WitnessBuilder::LogUpInverse(idx, sz, WitnessCoefficient(coeff, value)) => {
            WitnessBuilder::LogUpInverse(r(*idx), r(*sz), WitnessCoefficient(*coeff, r(*value)))
        }
        WitnessBuilder::DigitalDecomposition(dd) => {
            let new_witnesses_to_decompose =
                dd.witnesses_to_decompose.iter().map(|&w| r(w)).collect();
            WitnessBuilder::DigitalDecomposition(crate::witness::DigitalDecompositionWitnesses {
                log_bases:                  dd.log_bases.clone(),
                num_witnesses_to_decompose: dd.num_witnesses_to_decompose,
                witnesses_to_decompose:     new_witnesses_to_decompose,
                first_witness_idx:          r(dd.first_witness_idx),
                num_witnesses:              dd.num_witnesses,
            })
        }
        WitnessBuilder::SpiceMultisetFactor(
            idx,
            sz,
            rs,
            WitnessCoefficient(addr_c, addr_w),
            value,
            WitnessCoefficient(timer_c, timer_w),
        ) => WitnessBuilder::SpiceMultisetFactor(
            r(*idx),
            r(*sz),
            r(*rs),
            WitnessCoefficient(*addr_c, r(*addr_w)),
            r(*value),
            WitnessCoefficient(*timer_c, r(*timer_w)),
        ),
        WitnessBuilder::SpiceWitnesses(sw) => {
            let new_memory_operations = sw
                .memory_operations
                .iter()
                .map(|op| match op {
                    crate::witness::SpiceMemoryOperation::Load(addr, value, rt) => {
                        crate::witness::SpiceMemoryOperation::Load(r(*addr), r(*value), r(*rt))
                    }
                    crate::witness::SpiceMemoryOperation::Store(addr, old_val, new_val, rt) => {
                        crate::witness::SpiceMemoryOperation::Store(
                            r(*addr),
                            r(*old_val),
                            r(*new_val),
                            r(*rt),
                        )
                    }
                })
                .collect();
            WitnessBuilder::SpiceWitnesses(crate::witness::SpiceWitnesses {
                memory_length:           sw.memory_length,
                initial_value_witnesses: sw.initial_value_witnesses.iter().map(|w| r(*w)).collect(),
                memory_operations:       new_memory_operations,
                rv_final_start:          r(sw.rv_final_start),
                rt_final_start:          r(sw.rt_final_start),
                first_witness_idx:       r(sw.first_witness_idx),
                num_witnesses:           sw.num_witnesses,
            })
        }
        WitnessBuilder::U32AdditionMulti(result_idx, carry_idx, inputs) => {
            WitnessBuilder::U32AdditionMulti(
                r(*result_idx),
                r(*carry_idx),
                inputs.iter().map(|c| rc(c)).collect(),
            )
        }
        WitnessBuilder::BytePartition { lo, hi, x, k } => WitnessBuilder::BytePartition {
            lo: r(*lo),
            hi: r(*hi),
            x:  r(*x),
            k:  *k,
        },
        WitnessBuilder::BinOpLookupDenominator(idx, sz, rs, rs2, lhs, rhs, output) => {
            WitnessBuilder::BinOpLookupDenominator(
                r(*idx),
                r(*sz),
                r(*rs),
                r(*rs2),
                rc(lhs),
                rc(rhs),
                rc(output),
            )
        }
        WitnessBuilder::CombinedBinOpLookupDenominator(
            idx,
            sz,
            rs,
            rs2,
            rs3,
            lhs,
            rhs,
            and_out,
            xor_out,
        ) => WitnessBuilder::CombinedBinOpLookupDenominator(
            r(*idx),
            r(*sz),
            r(*rs),
            r(*rs2),
            r(*rs3),
            rc(lhs),
            rc(rhs),
            rc(and_out),
            rc(xor_out),
        ),
        WitnessBuilder::MultiplicitiesForBinOp(start, atomic_bits, pairs) => {
            let new_pairs = pairs.iter().map(|(lhs, rhs)| (rc(lhs), rc(rhs))).collect();
            WitnessBuilder::MultiplicitiesForBinOp(r(*start), *atomic_bits, new_pairs)
        }
        WitnessBuilder::U32Addition(result_idx, carry_idx, a, b) => {
            WitnessBuilder::U32Addition(r(*result_idx), r(*carry_idx), rc(a), rc(b))
        }
        WitnessBuilder::And(idx, lh, rh) => WitnessBuilder::And(r(*idx), rc(lh), rc(rh)),
        WitnessBuilder::Xor(idx, lh, rh) => WitnessBuilder::Xor(r(*idx), rc(lh), rc(rh)),
        WitnessBuilder::CombinedTableEntryInverse(data) => {
            WitnessBuilder::CombinedTableEntryInverse(
                crate::witness::CombinedTableEntryInverseData {
                    idx:          r(data.idx),
                    sz_challenge: r(data.sz_challenge),
                    rs_challenge: r(data.rs_challenge),
                    rs_sqrd:      r(data.rs_sqrd),
                    rs_cubed:     r(data.rs_cubed),
                    lhs:          data.lhs,
                    rhs:          data.rhs,
                    and_out:      data.and_out,
                    xor_out:      data.xor_out,
                },
            )
        }
        WitnessBuilder::ChunkDecompose {
            output_start,
            packed,
            chunk_bits,
        } => WitnessBuilder::ChunkDecompose {
            output_start: r(*output_start),
            packed:       r(*packed),
            chunk_bits:   chunk_bits.clone(),
        },
        WitnessBuilder::SpreadWitness(output, input) => {
            WitnessBuilder::SpreadWitness(r(*output), r(*input))
        }
        WitnessBuilder::SpreadBitExtract {
            output_start,
            chunk_bits,
            sum_terms,
            extract_even,
        } => WitnessBuilder::SpreadBitExtract {
            output_start: r(*output_start),
            chunk_bits:   chunk_bits.clone(),
            sum_terms:    sum_terms
                .iter()
                .map(|SumTerm(coeff, idx)| SumTerm(*coeff, r(*idx)))
                .collect(),
            extract_even: *extract_even,
        },
        WitnessBuilder::MultiplicitiesForSpread(start, num_bits, queries) => {
            let new_queries = queries.iter().map(|c| rc(c)).collect();
            WitnessBuilder::MultiplicitiesForSpread(r(*start), *num_bits, new_queries)
        }
        WitnessBuilder::SpreadLookupDenominator(idx, sz, rs, input, spread_output) => {
            WitnessBuilder::SpreadLookupDenominator(
                r(*idx),
                r(*sz),
                r(*rs),
                rc(input),
                rc(spread_output),
            )
        }
        WitnessBuilder::SpreadTableQuotient {
            idx,
            sz,
            rs,
            input_val,
            spread_val,
            multiplicity,
        } => WitnessBuilder::SpreadTableQuotient {
            idx:          r(*idx),
            sz:           r(*sz),
            rs:           r(*rs),
            input_val:    *input_val,
            spread_val:   *spread_val,
            multiplicity: r(*multiplicity),
        },
    }
}

/// Apply all relevant substitutions to a single row of a matrix.
///
/// Since Phase 2b resolves backward chains (later pivots referenced by
/// earlier substitutions), every substitution's terms now reference only
/// non-pivot columns. A single pass suffices.
fn apply_substitutions_to_row(
    matrix: &mut SparseMatrix,
    row: usize,
    substitutions: &[Substitution],
    sub_map: &HashMap<usize, usize>,
    interner: &mut crate::Interner,
) {
    let entries = matrix.get_row_entries(row);

    // Check if any entry references a pivot column
    let has_pivot = entries.iter().any(|(col, _)| sub_map.contains_key(col));
    if !has_pivot {
        return;
    }

    // Accumulate new row as HashMap<col, FieldElement>
    let mut new_entries: HashMap<usize, FieldElement> = HashMap::new();

    for (col, interned_val) in &entries {
        let val = interner.get(*interned_val).expect("interned value missing");

        if let Some(&sub_idx) = sub_map.get(col) {
            // This column is a pivot — replace with substitution terms
            let sub = &substitutions[sub_idx];
            for (sub_coeff, sub_col) in &sub.terms {
                let contribution = val * sub_coeff;
                *new_entries
                    .entry(*sub_col)
                    .or_insert_with(FieldElement::zero) += contribution;
            }
        } else {
            // Normal column — keep as-is
            *new_entries.entry(*col).or_insert_with(FieldElement::zero) += val;
        }
    }

    // Remove zero entries and sort by column
    let mut sorted_entries: Vec<(usize, InternedFieldElement)> = new_entries
        .into_iter()
        .filter(|(_, v)| !v.is_zero())
        .map(|(col, val)| (col, interner.intern(val)))
        .collect();
    sorted_entries.sort_by_key(|(col, _)| *col);

    matrix.replace_row(row, &sorted_entries);
}

#[cfg(test)]
mod tests {
    use {super::*, crate::witness::SumTerm, ark_std::One};

    #[test]
    fn test_simple_linear_elimination() {
        // Create a simple R1CS:
        // Constraint 0: A=[1*w0], B=[1*w0], C=[1*w1 + 1*w2 + (-1)*w3]
        //   → 1*1 = w1 + w2 - w3, i.e. w1 + w2 - w3 = 0  (linear)
        // Constraint 1: A=[1*w1], B=[1*w2], C=[1*w4]
        //   → w1 * w2 = w4  (non-linear, kept)
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg_one = -one;

        // 4 witnesses + constant = 5 columns
        r1cs.add_witnesses(5);

        // Constraint 0: linear
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[
            (one, 1),
            (one, 2),
            (neg_one, 3),
        ]);
        // Constraint 1: non-linear
        r1cs.add_constraint(&[(one, 1)], &[(one, 2)], &[(one, 4)]);

        let mut witness_builders = vec![
            WitnessBuilder::Constant(crate::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(None, 1), SumTerm(None, 2)]),
            WitnessBuilder::Product(4, 1, 2),
        ];

        assert_eq!(r1cs.num_constraints(), 2);

        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut witness_builders, &mut wmap)
        };

        // Constraint 0 should be eliminated (it's linear)
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.eliminated, 1);

        // The remaining constraint should still be valid
        assert_eq!(r1cs.num_constraints(), 1);
    }

    #[test]
    fn test_chained_linear_elimination() {
        // Two chained linear constraints where L1's expression references
        // L0's pivot, creating a substitution chain:
        //
        //   L0: 1*1 = w1 - w3  →  w3 = w1 - 1     (pivot w3)
        //   L1: 1*1 = w3 - w4  →  w4 = w3 - 1      (pivot w4, terms ref w3)
        //   Q:  w4 * w2 = w5                         (non-linear, kept)
        //
        // w1, w2 are public inputs (forbidden as pivots), forcing w3 and w4
        // as the only pivot candidates for L0 and L1 respectively.
        //
        // Without chain resolution in Phase 2, S1's terms are [(-1, w0), (1, w3)].
        // Substituting w4 in Q introduces w3 into Q's A matrix. But w3 is
        // S0's eliminated pivot — its defining constraint is removed. Bug!
        //
        // With chain resolution, S1's terms resolve w3 → (w1 - 1), yielding
        // [(-2, w0), (1, w1)]. Q becomes (w1-2)*w2 = w5. No dangling pivots.
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg = -one;

        // 6 columns: w0(const), w1(public), w2(public), w3, w4, w5
        r1cs.add_witnesses(6);
        r1cs.num_public_inputs = 2;

        // L0: 1*1 = w1 - w3
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 1), (neg, 3)]);
        // L1: 1*1 = w3 - w4
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 3), (neg, 4)]);
        // Q: w4 * w2 = w5
        r1cs.add_constraint(&[(one, 4)], &[(one, 2)], &[(one, 5)]);

        let mut builders = vec![
            WitnessBuilder::Constant(crate::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(Some(neg), 0), SumTerm(None, 1)]),
            WitnessBuilder::Sum(4, vec![SumTerm(Some(neg), 0), SumTerm(None, 3)]),
            WitnessBuilder::Product(5, 4, 2),
        ];

        assert_eq!(r1cs.num_constraints(), 3);
        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap)
        };

        // Both linear constraints eliminated, Q remains
        assert_eq!(stats.eliminated, 2);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(r1cs.num_constraints(), 1);

        // Without builder rewriting (currently disabled), pivot columns
        // remain alive because their producer builders are transitively
        // reachable from live builders. No witness reduction expected.
        assert_eq!(
            stats.witnesses_after, stats.witnesses_before,
            "Expected no witness reduction without builder rewriting, got {} -> {}",
            stats.witnesses_before, stats.witnesses_after
        );

        // Verify the remaining constraint references only valid column indices
        let num_cols = r1cs.num_witnesses();
        for (col, _) in r1cs.a.iter_row(0) {
            assert!(col < num_cols, "A references out-of-range col {col}");
        }
        for (col, _) in r1cs.b.iter_row(0) {
            assert!(col < num_cols, "B references out-of-range col {col}");
        }
        for (col, _) in r1cs.c.iter_row(0) {
            assert!(col < num_cols, "C references out-of-range col {col}");
        }
    }

    #[test]
    fn test_deep_chain_elimination() {
        // Chain of depth 4: w3 → w4 → w5 → w6, then Q uses w6.
        // Verifies that chain resolution works transitively because each
        // substitution's terms are already resolved when the next one
        // inlines them.
        //
        //   L0: 1*1 = w1 - w3  →  w3 = w1 - 1       (pivot w3)
        //   L1: 1*1 = w3 - w4  →  w4 = w3 - 1        (pivot w4)
        //   L2: 1*1 = w4 - w5  →  w5 = w4 - 1        (pivot w5)
        //   L3: 1*1 = w5 - w6  →  w6 = w5 - 1        (pivot w6)
        //   Q:  w6 * w2 = w7                           (non-linear, kept)
        //
        // After full chain resolution: w6 = w1 - 4.
        // Q becomes: (w1 - 4) * w2 = w7.
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg = -one;

        // 8 columns: w0(const), w1(pub), w2(pub), w3, w4, w5, w6, w7
        r1cs.add_witnesses(8);
        r1cs.num_public_inputs = 2;

        // L0..L3: chain of w3 → w4 → w5 → w6
        for i in 0..4u32 {
            // L0: C=[w1, -w3], L1: C=[w3, -w4], L2: C=[w4, -w5], L3: C=[w5, -w6]
            let prev_col = if i == 0 { 1 } else { 2 + i as usize };
            let cur_col = 3 + i as usize;
            r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, prev_col), (neg, cur_col)]);
        }
        // Q: w6 * w2 = w7
        r1cs.add_constraint(&[(one, 6)], &[(one, 2)], &[(one, 7)]);

        let mut builders = vec![
            WitnessBuilder::Constant(crate::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(Some(neg), 0), SumTerm(None, 1)]),
            WitnessBuilder::Sum(4, vec![SumTerm(Some(neg), 0), SumTerm(None, 3)]),
            WitnessBuilder::Sum(5, vec![SumTerm(Some(neg), 0), SumTerm(None, 4)]),
            WitnessBuilder::Sum(6, vec![SumTerm(Some(neg), 0), SumTerm(None, 5)]),
            WitnessBuilder::Product(7, 6, 2),
        ];

        assert_eq!(r1cs.num_constraints(), 5);
        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap)
        };

        // All 4 linear constraints eliminated, Q remains
        assert_eq!(stats.eliminated, 4);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(r1cs.num_constraints(), 1);

        // Without builder rewriting (currently disabled), pivot columns
        // w3-w6 remain alive because their producer builders are still
        // reachable. No witness reduction expected.
        assert_eq!(
            stats.witnesses_after, stats.witnesses_before,
            "Expected no witness reduction without builder rewriting, got {} -> {}",
            stats.witnesses_before, stats.witnesses_after
        );

        // Verify the remaining constraint references only valid column indices
        let num_cols = r1cs.num_witnesses();
        for (col, _) in r1cs.a.iter_row(0) {
            assert!(col < num_cols, "A references out-of-range col {col}");
        }
        for (col, _) in r1cs.b.iter_row(0) {
            assert!(col < num_cols, "B references out-of-range col {col}");
        }
        for (col, _) in r1cs.c.iter_row(0) {
            assert!(col < num_cols, "C references out-of-range col {col}");
        }
    }

    #[test]
    fn test_backward_chain_elimination() {
        // Backward chain: S_0 is built FIRST with terms referencing w5,
        // then S_1 eliminates w5. Phase 2b resolves this backward
        // reference so Phase 3's single pass works.
        //
        //   L0: 1*1 = w1 + w5 - w3  →  w3 = w1 + w5 - 1  (pivot w3, count=2)
        //   L1: 1*1 = w4 - w5       →  w5 = w4 - 1        (pivot w5, count=2 after
        // decrement)   Q1: w3 * w2 = w6
        // (non-linear)   Q2: w4 * w4 = w7                                (extra
        // w4 occurrences)   Q3: w5 * w1 = w8
        // (breaks count tie: w5=3 > w3=2)
        //
        // w1, w2 are public (forbidden).
        // Counts: w3=2, w5=3, w4=3 → L0 picks w3 (min).
        // After L0 decrement: w5=2, w4=3 → L1 picks w5.
        //
        // After full resolution: w3 = w1 + (w4-1) - 1 = w1 + w4 - 2.
        // Q1 becomes: (w1 + w4 - 2) * w2 = w6.
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg = -one;

        // 9 columns: w0(const), w1(pub), w2(pub), w3, w4, w5, w6, w7, w8
        r1cs.add_witnesses(9);
        r1cs.num_public_inputs = 2;

        // L0: 1*1 = w1 + w5 - w3
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 1), (one, 5), (neg, 3)]);
        // L1: 1*1 = w4 - w5
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 4), (neg, 5)]);
        // Q1: w3 * w2 = w6
        r1cs.add_constraint(&[(one, 3)], &[(one, 2)], &[(one, 6)]);
        // Q2: w4 * w4 = w7 (extra occurrences for w4)
        r1cs.add_constraint(&[(one, 4)], &[(one, 4)], &[(one, 7)]);
        // Q3: w5 * w1 = w8 (extra w5 occurrence to break tie vs w3)
        r1cs.add_constraint(&[(one, 5)], &[(one, 1)], &[(one, 8)]);

        let mut builders = vec![
            WitnessBuilder::Constant(crate::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![
                SumTerm(Some(neg), 0),
                SumTerm(None, 1),
                SumTerm(None, 5),
            ]),
            WitnessBuilder::Acir(4, 2),
            WitnessBuilder::Sum(5, vec![SumTerm(Some(neg), 0), SumTerm(None, 4)]),
            WitnessBuilder::Product(6, 3, 2),
            WitnessBuilder::Product(7, 4, 4),
            WitnessBuilder::Product(8, 5, 1),
        ];

        assert_eq!(r1cs.num_constraints(), 5);
        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap)
        };

        // Both linear constraints eliminated, Q1, Q2, Q3 remain
        assert_eq!(stats.eliminated, 2);
        assert_eq!(stats.constraints_after, 3);

        // Without builder rewriting (currently disabled), pivot columns
        // w3, w5 remain alive because their producer builders are still
        // reachable. No witness reduction expected.
        assert_eq!(
            stats.witnesses_after, stats.witnesses_before,
            "Expected no witness reduction without builder rewriting, got {} -> {}",
            stats.witnesses_before, stats.witnesses_after
        );

        // Verify all column references are in valid range
        let num_cols = r1cs.num_witnesses();
        for row in 0..r1cs.num_constraints() {
            for (col, _) in r1cs.a.iter_row(row) {
                assert!(col < num_cols, "row {row} A out-of-range col {col}");
            }
            for (col, _) in r1cs.b.iter_row(row) {
                assert!(col < num_cols, "row {row} B out-of-range col {col}");
            }
            for (col, _) in r1cs.c.iter_row(row) {
                assert!(col < num_cols, "row {row} C out-of-range col {col}");
            }
        }
    }
}
