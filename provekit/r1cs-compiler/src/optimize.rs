//! Gaussian elimination optimization pass for R1CS.
//!
//! Inspired by Circom's `-O2` substitution-based sparse elimination:
//!   1. Identify linear constraints (where A or B is constant)
//!   2. For each linear constraint, pick a pivot variable (fewest occurrences,
//!      not forbidden) and express it as a linear combination of remaining
//!      variables
//!   2b. Resolve backward chains (later pivots referenced by earlier
//!       substitutions)
//!   3. Apply substitutions to all remaining (non-eliminated) constraints
//!   4. Remove eliminated constraint rows
//!   5. Remove dead witness columns and prune unreachable witness builders

use {
    anyhow::{bail, Context as _, Result},
    ark_ff::Field,
    ark_std::{One, Zero},
    provekit_backend_bn254::witness::{DependencyInfo, WitnessBuilder},
    provekit_common::{FieldElement, Interner, SparseMatrix, R1CS},
    rayon::iter::{IntoParallelRefIterator, ParallelIterator},
    std::collections::{HashMap, HashSet},
    tracing::{debug, info},
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
    pub constraints_before: usize,
    pub constraints_after:  usize,
    pub witnesses_before:   usize,
    pub witnesses_after:    usize,
    pub eliminated:         usize,
    pub builders_removed:   usize,
    /// Virtual witnesses: computation-only, excluded from WHIR commitment.
    pub num_virtual:        usize,
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
        (self.witnesses_before as f64 - self.witnesses_after as f64) / self.witnesses_before as f64
            * 100.0
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
    acir_public_inputs_indices_set: &HashSet<u32>,
) -> Result<OptimizationStats> {
    let constraints_before = r1cs.num_constraints();
    let witnesses_before = r1cs.num_witnesses();

    // In raw Noir lowering, public-input builders may not yet be packed into
    // columns 1..=num_public_inputs. Track the actual public-input columns so
    // GE cannot pivot them away before the later canonical remap.
    let public_input_cols: HashSet<usize> = witness_builders
        .iter()
        .filter_map(|builder| match builder {
            WitnessBuilder::Acir(col, acir_idx)
                if acir_public_inputs_indices_set.contains(&(*acir_idx as u32)) =>
            {
                Some(*col)
            }
            _ => None,
        })
        .collect();

    // Columns that must not be eliminated:
    // - Column 0: constant one
    // - Columns 1..=num_public_inputs: canonical public inputs
    // - Any actual public-input builder columns before canonical remap
    let mut forbidden: HashSet<usize> = HashSet::new();
    forbidden.insert(0);
    for i in 1..=r1cs.num_public_inputs {
        forbidden.insert(i);
    }
    forbidden.extend(public_input_cols.iter().copied());

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
        let pivot_inv = pivot_coeff
            .inverse()
            .context("pivot coefficient is zero — cannot invert")?;

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
        return Ok(OptimizationStats {
            constraints_before,
            constraints_after: constraints_before,
            witnesses_before,
            witnesses_after: witnesses_before,
            eliminated: 0,
            builders_removed: 0,
            num_virtual: 0,
        });
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
    info!("Gaussian elimination: phase 2b (backward chains) complete");

    // Phase 3+4: Rebuild A, B, C in a single pass.
    //
    // The previous in-place implementation called `SparseMatrix::replace_row`
    // for every (row, matrix) with a pivot. That function's length-change
    // branch shifts every entry after the row plus updates every subsequent
    // row-index — an O(N) bookkeeping cost paid up to 3·survivors times,
    // giving O(N²) total. For circuits with hundreds of thousands of
    // constraints this dominated the whole optimize pass.
    //
    // We now:
    //   1. Build a flat pivot lookup (Vec<u32>) instead of a HashMap — O(1) lookup
    //      without hashing in the inner row loop.
    //   2. Classify each surviving row in parallel as either PassThrough (no pivot
    //      — output is identical to source row) or Substituted (pivots expanded
    //      into substitution terms). Read-only access to the interner here; no
    //      value is dehydrated unless it has to be.
    //   3. Run A, B, C in parallel via rayon::join.
    //   4. Assemble each new matrix sequentially: PassThrough rows are bulk
    //      memcpy'd from the source slices (existing InternedFieldElement handles
    //      remain valid because the interner only appends); only Substituted rows
    //      pay the per-value `intern` cost. Eliminated rows are simply not emitted,
    //      so Phase 4's row-removal fuses in for free.
    //
    // Total work is O(E') in the size of the output matrix instead of O(N²),
    // and intern cost scales with substituted entries only, not total entries.
    let num_constraints_before_removal = r1cs.num_constraints();
    let num_cols = r1cs.num_witnesses();

    let mut sub_lookup: Vec<u32> = vec![u32::MAX; num_cols];
    for (idx, sub) in substitutions.iter().enumerate() {
        sub_lookup[sub.pivot_col] = idx as u32;
    }

    let mut is_eliminated = vec![false; num_constraints_before_removal];
    for &r in &eliminated_rows {
        is_eliminated[r] = true;
    }
    let survivors: Vec<usize> = (0..num_constraints_before_removal)
        .filter(|r| !is_eliminated[*r])
        .collect();

    let (new_a_rows, (new_b_rows, new_c_rows)) = {
        let subs = substitutions.as_slice();
        let lookup = sub_lookup.as_slice();
        let survs = survivors.as_slice();
        let interner = &r1cs.interner;
        let (a, b, c) = (&r1cs.a, &r1cs.b, &r1cs.c);
        rayon::join(
            || rebuild_matrix_rows(a, "A", interner, subs, lookup, survs),
            || {
                rayon::join(
                    || rebuild_matrix_rows(b, "B", interner, subs, lookup, survs),
                    || rebuild_matrix_rows(c, "C", interner, subs, lookup, survs),
                )
            },
        )
    };
    let new_a_rows = new_a_rows?;
    let new_b_rows = new_b_rows?;
    let new_c_rows = new_c_rows?;
    info!("Gaussian elimination: phase 3 (rebuild rows in parallel) complete");

    // Disjoint-field borrows: &r1cs.a (read for memcpy) lives only inside the
    // call to `finalize_matrix`, then `r1cs.a` is reassigned. Same for b and c.
    // `r1cs.interner` is borrowed mutably for `intern()` calls; disjoint from
    // the matrix fields.
    let new_a = finalize_matrix(new_a_rows, &r1cs.a, num_cols, &mut r1cs.interner);
    r1cs.a = new_a;
    let new_b = finalize_matrix(new_b_rows, &r1cs.b, num_cols, &mut r1cs.interner);
    r1cs.b = new_b;
    let new_c = finalize_matrix(new_c_rows, &r1cs.c, num_cols, &mut r1cs.interner);
    r1cs.c = new_c;
    info!("Gaussian elimination: phase 4 (intern + assemble matrices) complete");

    let constraints_after = r1cs.num_constraints();
    let eliminated = substitutions.len();

    debug!(
        "Phase 3 done: {} constraints remaining after substitution",
        constraints_after
    );

    // Phase 5: Remove dead witness columns and prune unreachable builders
    debug!("Phase 5: starting dead column removal + virtual witness assignment");
    let col_stats = remove_dead_columns(
        r1cs,
        witness_builders,
        witness_map,
        acir_public_inputs_indices_set,
    )?;
    info!("Gaussian elimination: phase 5 (remove dead columns) complete");
    r1cs.num_virtual = col_stats.num_virtual;

    let stats = OptimizationStats {
        constraints_before,
        constraints_after,
        witnesses_before,
        witnesses_after: col_stats.witnesses_after,
        eliminated,
        builders_removed: col_stats.builders_removed,
        num_virtual: col_stats.num_virtual,
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

    Ok(stats)
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
    witnesses_after:  usize,
    builders_removed: usize,
    /// Virtual columns: computation-only, excluded from R1CS/WHIR but needed
    /// by builders.
    num_virtual:      usize,
}

/// Phase 5: Remove dead witness columns from matrices and prune unreachable
/// witness builders.
///
/// After GE, some columns have zero occurrences across all remaining
/// constraints in A, B, and C. These are "dead" columns. This function:
///
/// 1. Identifies dead columns (zero occurrences in all three matrices)
/// 2. Builds a dependency graph of witness builders
/// 3. DFS from live builders to find all transitively reachable builders
/// 4. Protects contiguous-range multi-output builders from partial removal
/// 5. Partitions removable columns into fully dead vs virtual (needed by live
///    builders for intermediate computation)
/// 6. Builds a remap table and removes dead/virtual columns from A, B, C
/// 6b. Remaps ACIR witness map column indices
/// 7. Prunes dead builders and remaps surviving builder witness indices
fn remove_dead_columns(
    r1cs: &mut R1CS,
    witness_builders: &mut Vec<WitnessBuilder>,
    witness_map: &mut [Option<std::num::NonZeroU32>],
    acir_public_inputs_indices_set: &HashSet<u32>,
) -> Result<ColumnRemovalStats> {
    let num_cols = r1cs.num_witnesses();
    if num_cols == 0 || witness_builders.is_empty() {
        return Ok(ColumnRemovalStats {
            witnesses_after:  num_cols,
            builders_removed: 0,
            num_virtual:      0,
        });
    }

    // Step 1: Find dead columns (zero occurrence across A, B, C).
    // ACIR-mapped columns are not automatic liveness roots: if a column has
    // no remaining constraint occurrences and no live builder depends on it,
    // it can be removed and its witness-map entry becomes `None`.
    let occurrence_counts = build_occurrence_counts(r1cs);
    let public_input_cols: HashSet<usize> = witness_builders
        .iter()
        .filter_map(|builder| match builder {
            WitnessBuilder::Acir(col, acir_idx)
                if acir_public_inputs_indices_set.contains(&(*acir_idx as u32)) =>
            {
                Some(*col)
            }
            _ => None,
        })
        .collect();

    let mut dead_cols = vec![false; num_cols];
    let mut num_dead = 0usize;
    for col in 0..num_cols {
        // Never remove column 0 (constant one) or public input columns
        if col == 0 || col <= r1cs.num_public_inputs || public_input_cols.contains(&col) {
            continue;
        }
        if occurrence_counts[col] == 0 {
            dead_cols[col] = true;
            num_dead += 1;
        }
    }

    if num_dead == 0 {
        return Ok(ColumnRemovalStats {
            witnesses_after:  num_cols,
            builders_removed: 0,
            num_virtual:      0,
        });
    }

    if tracing::enabled!(tracing::Level::DEBUG) {
        let zero_occ_total = (0..num_cols)
            .filter(|&c| c > r1cs.num_public_inputs && occurrence_counts[c] == 0)
            .count();

        debug!(
            "Column removal: {} zero-occurrence cols (excl public), {} truly dead",
            zero_occ_total, num_dead
        );
    }

    debug!(
        "Column removal: {} dead columns found out of {} total",
        num_dead, num_cols
    );

    // Step 2: Build witness builder dependency graph and find reachable builders.
    // A builder is "live" if any of its output columns is NOT dead, OR if a
    // live builder reads any of its output columns.
    //
    // Cache extract_reads/extract_writes once per builder to avoid repeated
    // heap allocation across the 5 downstream uses (col_to_builder build,
    // builder_reads_from build, BFS seed, contiguous protection, and
    // live_read_cols build).
    let builder_writes: Vec<Vec<usize>> = witness_builders
        .iter()
        .map(DependencyInfo::extract_writes)
        .collect();
    let builder_reads: Vec<Vec<usize>> = witness_builders
        .iter()
        .map(DependencyInfo::extract_reads)
        .collect();

    // Map: witness column -> builder index
    let mut col_to_builder: HashMap<usize, usize> = HashMap::new();
    for (builder_idx, writes) in builder_writes.iter().enumerate() {
        for &col in writes {
            col_to_builder.insert(col, builder_idx);
        }
    }

    // Build adjacency: which builders does each builder depend on?
    // (reverse of the normal dependency graph: we want "builder X reads from
    // builder Y")
    let mut builder_reads_from: Vec<HashSet<usize>> = vec![HashSet::new(); witness_builders.len()];
    for (builder_idx, reads) in builder_reads.iter().enumerate() {
        for &read_col in reads {
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
    let mut live_builders = vec![false; witness_builders.len()];
    let mut num_live_builders = 0usize;
    let mut queue: Vec<usize> = Vec::new();

    for (builder_idx, writes) in builder_writes.iter().enumerate() {
        let is_directly_live = writes.iter().any(|c| !dead_cols[*c]);
        if is_directly_live {
            live_builders[builder_idx] = true;
            num_live_builders += 1;
            queue.push(builder_idx);
        }
    }

    // DFS (LIFO via Vec::pop): if a live builder reads from another builder,
    // that builder is also live. DFS and BFS find the same reachable set.
    while let Some(builder_idx) = queue.pop() {
        for &dep_idx in &builder_reads_from[builder_idx] {
            if !live_builders[dep_idx] {
                live_builders[dep_idx] = true;
                num_live_builders += 1;
                queue.push(dep_idx);
            }
        }
    }

    debug!(
        "Column removal: {} total builders, {} live (directly or transitively), {} dead",
        witness_builders.len(),
        num_live_builders,
        witness_builders.len() - num_live_builders
    );

    // Diagnostic: count dead cols blocked by live builder reachability.
    // Only computed when debug tracing is active to avoid O(num_cols)
    // HashMap lookups on large circuits in release builds.
    if tracing::enabled!(tracing::Level::DEBUG) {
        let blocked_by_bfs = (0..num_cols)
            .filter(|&col| {
                dead_cols[col]
                    && col_to_builder
                        .get(&col)
                        .map_or(false, |&b| live_builders[b])
            })
            .count();

        debug!(
            "Column removal: of {} dead cols, {} blocked by live builder DFS, {} removable",
            num_dead,
            blocked_by_bfs,
            num_dead - blocked_by_bfs
        );
    }

    // Step 4: Dead columns are removable from R1CS matrices — BUT we must
    // protect multi-output builders whose output ranges must stay contiguous.
    // If ANY column in a multi-output builder's range is live (non-dead),
    // ALL columns in that range must stay real to preserve the contiguous
    // `output_start + num_witnesses` layout.
    //
    // Classification is delegated to `requires_contiguous_outputs`, which uses
    // an exhaustive `match` so adding a new `WitnessBuilder` variant fails to
    // compile until it is explicitly classified.
    let mut protected_cols = vec![false; num_cols];
    for (builder_idx, builder) in witness_builders.iter().enumerate() {
        if !DependencyInfo::requires_contiguous_outputs(builder) {
            continue;
        }
        let writes = &builder_writes[builder_idx];
        if writes.len() <= 1 {
            continue;
        }
        let has_live = writes.iter().any(|c| !dead_cols[*c]);
        if has_live && writes.iter().any(|c| dead_cols[*c]) {
            for &c in writes {
                protected_cols[c] = true;
            }
        }
    }
    let mut removable_cols = vec![false; num_cols];
    let mut num_removable = 0usize;
    for col in 0..num_cols {
        if dead_cols[col] && !protected_cols[col] {
            removable_cols[col] = true;
            num_removable += 1;
        }
    }
    let protected_count = num_dead - num_removable;
    if protected_count > 0 {
        debug!(
            "Column removal: {protected_count} dead cols protected (contiguous-range multi-output \
             builders with mixed live/dead outputs)"
        );
    }

    if num_removable == 0 {
        return Ok(ColumnRemovalStats {
            witnesses_after:  num_cols,
            builders_removed: 0,
            num_virtual:      0,
        });
    }

    // Partition dead cols: dead producers (fully removable) vs live producers
    // (virtual). A column must also be virtual if ANY live builder reads it
    // (even if its producer is dead) — this can happen after builder rewriting
    // changes dependency chains.
    let mut live_read_cols = vec![false; num_cols];
    for (bi, reads) in builder_reads.iter().enumerate() {
        if live_builders[bi] {
            for &c in reads {
                if removable_cols[c] {
                    live_read_cols[c] = true;
                }
            }
        }
    }
    let mut virtual_cols = vec![false; num_cols];
    let mut num_virtual = 0usize;
    let mut num_fully_dead = 0usize;
    for col in 0..num_cols {
        if !removable_cols[col] {
            continue;
        }
        let producer_is_live = col_to_builder
            .get(&col)
            .map_or(false, |&b| live_builders[b]);
        if producer_is_live || live_read_cols[col] {
            virtual_cols[col] = true;
            num_virtual += 1;
        } else {
            num_fully_dead += 1;
        }
    }

    debug!(
        "Column removal: {} dead cols total, {} fully dead (producer dead), {} virtual (producer \
         live, computation-only)",
        num_removable, num_fully_dead, num_virtual
    );

    // Step 5: Build remap table with two regions:
    //   Real columns → [0, num_real)         (for R1CS matrices + builders)
    //   Virtual columns → [num_real, num_real+num_virtual) (for builders only)
    //   Fully dead columns → None            (no mapping, builders pruned)
    let mut remap: Vec<Option<usize>> = vec![None; num_cols];
    let mut next_real = 0usize;
    // First pass: assign real column indices
    for col in 0..num_cols {
        if !removable_cols[col] {
            remap[col] = Some(next_real);
            next_real += 1;
        }
    }
    let num_real = next_real;
    // Second pass: assign virtual column indices (after real)
    let mut next_virtual = num_real;
    for col in 0..num_cols {
        if virtual_cols[col] {
            remap[col] = Some(next_virtual);
            next_virtual += 1;
        }
    }
    assert_eq!(next_virtual - num_real, num_virtual);

    // Step 6: Remap R1CS matrices — only uses [0, num_real) columns.
    // Virtual columns had zero entries so remove_columns drops them cleanly.
    let matrix_remap: Vec<Option<usize>> = (0..num_cols)
        .map(|col| {
            if removable_cols[col] {
                None // Remove from matrices (both virtual and fully dead)
            } else {
                remap[col] // Real column → compact index
            }
        })
        .collect();
    // A, B, C removal is independent — parallelize for large matrices.
    let (new_a, (new_b, new_c)) = rayon::join(
        || r1cs.a.remove_columns(&matrix_remap),
        || {
            rayon::join(
                || r1cs.b.remove_columns(&matrix_remap),
                || r1cs.c.remove_columns(&matrix_remap),
            )
        },
    );
    r1cs.a = new_a?;
    r1cs.b = new_b?;
    r1cs.c = new_c?;

    // Step 6b: Remap ACIR witness map (ACIR index -> R1CS column)
    for entry in witness_map.iter_mut() {
        if let Some(nz) = entry {
            let old_col = nz.get() as usize;
            match remap[old_col] {
                Some(new_col) => {
                    let Some(new_nz) = std::num::NonZeroU32::new(new_col as u32) else {
                        bail!("ACIR witness col {old_col} remapped to 0 (constant-one column)");
                    };
                    *entry = Some(new_nz);
                }
                None => {
                    *entry = None;
                }
            }
        }
    }

    // Step 7: Prune dead builders and remap surviving ones.
    // A builder must be kept if it's live OR if it produces any virtual column
    // (needed for computation even though its outputs are zero in A/B/C).
    let mut keep_builders = live_builders.clone();
    for col in 0..num_cols {
        if virtual_cols[col] {
            if let Some(&producer_idx) = col_to_builder.get(&col) {
                keep_builders[producer_idx] = true;
            } else {
                // Virtual columns must have a producer in col_to_builder.
                // Columns without producers (col 0, public inputs) are
                // excluded from dead_cols/removable_cols at Step 1.
                bail!(
                    "Virtual column {col} has no producer in col_to_builder — this should be \
                     unreachable because col 0 and public inputs are never classified as dead"
                );
            }
        }
    }
    let builders_before = witness_builders.len();
    // Build the remapper ONCE (not per-builder) to avoid repeated HashMap
    // construction from the 1M+ entry remap table.
    let remapper = {
        use provekit_backend_bn254::witness::WitnessIndexRemapper;
        let old_to_new: HashMap<usize, usize> = remap
            .iter()
            .enumerate()
            .filter_map(|(old, new)| new.map(|n| (old, n)))
            .collect();
        WitnessIndexRemapper::from_map(old_to_new)
    };
    let num_kept = keep_builders.iter().filter(|&&b| b).count();
    let mut new_builders: Vec<WitnessBuilder> = Vec::with_capacity(num_kept);
    for (idx, builder) in witness_builders.drain(..).enumerate() {
        if keep_builders[idx] {
            new_builders.push(remapper.remap_builder(&builder));
        }
    }
    *witness_builders = new_builders;
    let builders_removed = builders_before - witness_builders.len();

    info!(
        "Column removal: {} -> {} real + {} virtual witnesses ({} total for solving), {} builders \
         pruned",
        num_cols,
        num_real,
        num_virtual,
        num_real + num_virtual,
        builders_removed
    );

    Ok(ColumnRemovalStats {
        witnesses_after: num_real,
        builders_removed,
        num_virtual,
    })
}

/// Per-row result of the parallel rebuild pass.
///
/// `PassThrough { src_row }` — no pivot occurred in this row, so the output
/// row is byte-for-byte identical to the source row at index `src_row` in
/// the *original* matrix. Finalization bulk-copies the source matrix's
/// `col_indices` and `values` slices directly; no dehydrate, no arithmetic,
/// no re-intern.
///
/// `Substituted(entries)` — at least one pivot expanded into substitution
/// terms. Values are raw `FieldElement`s (sorted by column, duplicates
/// merged, zeros dropped) and must be interned during finalization.
enum RebuiltRow {
    PassThrough { src_row: usize },
    Substituted(Vec<(u32, FieldElement)>),
}

/// Classify and compute new entries for every survivor row, in parallel.
/// Reads only from `&Interner` — safe to share across A/B/C and across rows.
fn rebuild_matrix_rows(
    matrix: &SparseMatrix,
    matrix_name: &'static str,
    interner: &Interner,
    substitutions: &[Substitution],
    sub_lookup: &[u32],
    survivors: &[usize],
) -> Result<Vec<RebuiltRow>> {
    survivors
        .par_iter()
        .map(|&row| -> Result<RebuiltRow> {
            let (row_cols, row_vals) = matrix.row_slices(row);

            let has_pivot = row_cols.iter().any(|&c| sub_lookup[c as usize] != u32::MAX);
            if !has_pivot {
                return Ok(RebuiltRow::PassThrough { src_row: row });
            }

            // Slow path: expand pivot terms, sort, merge.
            let mut expanded_len = 0usize;
            for &col in row_cols {
                let sub_idx = sub_lookup[col as usize];
                if sub_idx == u32::MAX {
                    expanded_len += 1;
                } else {
                    expanded_len += substitutions[sub_idx as usize].terms.len();
                }
            }

            let mut expanded: Vec<(u32, FieldElement)> = Vec::with_capacity(expanded_len);
            for (&col, &iv) in row_cols.iter().zip(row_vals.iter()) {
                let val = interner.get(iv).with_context(|| {
                    format!(
                        "interned value missing during GE substitution at matrix {matrix_name} \
                         row {row} col {col}"
                    )
                })?;
                let sub_idx = sub_lookup[col as usize];
                if sub_idx == u32::MAX {
                    expanded.push((col, val));
                } else {
                    let sub = &substitutions[sub_idx as usize];
                    for (sub_coeff, sub_col) in &sub.terms {
                        expanded.push((*sub_col as u32, val * sub_coeff));
                    }
                }
            }

            expanded.sort_unstable_by_key(|&(c, _)| c);

            let mut merged: Vec<(u32, FieldElement)> = Vec::with_capacity(expanded.len());
            let flush = |col: u32, val: FieldElement, dst: &mut Vec<(u32, FieldElement)>| {
                if !val.is_zero() {
                    dst.push((col, val));
                }
            };
            let mut iter = expanded.into_iter();
            if let Some((mut cur_col, mut cur_val)) = iter.next() {
                for (c, v) in iter {
                    if c == cur_col {
                        cur_val += v;
                    } else {
                        flush(cur_col, cur_val, &mut merged);
                        cur_col = c;
                        cur_val = v;
                    }
                }
                flush(cur_col, cur_val, &mut merged);
            }
            Ok(RebuiltRow::Substituted(merged))
        })
        .collect()
}

/// Assemble a `SparseMatrix` from parallel-computed rows.
///
/// `PassThrough` rows are bulk-copied from the source matrix's raw slices.
/// `Substituted` rows pay the per-value `intern` cost. Sequential because
/// `Interner::intern` mutates the dedup table.
fn finalize_matrix(
    rows: Vec<RebuiltRow>,
    source: &SparseMatrix,
    num_cols: usize,
    interner: &mut Interner,
) -> SparseMatrix {
    let num_rows = rows.len();
    let total_entries: usize = rows
        .iter()
        .map(|r| match r {
            RebuiltRow::PassThrough { src_row } => source.row_range(*src_row).len(),
            RebuiltRow::Substituted(entries) => entries.len(),
        })
        .sum();

    let mut new_row_indices = Vec::with_capacity(num_rows);
    let mut col_indices = Vec::with_capacity(total_entries);
    let mut values = Vec::with_capacity(total_entries);

    let src_cols = source.col_indices_raw();
    let src_vals = source.values_raw();

    for row in rows {
        new_row_indices.push(col_indices.len() as u32);
        match row {
            RebuiltRow::PassThrough { src_row } => {
                let range = source.row_range(src_row);
                col_indices.extend_from_slice(&src_cols[range.clone()]);
                values.extend_from_slice(&src_vals[range]);
            }
            RebuiltRow::Substituted(entries) => {
                for (c, v) in entries {
                    col_indices.push(c);
                    values.push(interner.intern(v));
                }
            }
        }
    }

    SparseMatrix::from_raw_parts(num_rows, num_cols, new_row_indices, col_indices, values)
}

#[cfg(test)]
mod tests {
    use {super::*, ark_std::One, provekit_backend_bn254::witness::SumTerm};

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
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(None, 1), SumTerm(None, 2)]),
            WitnessBuilder::Product(4, 1, 2),
        ];

        assert_eq!(r1cs.num_constraints(), 2);

        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut witness_builders, &mut wmap, &HashSet::new()).unwrap()
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
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(Some(neg), 0), SumTerm(None, 1)]),
            WitnessBuilder::Sum(4, vec![SumTerm(Some(neg), 0), SumTerm(None, 3)]),
            WitnessBuilder::Product(5, 4, 2),
        ];

        assert_eq!(r1cs.num_constraints(), 3);
        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap, &HashSet::new()).unwrap()
        };

        // Both linear constraints eliminated, Q remains
        assert_eq!(stats.eliminated, 2);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(r1cs.num_constraints(), 1);

        // After Phase 4b: Sum(4) is rewritten to inline w3's substitution
        // (-1·w0 + 1·w1), so it no longer reads w3.  Sum(3) (producer of w3)
        // has no live consumers left → dead → w3 fully removed.
        // w4 is dead in constraints (GE substituted it out) but Sum(4) still
        // produces it and Product(5) reads it → w4 becomes virtual.
        // Expected: 6 → 4 real witnesses (w3 fully removed, w4 virtual).
        assert_eq!(
            stats.witnesses_after,
            stats.witnesses_before - 2,
            "Expected 2 witnesses removed from R1CS (w3 dead, w4 virtual), got {} -> {}",
            stats.witnesses_before,
            stats.witnesses_after
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
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
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
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap, &HashSet::new()).unwrap()
        };

        // Both linear constraints eliminated, Q1, Q2, Q3 remain
        assert_eq!(stats.eliminated, 2);
        assert_eq!(stats.constraints_after, 3);

        // Pivot columns w3, w5 are dead in constraints (GE substituted
        // them out) but their producers are still live (downstream builders
        // read them) → they become virtual witnesses.
        // Expected: 9 → 7 real witnesses (w3 and w5 become virtual).
        assert_eq!(
            stats.witnesses_after,
            stats.witnesses_before - 2,
            "Expected 2 virtual witnesses (w3, w5), got {} -> {}",
            stats.witnesses_before,
            stats.witnesses_after
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

    /// Helper: verify A·w ⊙ B·w == C·w for all constraints.
    fn assert_r1cs_satisfied(r1cs: &R1CS, witness: &[FieldElement]) {
        let interner = &r1cs.interner;
        for row in 0..r1cs.num_constraints() {
            let dot = |matrix: &SparseMatrix| -> FieldElement {
                let mut acc = FieldElement::zero();
                for (col, interned_val) in matrix.iter_row(row) {
                    assert!(
                        col < witness.len(),
                        "Row {row}: column index {col} out of range (witness len {})",
                        witness.len()
                    );
                    let val = interner.get(interned_val).unwrap();
                    acc += val * witness[col];
                }
                acc
            };
            let a_dot = dot(&r1cs.a);
            let b_dot = dot(&r1cs.b);
            let c_dot = dot(&r1cs.c);
            assert_eq!(
                a_dot * b_dot,
                c_dot,
                "Constraint {row} not satisfied: A·w * B·w != C·w"
            );
        }
    }

    fn solve_basic_builders(
        builders: &[WitnessBuilder],
        acir_values: &[FieldElement],
        num_total: usize,
    ) -> Vec<FieldElement> {
        let mut witness = vec![FieldElement::zero(); num_total];
        for builder in builders {
            match builder {
                WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(
                    idx,
                    val,
                )) => {
                    witness[*idx] = *val;
                }
                WitnessBuilder::Acir(idx, acir_idx) => {
                    witness[*idx] = acir_values[*acir_idx];
                }
                WitnessBuilder::Sum(idx, terms) => {
                    let mut acc = FieldElement::zero();
                    for term in terms {
                        let coeff = term.0.unwrap_or(FieldElement::one());
                        acc += coeff * witness[term.1];
                    }
                    witness[*idx] = acc;
                }
                WitnessBuilder::Product(idx, a, b) => {
                    witness[*idx] = witness[*a] * witness[*b];
                }
                other => panic!(
                    "Unexpected builder type in test: {other:?}. If a new variant was added, \
                     extend this helper or use the real solver from provekit-prover."
                ),
            }
        }
        witness
    }

    #[test]
    fn test_arithmetic_correctness() {
        // Verify optimized R1CS is semantically equivalent to original.
        // w0=1 (constant), w1=3 (public), w2=5 (public), w3=w1+w2=8,
        // w4=w1*w2=15, w5=w3+w4=23
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();

        r1cs.add_witnesses(6);
        r1cs.num_public_inputs = 2;

        // L0: 1*w3 = w1 + w2  →  w3 = w1 + w2 (linear: B is constant)
        r1cs.add_constraint(&[(one, 0)], &[(one, 3)], &[(one, 1), (one, 2)]);
        // L1: 1*w5 = w3 + w4  →  w5 = w3 + w4 (linear: A is constant)
        r1cs.add_constraint(&[(one, 0)], &[(one, 5)], &[(one, 3), (one, 4)]);
        // Q: w1 * w2 = w4 (non-linear, kept)
        r1cs.add_constraint(&[(one, 1)], &[(one, 2)], &[(one, 4)]);

        // Witness: w0=1, w1=3, w2=5, w3=8, w4=15, w5=23
        let witness_vals: Vec<FieldElement> = [1u64, 3, 5, 8, 15, 23]
            .iter()
            .map(|&v| FieldElement::from(v))
            .collect();

        // Verify original R1CS is satisfied
        assert_r1cs_satisfied(&r1cs, &witness_vals);

        let mut builders = vec![
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(None, 1), SumTerm(None, 2)]),
            WitnessBuilder::Product(4, 1, 2),
            WitnessBuilder::Sum(5, vec![SumTerm(None, 3), SumTerm(None, 4)]),
        ];

        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap, &HashSet::new()).unwrap()
        };

        assert_eq!(stats.eliminated, 2, "Should eliminate 2 linear constraints");
        assert_eq!(r1cs.num_constraints(), 1, "Should have 1 constraint left");

        // Verify column indices are in bounds.
        let num_cols = r1cs.num_witnesses();
        for row in 0..r1cs.num_constraints() {
            for (col, _) in r1cs.a.iter_row(row) {
                assert!(col < num_cols, "A col {col} out of range {num_cols}");
            }
            for (col, _) in r1cs.b.iter_row(row) {
                assert!(col < num_cols, "B col {col} out of range {num_cols}");
            }
            for (col, _) in r1cs.c.iter_row(row) {
                assert!(col < num_cols, "C col {col} out of range {num_cols}");
            }
        }

        // Solve all builders to produce the optimized witness, then verify
        // the optimized R1CS is actually satisfied.
        let acir_values: Vec<FieldElement> = witness_vals[1..=2].to_vec();
        let opt_witness = solve_basic_builders(
            &builders,
            &acir_values,
            r1cs.num_witnesses() + r1cs.num_virtual,
        );

        assert_r1cs_satisfied(&r1cs, &opt_witness);
    }

    #[test]
    fn test_deep_chain_elimination() {
        // Chain of depth 4: L0→L1→L2→L3→Q. Exercises transitive chain
        // resolution at a depth beyond what test_chained_linear_elimination
        // (depth 2) covers — catches off-by-one or infinite-loop bugs.
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg = -one;

        r1cs.add_witnesses(8);

        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 1), (neg, 3)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 3), (neg, 4)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 4), (neg, 5)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 5), (neg, 6)]);
        r1cs.add_constraint(&[(one, 6)], &[(one, 2)], &[(one, 7)]);

        let mut builders = vec![
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
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
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap, &HashSet::new()).unwrap()
        };

        assert_eq!(stats.eliminated, 4);
        assert_eq!(stats.constraints_after, 1);

        let acir_values: Vec<FieldElement> = [5u64, 7u64]
            .iter()
            .map(|&v| FieldElement::from(v))
            .collect();
        let opt_witness = solve_basic_builders(
            &builders,
            &acir_values,
            r1cs.num_witnesses() + r1cs.num_virtual,
        );
        assert_r1cs_satisfied(&r1cs, &opt_witness);
    }

    #[test]
    fn test_dead_acir_witnesses_are_removed() {
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg = -one;

        // 5 columns: w0(const), w1(public/acir live), w2(dead acir),
        // w3(derived), w4(output)
        r1cs.add_witnesses(5);
        r1cs.num_public_inputs = 1;

        // L0: 1*1 = w1 - w3
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 1), (neg, 3)]);
        // Q: w3 * w1 = w4
        r1cs.add_constraint(&[(one, 3)], &[(one, 1)], &[(one, 4)]);

        let mut builders = vec![
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(Some(neg), 0), SumTerm(None, 1)]),
            WitnessBuilder::Product(4, 3, 1),
        ];
        let mut witness_map = vec![std::num::NonZeroU32::new(1), std::num::NonZeroU32::new(2)];

        let stats = optimize_r1cs(
            &mut r1cs,
            &mut builders,
            &mut witness_map,
            &HashSet::from([0u32]),
        )
        .unwrap();

        assert_eq!(stats.witnesses_after, 3);
        assert_eq!(stats.num_virtual, 1);
        assert_eq!(witness_map[0].map(|v| v.get()), Some(1));
        assert_eq!(witness_map[1], None);
        assert!(
            !builders
                .iter()
                .any(|builder| matches!(builder, WitnessBuilder::Acir(_, 1))),
            "Dead ACIR builder should be pruned"
        );

        let acir_values: Vec<FieldElement> = [5u64, 9u64]
            .iter()
            .map(|&v| FieldElement::from(v))
            .collect();
        let opt_witness = solve_basic_builders(
            &builders,
            &acir_values,
            r1cs.num_witnesses() + r1cs.num_virtual,
        );
        assert_r1cs_satisfied(&r1cs, &opt_witness);
    }

    #[test]
    fn test_public_input_linear_constraint_is_not_eliminated_when_count_is_unset() {
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let six = FieldElement::from(6u64);

        // w0 = 1, w1 = public ACIR input
        r1cs.add_witnesses(2);
        // Public equality: w1 - 6 = 0
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 1), (-six, 0)]);

        let mut builders = vec![
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 1),
        ];
        let mut witness_map = vec![None, std::num::NonZeroU32::new(1)];

        let stats = optimize_r1cs(
            &mut r1cs,
            &mut builders,
            &mut witness_map,
            &HashSet::from([1u32]),
        )
        .unwrap();

        assert_eq!(
            stats.eliminated, 0,
            "public input row must not be pivoted away"
        );
        assert_eq!(
            r1cs.num_constraints(),
            1,
            "public-input equality must remain verifier-visible"
        );
        assert_eq!(r1cs.num_witnesses(), 2, "public input column must remain");
    }

    #[test]
    fn test_branch_coverage() {
        // Exercises all extract_linear_expression branches:
        //   L_a:    A=[2*w0],   B=[w2],    C=[w3]       A-only const
        //   L_b:    A=[w4,w2],  B=[3*w0],  C=[w5]       B-only const
        //   L_sr0:  A=[w0],     B=[w0],    C=[2*w6,-w7]  both const
        //   L_sr1:  A=[w0],     B=[w0],    C=[w7,-w6]    self-ref rescaling
        //   L_deg0: A=[w0],     B=[w0],    C=[w8,-w9]    both const
        //   L_deg1: A=[w0],     B=[w0],    C=[w8,-w9]    degenerate (1-r_p=0)
        //   Q:      A=[w4],     B=[w7],    C=[w10]       non-linear
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg = -one;
        let two = FieldElement::from(2u64);
        let three = FieldElement::from(3u64);

        r1cs.add_witnesses(11);

        r1cs.add_constraint(&[(two, 0)], &[(one, 2)], &[(one, 3)]);
        r1cs.add_constraint(&[(one, 4), (one, 2)], &[(three, 0)], &[(one, 5)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(two, 6), (neg, 7)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 7), (neg, 6)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 8), (neg, 9)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 8), (neg, 9)]);
        r1cs.add_constraint(&[(one, 4)], &[(one, 7)], &[(one, 10)]);

        let witness: Vec<FieldElement> = [1u64, 5, 4, 8, 5, 27, 2, 3, 11, 10, 15]
            .iter()
            .map(|v| FieldElement::from(*v))
            .collect();
        assert_r1cs_satisfied(&r1cs, &witness);

        let mut builders = vec![
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(Some(two), 2)]),
            WitnessBuilder::Acir(4, 2),
            WitnessBuilder::Sum(5, vec![SumTerm(Some(three), 4), SumTerm(Some(three), 2)]),
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(6, two)),
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(7, three)),
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(
                8,
                FieldElement::from(11u64),
            )),
            WitnessBuilder::Constant(provekit_backend_bn254::witness::ConstantTerm(
                9,
                FieldElement::from(10u64),
            )),
            WitnessBuilder::Product(10, 4, 7),
        ];

        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap, &HashSet::new()).unwrap()
        };

        // 5 eliminated: L_a(w3), L_b(w5), L_sr0(w6), L_sr1(w7),
        // L_deg0(w8 or w9). L_deg1 skipped (degenerate). Q non-linear.
        assert_eq!(stats.eliminated, 5);
        assert_eq!(stats.constraints_after, 2);
    }
}
