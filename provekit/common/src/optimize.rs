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
        witness::{DependencyInfo, WitnessBuilder},
        FieldElement, InternedFieldElement, SparseMatrix, R1CS,
    },
    anyhow::{bail, Context as _, Result},
    ark_ff::Field,
    ark_std::{One, Zero},
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
) -> Result<OptimizationStats> {
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
        )?;
        apply_substitutions_to_row(
            &mut r1cs.b,
            row,
            &substitutions,
            &sub_map,
            &mut r1cs.interner,
        )?;
        apply_substitutions_to_row(
            &mut r1cs.c,
            row,
            &substitutions,
            &sub_map,
            &mut r1cs.interner,
        )?;
    }

    // Phase 4: Remove eliminated constraint rows
    eliminated_rows.sort();
    r1cs.remove_constraints(&eliminated_rows);

    let constraints_after = r1cs.num_constraints();
    let eliminated = substitutions.len();

    debug!(
        "Phase 3 done: {} constraints remaining after substitution",
        constraints_after
    );

    // Phase 5: Remove dead witness columns and prune unreachable builders
    debug!("Phase 5: starting dead column removal + virtual witness assignment");
    let col_stats = remove_dead_columns(r1cs, witness_builders, witness_map)?;
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
/// 3. Finds which builders are transitively reachable from "live" columns
///    (columns still referenced by constraints)
/// 4. Prunes unreachable builders (Phase B+C cascading)
/// 5. Remaps matrix column indices to close gaps
/// 6. Remaps remaining builder witness indices
fn remove_dead_columns(
    r1cs: &mut R1CS,
    witness_builders: &mut Vec<WitnessBuilder>,
    witness_map: &mut [Option<std::num::NonZeroU32>],
) -> Result<ColumnRemovalStats> {
    let num_cols = r1cs.num_witnesses();
    if num_cols == 0 || witness_builders.is_empty() {
        return Ok(ColumnRemovalStats {
            witnesses_after:  num_cols,
            builders_removed: 0,
            num_virtual:      0,
        });
    }

    // Step 1: Find dead columns (zero occurrence across A, B, C)
    // Also collect columns referenced by the ACIR witness map — these are
    // entry points for witness data and must stay alive.
    let occurrence_counts = build_occurrence_counts(r1cs);
    let mut acir_referenced = vec![false; num_cols];
    for entry in witness_map.iter() {
        if let Some(nz) = entry {
            acir_referenced[nz.get() as usize] = true;
        }
    }

    let mut dead_cols = vec![false; num_cols];
    let mut num_dead = 0usize;
    for col in 0..num_cols {
        // Never remove column 0 (constant one) or public input columns
        if col == 0 || col <= r1cs.num_public_inputs {
            continue;
        }
        // Never remove columns referenced by the ACIR witness map
        if acir_referenced[col] {
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

    // Diagnostic: count how many zero-occurrence cols are blocked by each mechanism
    let zero_occ_total = (0..num_cols)
        .filter(|&c| c > r1cs.num_public_inputs && occurrence_counts[c] == 0)
        .count();
    let blocked_by_acir = (0..num_cols)
        .filter(|&c| {
            c > r1cs.num_public_inputs && occurrence_counts[c] == 0 && acir_referenced[c]
        })
        .count();
    debug!(
        "Column removal: {} zero-occurrence cols (excl public), {} blocked by ACIR witness map, \
         {} truly dead",
        zero_occ_total,
        blocked_by_acir,
        num_dead
    );

    debug!(
        "Column removal: {} dead columns found out of {} total",
        num_dead,
        num_cols
    );

    // Step 2: Build witness builder dependency graph and find reachable builders.
    // A builder is "live" if any of its output columns is NOT dead, OR if a
    // live builder reads any of its output columns.

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
    let mut live_builders = vec![false; witness_builders.len()];
    let mut num_live_builders = 0usize;
    let mut queue: Vec<usize> = Vec::new();

    for (builder_idx, builder) in witness_builders.iter().enumerate() {
        let writes = DependencyInfo::extract_writes(builder);
        let is_directly_live = writes.iter().any(|c| !dead_cols[*c]);
        if is_directly_live {
            live_builders[builder_idx] = true;
            num_live_builders += 1;
            queue.push(builder_idx);
        }
    }

    // BFS: if a live builder reads from another builder, that builder is also live
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

    let blocked_by_bfs = (0..num_cols)
        .filter(|&col| {
            dead_cols[col]
                && col_to_builder
                    .get(&col)
                    .map_or(false, |&b| live_builders[b])
        })
        .count();

    // Detailed diagnostic breakdowns (reader types, producer types,
    // hypothetical analyses) are disabled for performance — they are
    // O(dead_cols × graph_size) and blow up on large circuits. Enable
    // selectively when debugging a specific circuit.
    //
    // See git history for the full diagnostic block.

    debug!(
        "Column removal: of {} dead cols, {} blocked by live builder BFS, {} removable",
        num_dead,
        blocked_by_bfs,
        num_dead - blocked_by_bfs
    );

    // Step 4: Dead columns are removable from R1CS matrices — BUT we must
    // protect multi-output builders whose output ranges must stay contiguous.
    // If ANY column in a multi-output builder's range is live (non-dead),
    // ALL columns in that range must stay real to preserve the contiguous
    // output_start + num_witnesses layout.
    // Protect contiguous-range multi-output builders. Builders with
    // individually-addressed outputs don't need protection:
    //   - U32Addition/Multi, BytePartition: independent index fields
    //   - ChunkDecompose, SpreadBitExtract: output_indices Vec
    //   - DigitalDecomposition: output_indices Vec
    let mut protected_cols = vec![false; num_cols];
    for builder in witness_builders.iter() {
        let writes = DependencyInfo::extract_writes(builder);
        if writes.len() <= 1 {
            continue;
        }
        if matches!(
            builder,
            WitnessBuilder::U32Addition(..)
                | WitnessBuilder::U32AdditionMulti(..)
                | WitnessBuilder::BytePartition { .. }
                | WitnessBuilder::ChunkDecompose { .. }
                | WitnessBuilder::SpreadBitExtract { .. }
                | WitnessBuilder::DigitalDecomposition(..)
        ) {
            continue;
        }
        let has_live = writes.iter().any(|c| !dead_cols[*c]);
        if has_live && writes.iter().any(|c| dead_cols[*c]) {
            for &c in &writes {
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
    for (bi, b) in witness_builders.iter().enumerate() {
        if live_builders[bi] {
            for c in DependencyInfo::extract_reads(b) {
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
        num_removable,
        num_fully_dead,
        num_virtual
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
    r1cs.a = new_a;
    r1cs.b = new_b;
    r1cs.c = new_c;

    // Step 6b: Remap ACIR witness map (ACIR index -> R1CS column)
    for entry in witness_map.iter_mut() {
        if let Some(nz) = entry {
            let old_col = nz.get() as usize;
            let Some(new_col) = remap[old_col] else {
                bail!(
                    "ACIR witness map references removed column {old_col} (should be live)"
                );
            };
            let Some(new_nz) = std::num::NonZeroU32::new(new_col as u32) else {
                bail!(
                    "ACIR witness col {old_col} remapped to 0 (constant-one column)"
                );
            };
            *nz = new_nz;
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
            }
        }
    }
    let builders_before = witness_builders.len();
    // Build the remapper ONCE (not per-builder) to avoid repeated HashMap
    // construction from the 1M+ entry remap table.
    let remapper = {
        use crate::witness::WitnessIndexRemapper;
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
) -> Result<()> {
    let entries = matrix.get_row_entries(row);

    // Check if any entry references a pivot column
    let has_pivot = entries.iter().any(|(col, _)| sub_map.contains_key(col));
    if !has_pivot {
        return Ok(());
    }

    // Accumulate new row as HashMap<col, FieldElement>
    let mut new_entries: HashMap<usize, FieldElement> = HashMap::new();

    for (col, interned_val) in &entries {
        let val = interner
            .get(*interned_val)
            .context("interned value missing during constraint substitution")?;

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
    Ok(())
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
            optimize_r1cs(&mut r1cs, &mut witness_builders, &mut wmap).unwrap()
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
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap).unwrap()
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
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap).unwrap()
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
            let dot = |matrix: &crate::SparseMatrix| -> FieldElement {
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
            WitnessBuilder::Constant(crate::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(None, 1), SumTerm(None, 2)]),
            WitnessBuilder::Product(4, 1, 2),
            WitnessBuilder::Sum(5, vec![SumTerm(None, 3), SumTerm(None, 4)]),
        ];

        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap).unwrap()
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
        let num_total = r1cs.num_witnesses() + r1cs.num_virtual;
        let mut opt_witness = vec![FieldElement::zero(); num_total];
        let acir_values: Vec<FieldElement> = witness_vals[1..=2].to_vec();
        for b in &builders {
            match b {
                WitnessBuilder::Constant(crate::witness::ConstantTerm(idx, val)) => {
                    opt_witness[*idx] = *val;
                }
                WitnessBuilder::Acir(idx, acir_idx) => {
                    opt_witness[*idx] = acir_values[*acir_idx];
                }
                WitnessBuilder::Sum(idx, terms) => {
                    let mut acc = FieldElement::zero();
                    for term in terms {
                        let coeff = term.0.unwrap_or(FieldElement::one());
                        acc += coeff * opt_witness[term.1];
                    }
                    opt_witness[*idx] = acc;
                }
                WitnessBuilder::Product(idx, a, b) => {
                    opt_witness[*idx] = opt_witness[*a] * opt_witness[*b];
                }
                _ => panic!("Unexpected builder type in test"),
            }
        }

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
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap).unwrap()
        };

        assert_eq!(stats.eliminated, 4);
        assert_eq!(stats.constraints_after, 1);
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
            WitnessBuilder::Constant(crate::witness::ConstantTerm(0, one)),
            WitnessBuilder::Acir(1, 0),
            WitnessBuilder::Acir(2, 1),
            WitnessBuilder::Sum(3, vec![SumTerm(Some(two), 2)]),
            WitnessBuilder::Acir(4, 2),
            WitnessBuilder::Sum(5, vec![SumTerm(Some(three), 4), SumTerm(Some(three), 2)]),
            WitnessBuilder::Constant(crate::witness::ConstantTerm(6, two)),
            WitnessBuilder::Constant(crate::witness::ConstantTerm(7, three)),
            WitnessBuilder::Constant(crate::witness::ConstantTerm(
                8,
                FieldElement::from(11u64),
            )),
            WitnessBuilder::Constant(crate::witness::ConstantTerm(
                9,
                FieldElement::from(10u64),
            )),
            WitnessBuilder::Product(10, 4, 7),
        ];

        let stats = {
            let mut wmap = vec![];
            optimize_r1cs(&mut r1cs, &mut builders, &mut wmap).unwrap()
        };

        // 5 eliminated: L_a(w3), L_b(w5), L_sr0(w6), L_sr1(w7),
        // L_deg0(w8 or w9). L_deg1 skipped (degenerate). Q non-linear.
        assert_eq!(stats.eliminated, 5);
        assert_eq!(stats.constraints_after, 2);
    }
}
