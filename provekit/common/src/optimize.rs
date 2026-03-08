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
    ark_ff::Field,
    ark_std::{One, Zero},
    std::collections::{HashMap, HashSet},
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
    pub constraints_before: usize,
    pub constraints_after:  usize,
    pub witnesses_before:   usize,
    pub witnesses_after:    usize,
    pub eliminated:         usize,
    pub builders_removed:   usize,
    pub builders_rewritten: usize,
    pub new_sum_builders:   usize,
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

    // Phase 4b: Rewrite witness builders to sever dependency chains.
    // Currently disabled — Sum/SpreadBitExtract inlining can cause
    // witness scheduling violations when substitution terms reference
    // columns computed later in the builder schedule. Requires
    // scheduling-aware cycle detection to enable safely.
    // TODO(rs): Re-enable with proper topological ordering check.

    // Phase 5: Remove dead witness columns and prune unreachable builders
    let (witnesses_after, builders_removed) =
        remove_dead_columns(r1cs, witness_builders, witness_map);

    let stats = OptimizationStats {
        constraints_before,
        constraints_after,
        witnesses_before,
        witnesses_after,
        eliminated,
        builders_removed,
        builders_rewritten: 0,
        new_sum_builders: 0,
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
        witnesses_after,
        stats.witness_reduction_percent(),
        builders_removed
    );

    stats
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
///
/// Returns (new_witness_count, builders_removed_count).
fn remove_dead_columns(
    r1cs: &mut R1CS,
    witness_builders: &mut Vec<WitnessBuilder>,
    witness_map: &mut [Option<std::num::NonZeroU32>],
) -> (usize, usize) {
    let num_cols = r1cs.num_witnesses();
    if num_cols == 0 || witness_builders.is_empty() {
        return (num_cols, 0);
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
        return (num_cols, 0);
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
        return (num_cols, 0);
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

    (new_num_cols, builders_removed)
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
}