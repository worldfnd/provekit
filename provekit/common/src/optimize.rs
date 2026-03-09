//! Gaussian elimination optimization pass for R1CS.
//!
//! Inspired by Circom's `-O2` substitution-based sparse elimination:
//!   1. Identify linear constraints (where A or B is constant)
//!   2. For each linear constraint, pick a pivot variable (fewest occurrences,
//!      not forbidden)
//!   3. Express pivot as linear combination of remaining variables
//!   4. Substitute into all other constraints
//!   5. Remove eliminated constraints

use {
    crate::{witness::WitnessBuilder, FieldElement, InternedFieldElement, SparseMatrix, R1CS},
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
    _witness_builders: &mut [WitnessBuilder],
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

    // Note: We do NOT modify witness builders. The witnesses are still
    // computed by their original builders. GE only removes redundant
    // constraints and substitutes pivots into remaining constraints.

    let constraints_after = r1cs.num_constraints();
    let eliminated = substitutions.len();

    // witnesses_after = witnesses_before since we don't actually remove columns,
    // just make some witnesses derived. The column count doesn't change.
    let witnesses_after = witnesses_before;

    let stats = OptimizationStats {
        constraints_before,
        constraints_after,
        witnesses_before,
        witnesses_after,
        eliminated,
    };

    info!(
        "Gaussian elimination: {} -> {} constraints ({:.1}% reduction), {} substitutions",
        constraints_before,
        constraints_after,
        stats.constraint_reduction_percent(),
        eliminated
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

    /// Evaluate `matrix · witness` for each row, returning a Vec of
    /// FieldElements (one per constraint).
    fn matvec(r1cs: &R1CS, matrix: &SparseMatrix, witness: &[FieldElement]) -> Vec<FieldElement> {
        let hydrated = matrix.hydrate(&r1cs.interner);
        (0..matrix.num_rows)
            .map(|row| {
                hydrated
                    .iter_row(row)
                    .map(|(col, coeff)| coeff * witness[col])
                    .sum()
            })
            .collect()
    }

    /// Assert that `A·w ⊙ B·w == C·w` for every row of the R1CS.
    fn assert_r1cs_satisfied(r1cs: &R1CS, witness: &[FieldElement]) {
        let a_vals = matvec(r1cs, &r1cs.a, witness);
        let b_vals = matvec(r1cs, &r1cs.b, witness);
        let c_vals = matvec(r1cs, &r1cs.c, witness);
        for (row, ((a, b), c)) in a_vals
            .iter()
            .zip(b_vals.iter())
            .zip(c_vals.iter())
            .enumerate()
        {
            assert_eq!(
                *a * *b,
                *c,
                "R1CS not satisfied at row {row}: A·w={a:?}, B·w={b:?}, C·w={c:?}"
            );
        }
    }

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

        let stats = optimize_r1cs(&mut r1cs, &mut witness_builders);

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
        let stats = optimize_r1cs(&mut r1cs, &mut builders);

        // Both linear constraints eliminated, Q remains
        assert_eq!(stats.eliminated, 2);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(r1cs.num_constraints(), 1);

        // w3 (S0 pivot) must NOT appear in the remaining constraint.
        // This is the key chain-resolution check: without the fix, S1's
        // substitution of w4 would introduce w3 into Q.
        for (col, _) in r1cs.a.iter_row(0) {
            assert!(
                col != 3,
                "A matrix references eliminated pivot w3 (chain resolution failed)"
            );
            assert!(col != 4, "A matrix references eliminated pivot w4");
        }
        for (col, _) in r1cs.b.iter_row(0) {
            assert!(
                col != 3,
                "B matrix references eliminated pivot w3 (chain resolution failed)"
            );
            assert!(col != 4, "B matrix references eliminated pivot w4");
        }
        for (col, _) in r1cs.c.iter_row(0) {
            assert!(
                col != 3,
                "C matrix references eliminated pivot w3 (chain resolution failed)"
            );
            assert!(col != 4, "C matrix references eliminated pivot w4");
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
        let stats = optimize_r1cs(&mut r1cs, &mut builders);

        // All 4 linear constraints eliminated, Q remains
        assert_eq!(stats.eliminated, 4);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(r1cs.num_constraints(), 1);

        // No eliminated pivot (w3, w4, w5, w6) should appear in Q
        let eliminated = [3usize, 4, 5, 6];
        for (col, _) in r1cs.a.iter_row(0) {
            assert!(
                !eliminated.contains(&col),
                "A matrix references eliminated pivot w{col} (depth-4 chain)"
            );
        }
        for (col, _) in r1cs.b.iter_row(0) {
            assert!(
                !eliminated.contains(&col),
                "B matrix references eliminated pivot w{col} (depth-4 chain)"
            );
        }
        for (col, _) in r1cs.c.iter_row(0) {
            assert!(
                !eliminated.contains(&col),
                "C matrix references eliminated pivot w{col} (depth-4 chain)"
            );
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
        let stats = optimize_r1cs(&mut r1cs, &mut builders);

        // Both linear constraints eliminated, Q1, Q2, Q3 remain
        assert_eq!(stats.eliminated, 2);
        assert_eq!(stats.constraints_after, 3);

        // Neither w3 nor w5 (eliminated pivots) should appear in any
        // remaining constraint. w5 tests the backward chain: S_0's
        // terms originally referenced w5, resolved by Phase 2b.
        let eliminated = [3usize, 5];
        for row in 0..r1cs.num_constraints() {
            for (col, _) in r1cs.a.iter_row(row) {
                assert!(
                    !eliminated.contains(&col),
                    "row {row} A references eliminated pivot w{col} (backward chain)"
                );
            }
            for (col, _) in r1cs.b.iter_row(row) {
                assert!(
                    !eliminated.contains(&col),
                    "row {row} B references eliminated pivot w{col} (backward chain)"
                );
            }
            for (col, _) in r1cs.c.iter_row(row) {
                assert!(
                    !eliminated.contains(&col),
                    "row {row} C references eliminated pivot w{col} (backward chain)"
                );
            }
        }
    }

    #[test]
    fn test_arithmetic_correctness() {
        // Exercises simple elimination, forward chain, and backward chain
        // then checks A·w ⊙ B·w == C·w on optimized R1CS.
        //
        //   L0: 1*1 = w1 + w5 - w3   (linear, pivot w3)
        //   L1: 1*1 = w4 - w5        (linear, pivot w5)
        //   Q1: w3 * w2 = w6         (non-linear)
        //   Q2: w4 * w4 = w7         (non-linear)
        //   Q3: w5 * w1 = w8         (non-linear)
        //
        // L0's terms reference w5 (backward ref to L1's pivot).
        // After full resolution: w5 = w4-1, w3 = w1+w4-2.
        let mut r1cs = R1CS::new();
        let one = FieldElement::one();
        let neg = -one;

        // 9 columns: w0(const), w1(pub), w2(pub), w3..w8
        r1cs.add_witnesses(9);
        r1cs.num_public_inputs = 2;

        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 1), (one, 5), (neg, 3)]);
        r1cs.add_constraint(&[(one, 0)], &[(one, 0)], &[(one, 4), (neg, 5)]);
        r1cs.add_constraint(&[(one, 3)], &[(one, 2)], &[(one, 6)]);
        r1cs.add_constraint(&[(one, 4)], &[(one, 4)], &[(one, 7)]);
        r1cs.add_constraint(&[(one, 5)], &[(one, 1)], &[(one, 8)]);

        // w0=1, w1=5, w2=3, w4=7, w5=w4-1=6, w3=w1+w5-1=10,
        // w6=w3*w2=30, w7=w4*w4=49, w8=w5*w1=30
        let witness: Vec<FieldElement> = [1u64, 5, 3, 10, 7, 6, 30, 49, 30]
            .iter()
            .map(|v| FieldElement::from(*v))
            .collect();

        assert_r1cs_satisfied(&r1cs, &witness);

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

        let stats = optimize_r1cs(&mut r1cs, &mut builders);
        assert_eq!(stats.eliminated, 2);
        assert_r1cs_satisfied(&r1cs, &witness);
    }
}
