use {
    super::MatrixBranchingProgram,
    ark_ff::{batch_inversion, Field},
    tracing::{info, instrument},
};

// Bound the search and workspace even when almost every coefficient differs.
const CANDIDATES_PER_SIDE: usize = 4;
const CANDIDATES: usize = 2 * CANDIDATES_PER_SIDE;
const MAX_SWEEPS: usize = 4;

/// Misra–Gries candidates, grouping coefficients up to sign. Exact scoring
/// below prevents approximate frequency estimates from accepting a regression.
#[derive(Clone)]
struct Frequent<F: Field> {
    values: [F; CANDIDATES_PER_SIDE],
    votes:  [usize; CANDIDATES_PER_SIDE],
}

impl<F: Field> Frequent<F> {
    fn new() -> Self {
        Self {
            values: [F::ZERO; CANDIDATES_PER_SIDE],
            votes:  [0; CANDIDATES_PER_SIDE],
        }
    }

    fn offer(&mut self, value: F) {
        let negative = -value;
        if let Some(index) = (0..CANDIDATES_PER_SIDE).find(|&i| {
            self.votes[i] != 0 && (self.values[i] == value || self.values[i] == negative)
        }) {
            self.votes[index] += 1;
        } else if let Some(index) = self.votes.iter().position(|&votes| votes == 0) {
            self.values[index] = value;
            self.votes[index] = 1;
        } else {
            for votes in &mut self.votes {
                *votes -= 1;
            }
        }
    }

    fn candidates(&self) -> impl Iterator<Item = F> + '_ {
        self.values
            .iter()
            .zip(&self.votes)
            .map(|(&value, &votes)| if votes == 0 { F::ZERO } else { value })
    }
}

impl<F: Field> MatrixBranchingProgram<F> {
    /// Improve the number of +/-1 coefficients without changing widths or
    /// support. At a cut, A_b -> A_b D and B_b -> D^-1 B_b for both branches.
    /// Only strict improvements across all four cores are accepted. This is
    /// bounded coordinate descent, not a globally optimal change of basis.
    /// Each sweep takes O(stored entries + widths) time with a fixed candidate
    /// count, and O(max width) workspace besides rebuilding one interned core.
    #[instrument(skip_all)]
    pub(super) fn rescale(&mut self) {
        let cuts = self.layers.len().saturating_sub(1);
        for sweep in 0..MAX_SWEEPS {
            let mut changed = 0;
            let mut improvement = 0;
            for index in 0..cuts {
                let cut = if sweep % 2 == 0 {
                    index
                } else {
                    cuts - 1 - index
                };
                let (coordinates, gain) = self.rescale_cut(cut);
                changed += coordinates;
                improvement += gain;
            }
            info!(
                "MBP rescaling sweep {}: {} coordinates changed; other count reduced by {}.",
                sweep + 1,
                changed,
                improvement
            );
            if changed == 0 {
                break;
            }
        }
    }

    fn rescale_cut(&mut self, cut: usize) -> (usize, usize) {
        let width = self.layers[cut].matrices[0].num_cols();
        let mut incoming = vec![Frequent::new(); width];
        let mut outgoing = vec![Frequent::new(); width];
        let mut baseline = vec![0usize; width];
        let mut has_other = false;
        for core in &self.layers[cut].matrices {
            for ((_, column), value) in core.iter() {
                incoming[column].offer(value);
                let unit = value == F::ONE || value == -F::ONE;
                baseline[column] += usize::from(unit);
                has_other |= !unit;
            }
        }
        for core in &self.layers[cut + 1].matrices {
            for ((row, _), value) in core.iter() {
                outgoing[row].offer(value);
                let unit = value == F::ONE || value == -F::ONE;
                baseline[row] += usize::from(unit);
                has_other |= !unit;
            }
        }
        if !has_other {
            return (0, 0);
        }

        // Incoming a becomes a*d, so propose d=1/a. Outgoing b becomes
        // b/d, so propose d=b. Signs do not affect the objective.
        let mut incoming_scales: Vec<F> = incoming.iter().flat_map(Frequent::candidates).collect();
        batch_inversion(&mut incoming_scales);
        let mut scales = Vec::with_capacity(width * CANDIDATES);
        for (column, frequencies) in outgoing.iter().enumerate() {
            scales.extend_from_slice(
                &incoming_scales[column * CANDIDATES_PER_SIDE..(column + 1) * CANDIDATES_PER_SIDE],
            );
            scales.extend(frequencies.candidates());
        }
        drop(incoming);
        drop(outgoing);
        drop(incoming_scales);
        let mut inverses = scales.clone();
        batch_inversion(&mut inverses);
        let mut scores = vec![0usize; scales.len()];
        for core in &self.layers[cut].matrices {
            for ((_, column), value) in core.iter() {
                let start = column * CANDIDATES;
                let negative = -value;
                for (score, &target) in scores[start..start + CANDIDATES]
                    .iter_mut()
                    .zip(&inverses[start..start + CANDIDATES])
                {
                    *score += usize::from(value == target || negative == target);
                }
            }
        }
        for core in &self.layers[cut + 1].matrices {
            for ((row, _), value) in core.iter() {
                let start = row * CANDIDATES;
                let negative = -value;
                for (score, &target) in scores[start..start + CANDIDATES]
                    .iter_mut()
                    .zip(&scales[start..start + CANDIDATES])
                {
                    *score += usize::from(value == target || negative == target);
                }
            }
        }
        let mut diagonal = vec![F::ONE; width];
        let mut inverse_diagonal = vec![F::ONE; width];
        let mut changed = 0;
        let mut improvement = 0;
        for column in 0..width {
            let mut best = baseline[column];
            for candidate in column * CANDIDATES..(column + 1) * CANDIDATES {
                if scores[candidate] > best {
                    best = scores[candidate];
                    diagonal[column] = scales[candidate];
                    inverse_diagonal[column] = inverses[candidate];
                }
            }
            if best > baseline[column] {
                changed += 1;
                improvement += best - baseline[column];
            }
        }
        drop(scales);
        drop(inverses);
        drop(scores);
        drop(baseline);
        if changed != 0 {
            for core in &mut self.layers[cut].matrices {
                core.scale_axis(&diagonal, true);
            }
            for core in &mut self.layers[cut + 1].matrices {
                core.scale_axis(&inverse_diagonal, false);
            }
        }
        (changed, improvement)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::cmd::extract::{matrix::DenseMatrix, Core, MbpLayer},
        ark_ff::AdditiveGroup,
        provekit_backend_bn254::FieldElement as F,
    };

    fn evaluate(program: &MatrixBranchingProgram<F>, assignment: usize) -> Vec<F> {
        if let Some(constant) = program.constant {
            return constant.to_vec();
        }
        let mut values = vec![F::ONE];
        for (level, layer) in program.layers.iter().enumerate().rev() {
            let core = &layer.matrices[(assignment >> level) & 1];
            let mut next = vec![F::ZERO; core.num_rows()];
            for ((row, column), value) in core.iter() {
                next[row] += value * values[column];
            }
            values = next;
        }
        values
    }

    fn other_count(program: &MatrixBranchingProgram<F>) -> usize {
        program
            .layers
            .iter()
            .flat_map(|layer| &layer.matrices)
            .map(|core| core.value_counts()[2])
            .sum()
    }

    fn support(program: &MatrixBranchingProgram<F>) -> Vec<(usize, usize, Vec<(usize, usize)>)> {
        program
            .layers
            .iter()
            .flat_map(|layer| &layer.matrices)
            .map(|core| {
                (
                    core.num_rows(),
                    core.num_cols(),
                    core.iter().map(|(index, _)| index).collect(),
                )
            })
            .collect()
    }

    fn assert_equivalent(program: &mut MatrixBranchingProgram<F>) {
        let table: Vec<_> = (0..1 << program.layers.len())
            .map(|assignment| evaluate(program, assignment))
            .collect();
        let before_support = support(program);
        let before_other = other_count(program);
        program.rescale();
        assert_eq!(support(program), before_support);
        assert!(other_count(program) <= before_other);
        for (assignment, expected) in table.iter().enumerate() {
            assert_eq!(
                &evaluate(program, assignment),
                expected,
                "assignment {assignment}"
            );
        }
    }

    #[test]
    fn removes_diagonal_gauges_in_all_storage_formats() {
        let widths = [3, 3, 4, 1];
        let diagonals: Vec<Vec<F>> = vec![
            vec![F::ONE; 3],
            [2u64, 3, 5].into_iter().map(F::from).collect(),
            [7u64, 11, 13, 17].into_iter().map(F::from).collect(),
            vec![F::ONE],
        ];
        for representation in 0..4 {
            let mut program = MatrixBranchingProgram {
                index_bits: 0,
                constant:   None,
                layers:     (0..3)
                    .map(|level| MbpLayer {
                        matrices: std::array::from_fn(|bit| {
                            let mut dense = DenseMatrix::zeros(widths[level], widths[level + 1]);
                            for row in 0..dense.num_rows {
                                for column in 0..dense.num_cols {
                                    let base = match (row + column + bit) % 3 {
                                        0 => F::ZERO,
                                        1 => F::ONE,
                                        _ => -F::ONE,
                                    };
                                    dense[(row, column)] = base
                                        * diagonals[level][row].inverse().unwrap()
                                        * diagonals[level + 1][column];
                                }
                            }
                            match if representation == 3 {
                                (level + bit) % 3
                            } else {
                                representation
                            } {
                                0 => Core::Dense(dense),
                                1 => Core::force_sparse(dense),
                                _ => Core::force_direct(dense),
                            }
                        }),
                    })
                    .collect(),
            };
            assert!(other_count(&program) > 0);
            assert_equivalent(&mut program);
            assert_eq!(other_count(&program), 0, "representation {representation}");
        }
    }

    #[test]
    fn scores_both_adjacent_layers_before_accepting_a_scale() {
        let mut program = MatrixBranchingProgram {
            index_bits: 1,
            constant:   None,
            layers:     vec![
                MbpLayer::from_dense(std::array::from_fn(|_| DenseMatrix {
                    num_rows: 3,
                    num_cols: 1,
                    values:   vec![F::ONE; 3],
                })),
                MbpLayer::from_dense(std::array::from_fn(|_| DenseMatrix {
                    num_rows: 1,
                    num_cols: 1,
                    values:   vec![F::from(2u64)],
                })),
            ],
        };
        // Normalizing the two outgoing coefficients would spoil six incoming
        // units, so the scale must be rejected.
        assert_eq!(program.rescale_cut(0), (0, 0));
        assert_equivalent(&mut program);
        assert_eq!(other_count(&program), 2);
    }

    #[test]
    fn mixed_coefficients_preserve_every_assignment_and_never_regress() {
        for seed in 0..24 {
            let widths = [3, 4, 3, 2, 1];
            let mut program = MatrixBranchingProgram {
                index_bits: 2,
                constant:   None,
                layers:     (0..4)
                    .map(|level| MbpLayer {
                        matrices: std::array::from_fn(|bit| {
                            let dense = DenseMatrix {
                                num_rows: widths[level],
                                num_cols: widths[level + 1],
                                values:   (0..widths[level] * widths[level + 1])
                                    .map(|index| {
                                        F::from(
                                            ((index * 17 + seed * 11 + level * 7 + bit * 3) % 13)
                                                as i64
                                                - 6,
                                        )
                                    })
                                    .collect(),
                            };
                            match (seed + level + bit) % 3 {
                                0 => Core::Dense(dense),
                                1 => Core::force_sparse(dense),
                                _ => Core::force_direct(dense),
                            }
                        }),
                    })
                    .collect(),
            };
            // Check each cut's claimed gain against actual coefficient counts.
            for cut in 0..3 {
                let before = other_count(&program);
                let (_, gain) = program.rescale_cut(cut);
                assert_eq!(other_count(&program) + gain, before);
            }
            assert_equivalent(&mut program);
            program.minimize();
            assert_equivalent(&mut program);
        }
    }

    #[test]
    fn empty_widths_and_constant_programs_are_unchanged() {
        let constant = [F::from(2u64), -F::ONE, F::ZERO];
        let mut program = MatrixBranchingProgram {
            index_bits: 0,
            layers:     vec![],
            constant:   Some(constant),
        };
        program.rescale();
        assert_eq!(program.constant, Some(constant));
        for widths in [[3, 0, 1], [3, 2, 1]] {
            let mut program = MatrixBranchingProgram {
                index_bits: 1,
                constant:   None,
                layers:     (0..2)
                    .map(|level| {
                        MbpLayer::from_dense(std::array::from_fn(|_| {
                            DenseMatrix::zeros(widths[level], widths[level + 1])
                        }))
                    })
                    .collect(),
            };
            assert_equivalent(&mut program);
        }
    }
}
