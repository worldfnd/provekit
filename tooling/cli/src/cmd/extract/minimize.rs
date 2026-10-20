use {
    super::{MatrixBranchingProgram, MbpLayer},
    ark_ff::Field,
    tracing::{info, instrument},
};

impl<F: Field> MatrixBranchingProgram<F> {
    /// Minimize every internal width by exact forward and backward rank sweeps.
    /// Boundary dimensions are preserved, including the three coefficient rows.
    /// Uses O(k w^3) field operations and O(w^2) auxiliary field elements.
    #[instrument(skip_all)]
    pub(super) fn minimize(&mut self) {
        // Establish a full-column-rank prefix at every cut.
        for level in 0..self.layers.len().saturating_sub(1) {
            info!("Forwards level {}/{}", level, self.layers.len());
            let before = tracing::enabled!(tracing::Level::INFO).then(|| {
                [
                    layer_stats(&self.layers[level]),
                    layer_stats(&self.layers[level + 1]),
                ]
            });
            let old_rank = self.layers[level].matrices[0].num_cols();
            let num_rows = self.layers[level].matrices[0].num_rows();
            let (left, right) = self.layers[level].rank_factor(true);
            let rank = right.num_rows();
            info!("Rank {} → {}", old_rank, rank);
            let current = std::array::from_fn(|bit| left.block(bit * num_rows, num_rows, 0, rank));
            let next = self.layers[level + 1]
                .matrices
                .each_ref()
                .map(|matrix| right.multiply(matrix));
            self.layers[level] = MbpLayer { matrices: current };
            self.layers[level + 1] = MbpLayer { matrices: next };
            if let Some([current, next]) = before {
                log_density(level, current, layer_stats(&self.layers[level]));
                log_density(level + 1, next, layer_stats(&self.layers[level + 1]));
            }
        }

        // Remove directions invisible to the suffix at every cut. The forward
        // sweep makes these suffix ranks equal to the full unfolding ranks.
        for level in (1..self.layers.len()).rev() {
            info!("Backwards level {}/{}", level, self.layers.len());
            let before = tracing::enabled!(tracing::Level::INFO).then(|| {
                [
                    layer_stats(&self.layers[level]),
                    layer_stats(&self.layers[level - 1]),
                ]
            });
            let old_rank = self.layers[level].matrices[0].num_rows();
            let num_cols = self.layers[level].matrices[0].num_cols();
            let (left, right) = self.layers[level].rank_factor(false);
            let rank = left.num_cols();
            info!("Rank {} → {}", old_rank, rank);
            let current = std::array::from_fn(|bit| right.block(0, rank, bit * num_cols, num_cols));
            let previous = self.layers[level - 1]
                .matrices
                .each_ref()
                .map(|matrix| matrix.multiply(&left));
            self.layers[level] = MbpLayer { matrices: current };
            self.layers[level - 1] = MbpLayer { matrices: previous };
            if let Some([current, previous]) = before {
                log_density(level, current, layer_stats(&self.layers[level]));
                log_density(level - 1, previous, layer_stats(&self.layers[level - 1]));
            }
        }
    }
}

/// (Nonzero count, occupancy percentage) for branches zero and one.
fn layer_stats<F: Field>(layer: &MbpLayer<F>) -> [(usize, f64); 2] {
    layer.matrices.each_ref().map(|core| {
        let nnz = core.nnz();
        let entries = core.num_rows() as f64 * core.num_cols() as f64;
        let density = if entries == 0.0 {
            0.0
        } else {
            100.0 * nnz as f64 / entries
        };
        (nnz, density)
    })
}

fn log_density(level: usize, before: [(usize, f64); 2], after: [(usize, f64); 2]) {
    info!(
        "Level {} nnz ({}, {}) → ({}, {}); density ({:.2}%, {:.2}%) → ({:.2}%, {:.2}%)",
        level,
        before[0].0,
        before[1].0,
        after[0].0,
        after[1].0,
        before[0].1,
        before[1].1,
        after[0].1,
        after[1].1,
    );
}

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{extract, extract_cqbdd, matrix::DenseMatrix, Core, MinimizeStrategy},
            *,
        },
        provekit_backend_bn254::FieldElement as F,
        provekit_common::{Interner, SparseMatrix, R1CS},
        tracing::instrument,
    };

    fn matrix(num_rows: usize, num_cols: usize, values: &[i64]) -> DenseMatrix<F> {
        assert_eq!(values.len(), num_rows * num_cols);
        DenseMatrix {
            num_rows,
            num_cols,
            values: values.iter().copied().map(F::from).collect(),
        }
    }

    #[test]
    fn sparse_products_match_dense_products() {
        for rows in [0, 1, 3, 5] {
            for inner in [0, 1, 3, 5] {
                for columns in [0, 1, 3, 5] {
                    for all_zero in [false, true] {
                        let mut lhs = DenseMatrix::zeros(rows, inner);
                        let mut rhs = DenseMatrix::zeros(inner, columns);
                        for (index, value) in lhs.values.iter_mut().enumerate() {
                            *value = F::from((index * 7 % 11) as i64 - 5);
                        }
                        if !all_zero {
                            for (index, value) in rhs.values.iter_mut().enumerate() {
                                // Covers zeros, +/-1, and general coefficients.
                                *value = F::from((index % 7) as i64 - 3);
                            }
                        }
                        let expected = lhs.multiply(&rhs);
                        let sparse_rhs = Core::force_sparse(rhs.clone());
                        assert_eq!(
                            lhs.multiply_core(&sparse_rhs),
                            expected,
                            "dense x sparse: {rows} x {inner} x {columns}, zero={all_zero}"
                        );
                        assert_eq!(lhs.multiply_core(&Core::Dense(rhs.clone())), expected);
                        let sparse_lhs = Core::force_sparse(lhs.clone());
                        assert_eq!(
                            DenseMatrix::core_multiply(&sparse_lhs, &rhs),
                            expected,
                            "sparse x dense: {rows} x {inner} x {columns}, zero={all_zero}"
                        );
                        assert_eq!(
                            DenseMatrix::core_multiply(&Core::Dense(lhs.clone()), &rhs),
                            expected
                        );
                        let product = sparse_lhs.multiply(&sparse_rhs);
                        let mut actual = DenseMatrix::zeros(product.num_rows(), product.num_cols());
                        for ((row, column), value) in product.iter() {
                            actual[(row, column)] = value;
                        }
                        assert_eq!(
                            actual, expected,
                            "sparse x sparse: {rows} x {inner} x {columns}"
                        );
                        let direct_lhs = Core::force_direct(lhs.clone());
                        let direct_rhs = Core::force_direct(rhs.clone());
                        assert_eq!(lhs.multiply_core(&direct_rhs), expected);
                        assert_eq!(DenseMatrix::core_multiply(&direct_lhs, &rhs), expected);
                        for product in [
                            direct_lhs.multiply(&sparse_rhs),
                            sparse_lhs.multiply(&direct_rhs),
                            direct_lhs.multiply(&direct_rhs),
                        ] {
                            let mut actual =
                                DenseMatrix::zeros(product.num_rows(), product.num_cols());
                            for ((row, column), value) in product.iter() {
                                actual[(row, column)] = value;
                            }
                            assert_eq!(actual, expected, "direct CSR multiplication");
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "manual performance comparison with a 64 MiB dense baseline"]
    fn benchmark_sparse_products() {
        use std::{hint::black_box, time::Instant};

        let mut interner = Interner::new();
        let one = interner.intern(F::from(1u64));
        let minus_one = interner.intern(F::from(-1i64));
        let mut core = SparseMatrix::new(0, 4096);
        for row in 0..512 {
            core.push_row(
                [
                    (0, one),
                    (row + 1, if row % 2 == 0 { one } else { minus_one }),
                ]
                .into_iter(),
            );
        }
        let mut left = DenseMatrix::zeros(4, core.num_rows);
        let mut right = DenseMatrix::zeros(core.num_cols, 4);
        for (index, value) in left.values.iter_mut().chain(&mut right.values).enumerate() {
            *value = F::from((index % 17 + 2) as u64);
        }

        let start = Instant::now();
        let sparse_product = black_box(&left).multiply_sparse(black_box(&core), &interner);
        let sparse_time = start.elapsed();
        let start = Instant::now();
        let dense_product = left.multiply(&DenseMatrix::from_sparse(&core, &interner));
        let dense_time = start.elapsed();
        assert_eq!(sparse_product, dense_product);
        eprintln!("forward: dense including conversion {dense_time:?}, sparse {sparse_time:?}");

        let start = Instant::now();
        let sparse_product =
            DenseMatrix::sparse_multiply(black_box(&core), &interner, black_box(&right));
        let sparse_time = start.elapsed();
        let start = Instant::now();
        let dense_product = DenseMatrix::from_sparse(&core, &interner).multiply(&right);
        let dense_time = start.elapsed();
        assert_eq!(sparse_product, dense_product);
        eprintln!("backward: dense including conversion {dense_time:?}, sparse {sparse_time:?}");
        eprintln!(
            "avoided dense core: {} bytes; forward output: {} bytes; backward output: {} bytes",
            core.num_rows * core.num_cols * size_of::<F>(),
            left.num_rows * core.num_cols * size_of::<F>(),
            core.num_rows * right.num_cols * size_of::<F>(),
        );
    }

    // Independent forward elimination, without row normalization or inverses.
    #[instrument(skip_all)]
    fn rank(mut matrix: DenseMatrix<F>) -> usize {
        let mut rank = 0;
        for column in 0..matrix.num_cols {
            let Some(pivot) =
                (rank..matrix.num_rows).find(|&row| matrix[(row, column)] != F::from(0u64))
            else {
                continue;
            };
            for j in 0..matrix.num_cols {
                matrix
                    .values
                    .swap(rank * matrix.num_cols + j, pivot * matrix.num_cols + j);
            }
            let pivot = matrix[(rank, column)];
            for row in rank + 1..matrix.num_rows {
                let coefficient = matrix[(row, column)];
                if coefficient == F::from(0u64) {
                    continue;
                }
                for j in column..matrix.num_cols {
                    matrix[(row, j)] = matrix[(row, j)] * pivot - coefficient * matrix[(rank, j)];
                }
            }
            rank += 1;
        }
        rank
    }

    fn evaluate(program: &MatrixBranchingProgram<F>, assignment: usize) -> Vec<F> {
        if let Some(values) = program.constant {
            return values.to_vec();
        }
        let mut values = matrix(1, 1, &[1]);
        for (level, layer) in program.layers.iter().enumerate().rev() {
            let core = &layer.matrices[(assignment >> level) & 1];
            let mut dense = DenseMatrix::zeros(core.num_rows(), core.num_cols());
            for ((row, column), value) in core.iter() {
                dense[(row, column)] = value;
            }
            values = dense.multiply(&values);
        }
        values.values
    }

    #[instrument(skip_all)]
    fn assert_minimal_and_equivalent(program: &mut MatrixBranchingProgram<F>) {
        let num_variables = program.layers.len();
        let table: Vec<_> = (0..1 << num_variables)
            .map(|assignment| evaluate(program, assignment))
            .collect();
        let old_widths: Vec<_> = program
            .layers
            .iter()
            .map(|layer| layer.matrices[0].num_cols())
            .collect();
        let constant = program.constant;
        program.minimize();
        assert_eq!(program.constant, constant);
        assert_eq!(program.layers.len(), num_variables);
        for (assignment, expected) in table.iter().enumerate() {
            assert_eq!(
                &evaluate(program, assignment),
                expected,
                "assignment {assignment}"
            );
        }
        for cut in 1..num_variables {
            let num_prefixes = 1 << cut;
            let num_suffixes = 1 << (num_variables - cut);
            let mut unfolding = DenseMatrix::zeros(table[0].len() * num_prefixes, num_suffixes);
            for prefix in 0..num_prefixes {
                for suffix in 0..num_suffixes {
                    let values = &table[prefix | (suffix << cut)];
                    for (component, &value) in values.iter().enumerate() {
                        unfolding[(component * num_prefixes + prefix, suffix)] = value;
                    }
                }
            }
            let rank = rank(unfolding);
            assert!(rank <= old_widths[cut - 1]);
            for bit in 0..2 {
                assert_eq!(
                    program.layers[cut - 1].matrices[bit].num_cols(),
                    rank,
                    "cut {cut}"
                );
                assert_eq!(
                    program.layers[cut].matrices[bit].num_rows(),
                    rank,
                    "cut {cut}"
                );
            }
        }
        if let Some(first) = program.layers.first() {
            for core in &first.matrices {
                assert_eq!(core.num_rows(), table[0].len());
            }
            for core in &program.layers.last().unwrap().matrices {
                assert_eq!(core.num_cols(), 1);
            }
        }
    }

    #[test]
    fn rank_factorizations_are_exact_including_degenerate_shapes() {
        let cases = [
            (matrix(3, 4, &[0, 2, 4, 0, 0, 0, 0, 3, 0, 4, 8, 6]), 2),
            (matrix(3, 2, &[0, 2, 3, 4, 6, 8]), 2),
            (matrix(2, 3, &[2, 4, -6, -3, -6, 9]), 1),
            (matrix(3, 3, &[0, 0, 2, 0, 3, 0, 4, 0, 0]), 3),
            (matrix(2, 3, &[0; 6]), 0),
            (matrix(0, 3, &[]), 0),
            (matrix(3, 0, &[]), 0),
            (matrix(0, 0, &[]), 0),
        ];
        for (original, expected_rank) in cases {
            let (left, right) = original.clone().rank_factor();
            assert_eq!(
                (left.num_rows, left.num_cols),
                (original.num_rows, expected_rank)
            );
            assert_eq!(
                (right.num_rows, right.num_cols),
                (expected_rank, original.num_cols)
            );
            assert_eq!(left.multiply(&right), original);
        }
    }

    #[test]
    fn both_scalar_and_vector_boundaries_attain_unfolding_ranks() {
        for widths in [[1, 6, 5, 7, 1], [3, 8, 7, 5, 1]] {
            let mut seed = 17u64;
            let layers = widths
                .windows(2)
                .map(|width| {
                    let matrices = std::array::from_fn(|_| {
                        let mut dense = DenseMatrix::zeros(width[0], width[1]);
                        for value in &mut dense.values {
                            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                            *value = F::from(((seed >> 32) % 11) as i64 - 5);
                        }
                        dense
                    });
                    MbpLayer::from_dense(matrices)
                })
                .collect();
            let mut program = MatrixBranchingProgram {
                index_bits: 2,
                layers,
                constant: None,
            };
            assert_minimal_and_equivalent(&mut program);
        }
    }

    #[test]
    fn backward_sweep_removes_cancelling_directions() {
        let mut program = MatrixBranchingProgram {
            index_bits: 1,
            layers:     vec![
                MbpLayer::from_dense(std::array::from_fn(|_| matrix(3, 2, &[1, 1, 2, 2, 3, 3]))),
                MbpLayer::from_dense(std::array::from_fn(|_| matrix(2, 1, &[1, -1]))),
            ],
            constant:   None,
        };
        assert_minimal_and_equivalent(&mut program);
        assert_eq!(program.layers[0].matrices[0].num_cols(), 0);
        assert_eq!(program.layers[1].matrices[0].num_rows(), 0);
        for layer in program.layers {
            for core in layer.matrices {
                assert!(core.iter().next().is_none());
            }
        }
    }

    #[test]
    fn extraction_minimizes_and_preserves_every_coefficient() {
        let mut r1cs = R1CS::<F>::new();
        r1cs.add_witnesses(7);
        for row in 0..5 {
            let a: Vec<_> = (0..7)
                .map(|column| (F::from((row + 1) * (column + 1)), column as usize))
                .collect();
            let b = [(F::from(-3i64), row as usize)];
            let c: Vec<_> = (0..7)
                .map(|column| (F::from((row ^ column) + 1), column as usize))
                .collect();
            r1cs.add_constraint(&a, &b, &c);
        }
        let mut program = extract_cqbdd(&r1cs).to_mbp();
        assert_minimal_and_equivalent(&mut program);
        let extracted = extract(&r1cs, MinimizeStrategy::Rank);
        for assignment in 0..64 {
            let mut row = 0;
            let mut column = 0;
            for bit in 0..3 {
                row |= ((assignment >> (2 * bit)) & 1) << bit;
                column |= ((assignment >> (2 * bit + 1)) & 1) << bit;
            }
            let expected = [&r1cs.a, &r1cs.b, &r1cs.c].map(|matrix| {
                if row < matrix.num_rows && column < matrix.num_cols {
                    matrix
                        .get(row, column)
                        .map_or(F::from(0u64), |value| r1cs.interner.get(value).unwrap())
                } else {
                    F::from(0u64)
                }
            });
            assert_eq!(evaluate(&extracted, assignment), expected);
        }
    }

    #[test]
    fn constants_and_programs_without_internal_cuts_are_unchanged() {
        let mut constant = MatrixBranchingProgram::<F> {
            index_bits: 0,
            layers:     Vec::new(),
            constant:   Some([F::from(7u64); 3]),
        };
        assert_minimal_and_equivalent(&mut constant);
        let mut single = MatrixBranchingProgram {
            index_bits: 0,
            layers:     vec![MbpLayer::from_dense([
                matrix(3, 1, &[1, 2, 3]),
                matrix(3, 1, &[4, 5, 6]),
            ])],
            constant:   None,
        };
        assert_minimal_and_equivalent(&mut single);
    }
}
