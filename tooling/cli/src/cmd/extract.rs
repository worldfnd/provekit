use {
    ark_ff::Field,
    provekit_common::{InternedFieldElement, Interner, SparseMatrix, R1CS},
    std::collections::HashMap,
    tracing::info,
};

mod matrix;
mod minimize;
mod rank;

pub(super) use matrix::Core;

/// Two matrices per variable in r_0, c_0, r_1, c_1, ... order.
///
/// Their product M_0[z_0] ... M_(2K-1)[z_(2K-1)] is the 3-by-1
/// coefficient triple at (row, column). Before minimization, internal
/// dimensions contain one value per BDD node and one shared constant-one value
/// at coordinate zero. Minimization may change this basis and remove redundant
/// coordinates.
#[derive(Debug)]
pub(super) struct MatrixBranchingProgram<F: Field> {
    pub(super) index_bits: usize,
    pub(super) layers:     Vec<MbpLayer<F>>,
    /// With no variables, the 3-by-1 product is this constant column instead.
    pub(super) constant:   Option<[F; 3]>,
}

/// Each branch independently chooses sparse or dense storage.
#[derive(Debug)]
pub(super) struct MbpLayer<F: Field> {
    pub(super) matrices: [Core<F>; 2],
}

pub(super) fn extract<F: Field>(r1cs: &R1CS<F>) -> MatrixBranchingProgram<F> {
    let mut program = extract_cqbdd(r1cs).to_mbp();
    info!(
        "Extracted an MBP for {} index bits with {} layers (constant: {}).",
        program.index_bits,
        program.layers.len(),
        program.constant.is_some()
    );
    let dimensions = if program.constant.is_some() {
        vec![3, 1]
    } else {
        std::iter::once(3)
            .chain(
                program
                    .layers
                    .iter()
                    .map(|layer| layer.matrices[0].num_cols()),
            )
            .collect::<Vec<_>>()
    };
    info!("MBP dimensions: {:?}", dimensions);
    program.minimize();
    let dimensions = if program.constant.is_some() {
        vec![3, 1]
    } else {
        std::iter::once(3)
            .chain(
                program
                    .layers
                    .iter()
                    .map(|layer| layer.matrices[0].num_cols()),
            )
            .collect::<Vec<_>>()
    };
    info!("Minimized MBP dimensions: {:?}", dimensions);
    let dense_cores = program
        .layers
        .iter()
        .flat_map(|layer| &layer.matrices)
        .filter(|core| matches!(core, Core::Dense(_)))
        .count();
    info!(
        "Minimized MBP storage: {} sparse, {} dense cores.",
        2 * program.layers.len() - dense_cores,
        dense_cores
    );
    program
}

/// A shared, fully layered BDD in interleaved LSB order.
///
/// Terminal ID 1 represents true, and -1 represents false. Nonterminal ID `v`
/// indexes `nodes[v - 2]`. A negative reference complements the entire node.
#[derive(Debug)]
pub(super) struct Cqbdd<F: Field> {
    pub(super) index_bits: usize,
    pub(super) nodes:      Vec<CqbddNode>,
    pub(super) roots:      HashMap<(F, F, F), isize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct CqbddNode {
    /// Zero-based variable level: r_0, c_0, r_1, c_1, ...
    pub(super) level:            usize,
    pub(super) low_complemented: bool,
    pub(super) low:              usize,
    pub(super) high:             usize,
}

/// Extract one CQBDD root for each nonzero coefficient triple.
fn extract_cqbdd<F: Field>(r1cs: &R1CS<F>) -> Cqbdd<F> {
    let entries = collect_entries(r1cs);

    let total_nonzero = entries.values().map(|v| v.len()).sum::<usize>();
    info!(
        "Collected {} unique triplets among {}.",
        entries.len(),
        total_nonzero
    );

    // Construct a CQBDD for all index sets. Use a square power-of-two domain
    // covering both matrix dimensions, including any unused rows or columns.
    let dimension = r1cs.num_constraints().max(r1cs.num_witnesses());
    let index_bits = (usize::BITS - dimension.saturating_sub(1).leading_zeros()) as usize;
    let mut builder = CqbddBuilder::new(index_bits);
    let roots = entries
        .into_iter()
        .map(|(coefficients, mut indices)| (coefficients, builder.build(0, &mut indices)))
        .collect();
    let graph = Cqbdd {
        index_bits,
        nodes: builder.nodes,
        roots,
    };
    info!(
        "Extracted {} CQBDD nodes across {} layers for {} roots.",
        graph.nodes.len(),
        2 * graph.index_bits,
        graph.roots.len()
    );
    let widths = (0..2 * graph.index_bits)
        .map(|level| {
            graph
                .nodes
                .iter()
                .filter(|node| node.level == level)
                .count()
        })
        .collect::<Vec<_>>();
    info!("Layer widths: {:?}", widths);
    graph
}

impl<F: Field> Cqbdd<F> {
    fn to_mbp(&self) -> MatrixBranchingProgram<F> {
        let num_variables = 2 * self.index_bits;
        let mut program = MatrixBranchingProgram {
            index_bits: self.index_bits,
            layers:     Vec::with_capacity(num_variables),
            constant:   None,
        };
        if num_variables == 0 {
            let mut values = [F::ZERO; 3];
            for (&(a, b, c), &root) in &self.roots {
                if root == 1 {
                    for (value, coefficient) in values.iter_mut().zip([a, b, c]) {
                        *value += coefficient;
                    }
                }
            }
            program.constant = Some(values);
            return program;
        }

        let mut levels = vec![Vec::new(); num_variables];
        let mut columns = vec![0; self.nodes.len()];
        for (offset, node) in self.nodes.iter().enumerate() {
            // Coordinate zero holds the one additional value for complements.
            columns[offset] = levels[node.level].len() + 1;
            levels[node.level].push(offset);
        }
        let child_column = |child: usize| {
            if child == 1 {
                0
            } else {
                columns[child - 2]
            }
        };
        for level in 0..num_variables {
            let mut interner = Interner::new();
            let one = interner.intern(F::ONE);
            let minus_one = interner.intern(-F::ONE);
            // At the terminal, the node value and the extra constant coincide.
            let num_cols = levels.get(level + 1).map_or(1, |nodes| nodes.len() + 1);
            let matrices = std::array::from_fn(|bit| {
                let mut matrix = SparseMatrix::new(0, num_cols);
                if level == 0 {
                    // Absorb the coefficient-weighted signed roots into this
                    // first pair, so the initial dimension is exactly three.
                    let mut values = vec![[F::ZERO; 3]; num_cols];
                    for (&(a, b, c), &root) in &self.roots {
                        let node = &self.nodes[root.unsigned_abs() - 2];
                        let child = if bit == 0 { node.low } else { node.high };
                        let column = child_column(child);
                        let complemented = (root < 0) ^ (bit == 0 && node.low_complemented);
                        for (component, coefficient) in [a, b, c].into_iter().enumerate() {
                            if complemented {
                                values[0][component] += coefficient;
                                values[column][component] -= coefficient;
                            } else {
                                values[column][component] += coefficient;
                            }
                        }
                    }
                    for component in 0..3 {
                        matrix.push_row(values.iter().enumerate().filter_map(
                            |(column, values)| {
                                let value = values[component];
                                (!value.is_zero()).then(|| {
                                    (
                                        u32::try_from(column)
                                            .expect("MBP column index exceeds u32::MAX"),
                                        interner.intern(value),
                                    )
                                })
                            },
                        ));
                    }
                } else {
                    // Preserve the constant-one coordinate in both branches.
                    matrix.push_row([(0, one)].into_iter());
                    for &offset in &levels[level] {
                        let node = &self.nodes[offset];
                        let child = if bit == 0 { node.low } else { node.high };
                        let column = child_column(child);
                        let complemented = bit == 0 && node.low_complemented;
                        append_branch_row(&mut matrix, column, complemented, one, minus_one);
                    }
                }
                matrix
            });
            program
                .layers
                .push(MbpLayer::from_sparse(matrices, interner));
        }
        program
    }
}

fn append_branch_row(
    matrix: &mut SparseMatrix,
    column: usize,
    complemented: bool,
    one: InternedFieldElement,
    minus_one: InternedFieldElement,
) {
    let column = u32::try_from(column).expect("MBP column index exceeds u32::MAX");
    match (column, complemented) {
        // The complement of terminal one is zero.
        (0, true) => matrix.push_row(std::iter::empty()),
        (_, false) => matrix.push_row([(column, one)].into_iter()),
        (_, true) => matrix.push_row([(0, one), (column, minus_one)].into_iter()),
    }
}

struct CqbddBuilder {
    num_variables: usize,
    nodes:         Vec<CqbddNode>,
    unique_tables: Vec<Option<HashMap<CqbddNode, isize>>>,
    ones:          Vec<Option<isize>>,
}

impl CqbddBuilder {
    fn new(index_bits: usize) -> Self {
        assert!(index_bits <= usize::BITS as usize);
        let num_variables = 2 * index_bits;
        let mut ones = vec![None; num_variables + 1];
        ones[num_variables] = Some(1);
        Self {
            num_variables,
            nodes: Vec::new(),
            unique_tables: (0..num_variables).map(|_| None).collect(),
            ones,
        }
    }

    fn make(&mut self, level: usize, low: isize, high: isize) -> isize {
        // Normalize the high edge to positive, moving its complement to the
        // returned reference and toggling the low complement when necessary.
        let node = CqbddNode {
            level,
            low_complemented: (low < 0) ^ (high < 0),
            low: low.unsigned_abs(),
            high: high.unsigned_abs(),
        };
        let table = self.unique_tables[level].get_or_insert_with(HashMap::new);
        let id = *table.entry(node).or_insert_with(|| {
            let id =
                isize::try_from(self.nodes.len() + 2).expect("CQBDD node IDs exceed isize::MAX");
            // Keep equal-child nodes: every edge must advance exactly one level.
            self.nodes.push(node);
            id
        });
        if high < 0 {
            -id
        } else {
            id
        }
    }

    fn one(&mut self, level: usize) -> isize {
        if let Some(id) = self.ones[level] {
            return id;
        }
        let child = self.one(level + 1);
        let id = self.make(level, child, child);
        self.ones[level] = Some(id);
        id
    }

    fn build(&mut self, level: usize, indices: &mut [(usize, usize)]) -> isize {
        if indices.is_empty() {
            return -self.one(level);
        }
        if level == self.num_variables {
            return 1;
        }

        // Partition in place by r_(level/2) or c_(level/2), LSB first.
        let mut split = 0;
        for index in 0..indices.len() {
            let (row, column) = indices[index];
            let coordinate = if level % 2 == 0 { row } else { column };
            if (coordinate >> (level / 2)) & 1 == 0 {
                indices.swap(split, index);
                split += 1;
            }
        }
        let (low_indices, high_indices) = indices.split_at_mut(split);
        let low = self.build(level + 1, low_indices);
        let high = self.build(level + 1, high_indices);
        self.make(level, low, high)
    }
}

fn collect_entries<F: Field>(r1cs: &R1CS<F>) -> HashMap<(F, F, F), Vec<(usize, usize)>> {
    let matrices = [r1cs.a(), r1cs.b(), r1cs.c()];
    let mut entries = matrices.each_ref().map(|matrix| matrix.iter().peekable());
    let mut triples = HashMap::<_, Vec<_>>::new();

    // Merge the three sorted streams, visiting each occupied position once.
    loop {
        let Some(index) = entries
            .iter_mut()
            .filter_map(|entries| entries.peek().map(|&(index, _)| index))
            .min()
        else {
            break;
        };

        let [a, b, c] = entries.each_mut().map(|entries| {
            entries
                .next_if(|&(entry_index, _)| entry_index == index)
                .map_or(F::ZERO, |(_, value)| value)
        });

        if !a.is_zero() || !b.is_zero() || !c.is_zero() {
            triples.entry((a, b, c)).or_default().push(index);
        }
    }

    triples
}

#[cfg(test)]
mod tests {
    use {super::*, provekit_backend_bn254::FieldElement, std::collections::HashSet};

    fn evaluate_mbp(
        program: &MatrixBranchingProgram<FieldElement>,
        row: usize,
        column: usize,
    ) -> [FieldElement; 3] {
        if let Some(values) = program.constant {
            assert!(program.layers.is_empty());
            return values;
        }
        let mut values = vec![FieldElement::from(1u64)];
        for (level, layer) in program.layers.iter().enumerate().rev() {
            let coordinate = if level % 2 == 0 { row } else { column };
            let matrix = &layer.matrices[(coordinate >> (level / 2)) & 1];
            assert_eq!(matrix.num_cols(), values.len());
            let mut next = vec![FieldElement::from(0u64); matrix.num_rows()];
            for ((row, column), coefficient) in matrix.iter() {
                next[row] += coefficient * values[column];
            }
            values = next;
        }
        values.try_into().unwrap()
    }

    fn assert_mbp_dimensions<F: Field>(graph: &Cqbdd<F>, program: &MatrixBranchingProgram<F>) {
        assert_eq!(program.index_bits, graph.index_bits);
        assert_eq!(program.layers.len(), 2 * graph.index_bits);
        let mut num_rows = 3;
        for (level, layer) in program.layers.iter().enumerate() {
            let num_cols = if level + 1 == program.layers.len() {
                1
            } else {
                graph
                    .nodes
                    .iter()
                    .filter(|node| node.level == level + 1)
                    .count()
                    + 1
            };
            for matrix in &layer.matrices {
                assert_eq!((matrix.num_rows(), matrix.num_cols()), (num_rows, num_cols));
                for ((..), value) in matrix.iter() {
                    assert!(!value.is_zero());
                }
                if level != 0 {
                    assert_eq!(
                        matrix
                            .iter()
                            .filter_map(
                                |((row, column), value)| (row == 0).then_some((column, value))
                            )
                            .collect::<Vec<_>>(),
                        [(0, F::ONE)]
                    );
                    for row in 1..matrix.num_rows() {
                        assert!(
                            matrix
                                .iter()
                                .filter(|((entry_row, _), _)| *entry_row == row)
                                .count()
                                <= 2
                        );
                    }
                }
            }
            num_rows = num_cols;
        }
    }

    fn evaluate(nodes: &[CqbddNode], mut root: isize, row: usize, column: usize) -> bool {
        let mut complemented = false;
        let mut bits = [row, column];
        let mut level = 0;
        while root.unsigned_abs() != 1 {
            complemented ^= root < 0;
            let node = &nodes[root.unsigned_abs() - 2];
            assert_eq!(node.level, level);
            let high = bits[level % 2] & 1 != 0;
            bits[level % 2] >>= 1;
            root = if high {
                node.high as isize
            } else if node.low_complemented {
                -(node.low as isize)
            } else {
                node.low as isize
            };
            level += 1;
        }
        (root > 0) ^ complemented
    }

    fn assert_layered(nodes: &[CqbddNode], num_variables: usize) {
        let mut unique = HashSet::new();
        for (offset, node) in nodes.iter().enumerate() {
            assert!(unique.insert(*node), "duplicate node: {node:?}");
            assert!(node.level < num_variables);
            for child in [node.low, node.high] {
                assert!((1..offset + 2).contains(&child));
                if node.level + 1 == num_variables {
                    assert_eq!(child, 1);
                } else {
                    assert!(child > 1);
                    assert_eq!(nodes[child - 2].level, node.level + 1);
                }
            }
        }
    }

    #[test]
    fn exhaustive_four_by_four_index_sets() {
        let mut builder = CqbddBuilder::new(2);
        let mut roots = Vec::new();
        // Exercise every Boolean function on the four interleaved variables.
        for mask in 0..=u16::MAX {
            let mut indices: Vec<_> = (0..16)
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| (bit / 4, bit % 4))
                .collect();
            roots.push(builder.build(0, &mut indices));
        }

        for mask in 0..=u16::MAX {
            let root = roots[mask as usize];
            assert_eq!(root, -roots[(!mask) as usize]);
            for row in 0..4 {
                for column in 0..4 {
                    assert_eq!(
                        evaluate(&builder.nodes, root, row, column),
                        mask & (1 << (4 * row + column)) != 0,
                        "mask {mask:#06x}, position ({row}, {column})"
                    );
                }
            }
        }
        assert_layered(&builder.nodes, 4);
    }

    #[test]
    fn constants_keep_every_layer_and_share_nodes() {
        let mut builder = CqbddBuilder::new(3);
        let empty = builder.build(0, &mut []);
        let mut full: Vec<_> = (0..8).flat_map(|r| (0..8).map(move |c| (r, c))).collect();
        let full = builder.build(0, &mut full);
        assert_eq!(full, -empty);
        assert_eq!(builder.nodes.len(), 6);
        for node in &builder.nodes {
            assert!(!node.low_complemented);
            assert_eq!(node.low, node.high);
        }
        assert_layered(&builder.nodes, 6);
    }

    #[test]
    fn input_order_does_not_change_the_root() {
        let mut builder = CqbddBuilder::new(3);
        let mut indices = [(7, 0), (0, 5), (3, 2), (1, 7), (4, 4)];
        let root = builder.build(0, &mut indices);
        let node_count = builder.nodes.len();
        indices.reverse();
        assert_eq!(root, builder.build(0, &mut indices));
        assert_eq!(builder.nodes.len(), node_count);
    }

    #[test]
    fn zero_bit_and_full_word_domains() {
        let mut builder = CqbddBuilder::new(0);
        assert_eq!(builder.build(0, &mut []), -1);
        assert_eq!(builder.build(0, &mut [(0, 0)]), 1);
        assert!(builder.nodes.is_empty());

        let mut builder = CqbddBuilder::new(usize::BITS as usize);
        let root = builder.build(0, &mut [(usize::MAX, 1)]);
        assert!(evaluate(&builder.nodes, root, usize::MAX, 1));
        assert!(!evaluate(&builder.nodes, root, usize::MAX >> 1, 1));
        assert!(!evaluate(&builder.nodes, root, usize::MAX, 0));
        assert_layered(&builder.nodes, 2 * usize::BITS as usize);

        let coefficients = (
            FieldElement::from(2u64),
            FieldElement::from(0u64),
            -FieldElement::from(3u64),
        );
        let graph = Cqbdd {
            index_bits: usize::BITS as usize,
            nodes:      builder.nodes,
            roots:      HashMap::from([(coefficients, root)]),
        };
        let program = graph.to_mbp();
        assert_mbp_dimensions(&graph, &program);
        assert_eq!(evaluate_mbp(&program, usize::MAX, 1), [
            coefficients.0,
            coefficients.1,
            coefficients.2
        ]);
        assert_eq!(
            evaluate_mbp(&program, usize::MAX >> 1, 1),
            [FieldElement::from(0u64); 3]
        );
    }

    #[test]
    fn mbp_combines_complementary_roots_with_one_extra_coordinate() {
        let coefficients = [
            (
                FieldElement::from(0u64),
                FieldElement::from(5u64),
                -FieldElement::from(7u64),
            ),
            (
                -FieldElement::from(3u64),
                FieldElement::from(0u64),
                FieldElement::from(13u64),
            ),
        ];
        for mask in 0u8..16 {
            let mut builder = CqbddBuilder::new(1);
            let mut indices: Vec<_> = (0..4)
                .filter(|bit| mask & (1 << bit) != 0)
                .map(|bit| (bit / 2, bit % 2))
                .collect();
            let root = builder.build(0, &mut indices);
            let graph = Cqbdd {
                index_bits: 1,
                nodes:      builder.nodes,
                roots:      HashMap::from([(coefficients[0], root), (coefficients[1], -root)]),
            };
            let program = graph.to_mbp();
            assert_mbp_dimensions(&graph, &program);
            for row in 0..2 {
                for column in 0..2 {
                    let index = usize::from(mask & (1 << (2 * row + column)) == 0);
                    let (a, b, c) = coefficients[index];
                    assert_eq!(
                        evaluate_mbp(&program, row, column),
                        [a, b, c],
                        "mask {mask}"
                    );
                }
            }
        }
    }

    #[test]
    fn mbp_handles_constant_and_empty_systems() {
        let zero = FieldElement::from(0u64);
        let one = FieldElement::from(1u64);
        let two = FieldElement::from(2u64);
        let mut r1cs = R1CS::new();
        let program = extract(&r1cs);
        assert_eq!(program.constant, Some([zero; 3]));
        assert_eq!(evaluate_mbp(&program, 0, 0), [zero; 3]);

        r1cs.add_witnesses(1);
        r1cs.add_constraint(&[(one, 0)], &[(two, 0)], &[(-one, 0)]);
        let program = extract(&r1cs);
        assert_eq!(program.index_bits, 0);
        assert_eq!(program.constant, Some([one, two, -one]));
        assert_eq!(evaluate_mbp(&program, 0, 0), [one, two, -one]);

        let mut r1cs = R1CS::<FieldElement>::new();
        r1cs.add_witnesses(5);
        let graph = extract_cqbdd(&r1cs);
        let program = graph.to_mbp();
        assert_mbp_dimensions(&graph, &program);
        for row in 0..8 {
            for column in 0..8 {
                assert_eq!(evaluate_mbp(&program, row, column), [zero; 3]);
            }
        }
    }

    #[test]
    fn extraction_preserves_coefficients_and_pads_the_domain() {
        let one = FieldElement::from(1u64);
        let two = FieldElement::from(2u64);
        let zero = FieldElement::from(0u64);
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(5);
        r1cs.add_constraint(&[(one, 0), (two, 2)], &[(one, 0)], &[(one, 4)]);
        r1cs.add_constraint(&[(one, 1)], &[(one, 1), (two, 3)], &[(two, 3)]);
        r1cs.add_constraint(&[], &[], &[]);

        let graph = extract_cqbdd(&r1cs);
        let expected = [
            ((one, one, zero), vec![(0, 0), (1, 1)]),
            ((two, zero, zero), vec![(0, 2)]),
            ((zero, zero, one), vec![(0, 4)]),
            ((zero, two, two), vec![(1, 3)]),
        ];
        assert_eq!(graph.index_bits, 3);
        assert_eq!(graph.roots.len(), expected.len());
        for (coefficients, indices) in &expected {
            let root = graph.roots[coefficients];
            for row in 0..8 {
                for column in 0..8 {
                    assert_eq!(
                        evaluate(&graph.nodes, root, row, column),
                        indices.contains(&(row, column))
                    );
                }
            }
        }
        assert_layered(&graph.nodes, 6);

        let program = graph.to_mbp();
        assert_mbp_dimensions(&graph, &program);
        for row in 0..8 {
            for column in 0..8 {
                let &(a, b, c) = expected
                    .iter()
                    .find(|(_, indices)| indices.contains(&(row, column)))
                    .map_or(&(zero, zero, zero), |(coefficients, _)| coefficients);
                assert_eq!(evaluate_mbp(&program, row, column), [a, b, c]);
            }
        }

        let graph = extract_cqbdd(&R1CS::<FieldElement>::new());
        assert_eq!(graph.index_bits, 0);
        assert!(graph.roots.is_empty());
        assert!(graph.nodes.is_empty());
    }
}
