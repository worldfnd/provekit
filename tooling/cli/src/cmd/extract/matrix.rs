use {
    super::MbpLayer,
    ark_ff::Field,
    provekit_common::{InternedFieldElement, Interner, SparseMatrix},
    std::{
        collections::HashSet,
        ops::{Index, IndexMut},
        sync::Arc,
    },
};

/// Each core chooses its own storage when it is produced. Sparse cores own
/// their coefficients; the two original BDD branches can share an interner.
#[derive(Debug)]
pub(in crate::cmd) enum Core<F: Field> {
    Sparse {
        matrix:   SparseMatrix,
        interner: Arc<Interner<F>>,
    },
    Direct(DirectSparseMatrix<F>),
    Dense(DenseMatrix<F>),
}

/// CSR with direct field values. No reverse dictionary or value-index array.
#[derive(Debug)]
pub(in crate::cmd) struct DirectSparseMatrix<F> {
    pub(super) num_cols: usize,
    pub(super) offsets:  Vec<usize>,
    pub(super) columns:  Vec<u32>,
    pub(super) values:   Vec<F>,
}

impl<F: Field> DirectSparseMatrix<F> {
    pub(super) fn new(num_cols: usize) -> Self {
        Self {
            num_cols,
            offsets: vec![0],
            columns: Vec::new(),
            values: Vec::new(),
        }
    }

    pub(super) fn num_rows(&self) -> usize {
        self.offsets.len() - 1
    }

    pub(super) fn push_row(&mut self, entries: impl Iterator<Item = (usize, F)>) {
        for (column, value) in entries {
            self.columns
                .push(u32::try_from(column).expect("MBP column index exceeds u32::MAX"));
            self.values.push(value);
        }
        self.offsets.push(self.values.len());
    }

    pub(super) fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, F)> + '_ {
        let range = self.offsets[row]..self.offsets[row + 1];
        self.columns[range.clone()]
            .iter()
            .copied()
            .zip(self.values[range].iter().copied())
            .map(|(column, value)| (column as usize, value))
    }

    fn iter(&self) -> impl Iterator<Item = ((usize, usize), F)> + '_ {
        (0..self.num_rows()).flat_map(|row| {
            self.iter_row(row)
                .map(move |(column, value)| ((row, column), value))
        })
    }
}

impl<F: Field> Core<F> {
    pub(super) fn from_direct(mut direct: DirectSparseMatrix<F>) -> Self {
        let num_rows = direct.num_rows();
        let nnz = direct.values.len();
        let dense_bytes = num_rows
            .saturating_mul(direct.num_cols)
            .saturating_mul(size_of::<F>());
        let direct_bytes = direct
            .offsets
            .capacity()
            .saturating_mul(size_of::<usize>())
            .saturating_add(direct.columns.capacity().saturating_mul(size_of::<u32>()))
            .saturating_add(direct.values.capacity().saturating_mul(size_of::<F>()));
        if Self::prefer_sparse(
            num_rows,
            nnz,
            dense_bytes.min(direct_bytes),
            direct.values.iter().copied(),
        ) {
            let mut interner = Interner::new();
            let values = direct
                .values
                .into_iter()
                .map(|value| interner.intern(value))
                .collect();
            direct.offsets.pop();
            let offsets = direct
                .offsets
                .into_iter()
                .map(|offset| u32::try_from(offset).expect("too many sparse entries"))
                .collect();
            return Self::Sparse {
                matrix:   SparseMatrix::from_raw_parts(
                    num_rows,
                    direct.num_cols,
                    offsets,
                    direct.columns,
                    values,
                ),
                interner: Arc::new(interner),
            };
        }
        if direct_bytes < dense_bytes {
            return Self::Direct(direct);
        }
        if nnz == num_rows.saturating_mul(direct.num_cols) {
            return Self::Dense(DenseMatrix {
                num_rows,
                num_cols: direct.num_cols,
                values: direct.values,
            });
        }
        let mut dense = DenseMatrix::zeros(num_rows, direct.num_cols);
        for ((row, column), value) in direct.iter() {
            dense[(row, column)] = value;
        }
        Self::Dense(dense)
    }

    pub(super) fn num_rows(&self) -> usize {
        match self {
            Self::Sparse { matrix, .. } => matrix.num_rows,
            Self::Direct(matrix) => matrix.num_rows(),
            Self::Dense(matrix) => matrix.num_rows,
        }
    }

    pub(super) fn num_cols(&self) -> usize {
        match self {
            Self::Sparse { matrix, .. } => matrix.num_cols,
            Self::Direct(matrix) => matrix.num_cols,
            Self::Dense(matrix) => matrix.num_cols,
        }
    }

    pub(super) fn nnz(&self) -> usize {
        match self {
            Self::Sparse { matrix, .. } => matrix.num_entries(),
            Self::Direct(matrix) => matrix.values.len(),
            Self::Dense(matrix) => matrix
                .values
                .iter()
                .filter(|value| !value.is_zero())
                .count(),
        }
    }

    pub(super) fn is_sparse(&self) -> bool {
        matches!(self, Self::Sparse { .. } | Self::Direct(_))
    }

    pub(super) fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, F)> + '_ {
        let (sparse, direct, dense) = match self {
            Self::Sparse { matrix, interner } => (Some((matrix, interner)), None, None),
            Self::Direct(matrix) => (None, Some(matrix), None),
            Self::Dense(matrix) => (None, None, Some(matrix)),
        };
        sparse
            .into_iter()
            .flat_map(move |(matrix, interner)| {
                matrix.iter_row(row).map(move |(column, value)| {
                    (column, interner.get(value).expect("invalid coefficient"))
                })
            })
            .chain(
                direct
                    .into_iter()
                    .flat_map(move |matrix| matrix.iter_row(row)),
            )
            .chain(dense.into_iter().flat_map(move |matrix| {
                matrix.values[row * matrix.num_cols..(row + 1) * matrix.num_cols]
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(_, value)| !value.is_zero())
            }))
    }

    /// Nonzero entries, independent of the chosen representation.
    pub(super) fn iter(&self) -> impl Iterator<Item = ((usize, usize), F)> + '_ {
        let (sparse, direct, dense) = match self {
            Self::Sparse { matrix, interner } => (Some((matrix, interner)), None, None),
            Self::Direct(matrix) => (None, Some(matrix), None),
            Self::Dense(matrix) => (None, None, Some(matrix)),
        };
        sparse
            .into_iter()
            .flat_map(|(matrix, interner)| {
                matrix.iter().map(move |(index, value)| {
                    (
                        index,
                        interner.get(value).expect("invalid core coefficient"),
                    )
                })
            })
            .chain(direct.into_iter().flat_map(|matrix| matrix.iter()))
            .chain(dense.into_iter().flat_map(|matrix| {
                matrix
                    .values
                    .iter()
                    .enumerate()
                    .filter_map(move |(index, &value)| {
                        (!value.is_zero())
                            .then(|| ((index / matrix.num_cols, index % matrix.num_cols), value))
                    })
            }))
    }

    /// Select storage by estimated heap bytes, including coefficient diversity.
    /// The reverse-map allowance is conservative, not an exact allocator model.
    /// Dense inputs retain their buffer. No existing core is converted in
    /// place.
    pub(super) fn from_dense(dense: DenseMatrix<F>) -> Self {
        let nnz = dense.values.iter().filter(|value| !value.is_zero()).count();
        let dense_bytes = dense.values.capacity().saturating_mul(size_of::<F>());
        let direct_bytes = Self::direct_bytes(dense.num_rows, nnz);
        if Self::prefer_sparse(
            dense.num_rows,
            nnz,
            dense_bytes.min(direct_bytes),
            dense.values.iter().copied(),
        ) {
            Self::encode_sparse(dense, nnz)
        } else if direct_bytes < dense_bytes {
            let mut direct = DirectSparseMatrix::new(dense.num_cols);
            direct.columns.reserve(nnz);
            direct.values.reserve(nnz);
            for row in 0..dense.num_rows {
                direct.push_row((0..dense.num_cols).filter_map(|column| {
                    let value = dense[(row, column)];
                    (!value.is_zero()).then_some((column, value))
                }));
            }
            Self::Direct(direct)
        } else {
            Self::Dense(dense)
        }
    }

    fn prefer_sparse(
        num_rows: usize,
        nnz: usize,
        dense_bytes: usize,
        values: impl Iterator<Item = F>,
    ) -> bool {
        let sparse_base = num_rows
            .saturating_mul(size_of::<u32>())
            .saturating_add(
                nnz.saturating_mul(size_of::<u32>() + size_of::<InternedFieldElement>()),
            )
            .saturating_add(size_of::<Interner<F>>() + 2 * size_of::<usize>());
        if sparse_base >= dense_bytes {
            return false;
        }
        // One stored field value plus a reverse-map entry with slack for hash
        // table capacity and control bytes. Repeated +/-1 values cost very little.
        let per_distinct = size_of::<F>() + 2 * size_of::<(F, usize)>();
        // Bound dictionary probing even when the logical dense matrix is huge.
        // High-diversity factors use direct CSR instead of multi-GB hash tables.
        let max_distinct = ((dense_bytes - sparse_base) / per_distinct).min(4096);
        let mut distinct = HashSet::new();
        for value in values {
            if !value.is_zero() && distinct.insert(value) && distinct.len() > max_distinct {
                return false;
            }
        }
        true
    }

    fn direct_bytes(num_rows: usize, nnz: usize) -> usize {
        (num_rows + 1)
            .saturating_mul(size_of::<usize>())
            .saturating_add(nnz.saturating_mul(size_of::<u32>() + size_of::<F>()))
    }

    /// Sorted, duplicate-free nonzero rows can stay sparse throughout assembly.
    pub(super) fn from_rows(num_cols: usize, rows: Vec<Vec<(usize, F)>>) -> Self {
        let nnz = rows.iter().map(Vec::len).sum();
        let dense_bytes = rows
            .len()
            .saturating_mul(num_cols)
            .saturating_mul(size_of::<F>());
        let direct_bytes = Self::direct_bytes(rows.len(), nnz);
        if !Self::prefer_sparse(
            rows.len(),
            nnz,
            dense_bytes.min(direct_bytes),
            rows.iter().flatten().map(|&(_, value)| value),
        ) {
            if direct_bytes < dense_bytes {
                let mut direct = DirectSparseMatrix::new(num_cols);
                direct.columns.reserve(nnz);
                direct.values.reserve(nnz);
                direct.offsets.reserve(rows.len());
                for row in rows {
                    direct.push_row(row.into_iter());
                }
                return Self::Direct(direct);
            }
            let mut dense = DenseMatrix::zeros(rows.len(), num_cols);
            for (row, entries) in rows.into_iter().enumerate() {
                for (column, value) in entries {
                    dense[(row, column)] = value;
                }
            }
            return Self::Dense(dense);
        }
        let mut interner = Interner::new();
        let mut matrix = SparseMatrix::new(0, num_cols);
        matrix.reserve(rows.len(), nnz);
        for entries in rows {
            matrix.push_row(entries.into_iter().map(|(column, value)| {
                (
                    u32::try_from(column).expect("MBP column index exceeds u32::MAX"),
                    interner.intern(value),
                )
            }));
        }
        Self::Sparse {
            matrix,
            interner: Arc::new(interner),
        }
    }

    pub(super) fn block(
        &self,
        row: usize,
        num_rows: usize,
        column: usize,
        num_cols: usize,
    ) -> Self {
        match self {
            Self::Dense(matrix) => Self::from_dense(matrix.block(row, num_rows, column, num_cols)),
            Self::Direct(matrix) => {
                let mut block = DirectSparseMatrix::new(num_cols);
                for row in row..row + num_rows {
                    block.push_row(
                        matrix
                            .iter_row(row)
                            .filter(|&(col, _)| (column..column + num_cols).contains(&col))
                            .map(|(col, value)| (col - column, value)),
                    );
                }
                Self::Direct(block)
            }
            Self::Sparse { matrix, interner } => {
                let mut block = SparseMatrix::new(0, num_cols);
                for row in row..row + num_rows {
                    block.push_row(
                        matrix
                            .iter_row(row)
                            .filter(|&(col, _)| (column..column + num_cols).contains(&col))
                            .map(|(col, value)| ((col - column) as u32, value)),
                    );
                }
                Self::Sparse {
                    matrix:   block,
                    interner: Arc::clone(interner),
                }
            }
        }
    }

    pub(super) fn multiply(&self, rhs: &Self) -> Self {
        assert_eq!(self.num_cols(), rhs.num_rows());
        match (self, rhs) {
            (lhs, rhs) if lhs.is_sparse() && rhs.is_sparse() => {
                // Gustavson row accumulation: only one output row is dense.
                let num_cols = rhs.num_cols();
                let mut values = vec![F::ZERO; num_cols];
                let mut seen = vec![false; num_cols];
                let mut touched = Vec::new();
                let mut rows = Vec::with_capacity(lhs.num_rows());
                for row in 0..self.num_rows() {
                    for (inner, coefficient) in lhs.iter_row(row) {
                        for (column, value) in rhs.iter_row(inner) {
                            if !seen[column] {
                                seen[column] = true;
                                touched.push(column);
                            }
                            values[column] += if coefficient == F::ONE {
                                value
                            } else if coefficient == -F::ONE {
                                -value
                            } else if value == F::ONE {
                                coefficient
                            } else if value == -F::ONE {
                                -coefficient
                            } else {
                                coefficient * value
                            };
                        }
                    }
                    touched.sort_unstable();
                    let mut entries = Vec::with_capacity(touched.len());
                    for column in touched.drain(..) {
                        let value = std::mem::replace(&mut values[column], F::ZERO);
                        seen[column] = false;
                        if !value.is_zero() {
                            entries.push((column, value));
                        }
                    }
                    rows.push(entries);
                }
                Self::from_rows(num_cols, rows)
            }
            (Self::Dense(lhs), _) => Self::from_dense(lhs.multiply_core(rhs)),
            (_, Self::Dense(rhs)) => Self::from_dense(DenseMatrix::core_multiply(self, rhs)),
            _ => unreachable!("all sparse combinations handled above"),
        }
    }

    fn encode_sparse(dense: DenseMatrix<F>, nnz: usize) -> Self {
        let mut interner = Interner::new();
        let mut matrix = SparseMatrix::new(0, dense.num_cols);
        matrix.reserve(dense.num_rows, nnz);
        for row in 0..dense.num_rows {
            matrix.push_row((0..dense.num_cols).filter_map(|column| {
                let value = dense[(row, column)];
                (!value.is_zero()).then(|| {
                    (
                        u32::try_from(column).expect("MBP column index exceeds u32::MAX"),
                        interner.intern(value),
                    )
                })
            }));
        }
        Self::Sparse {
            matrix,
            interner: Arc::new(interner),
        }
    }

    #[cfg(test)]
    pub(super) fn force_sparse(dense: DenseMatrix<F>) -> Self {
        let nnz = dense.values.iter().filter(|value| !value.is_zero()).count();
        Self::encode_sparse(dense, nnz)
    }

    #[cfg(test)]
    pub(super) fn force_direct(dense: DenseMatrix<F>) -> Self {
        let mut direct = DirectSparseMatrix::new(dense.num_cols);
        for row in 0..dense.num_rows {
            direct.push_row((0..dense.num_cols).filter_map(|column| {
                let value = dense[(row, column)];
                (!value.is_zero()).then_some((column, value))
            }));
        }
        Self::Direct(direct)
    }
}

impl<F: Field> MbpLayer<F> {
    #[cfg(test)]
    pub(super) fn from_dense(matrices: [DenseMatrix<F>; 2]) -> Self {
        Self {
            matrices: matrices.map(Core::from_dense),
        }
    }

    pub(super) fn from_sparse(matrices: [SparseMatrix; 2], interner: Interner<F>) -> Self {
        let interner = Arc::new(interner);
        Self {
            matrices: matrices.map(|matrix| Core::Sparse {
                matrix,
                interner: Arc::clone(&interner),
            }),
        }
    }
}

/// Dense workspaces and products. Stored cores independently use dense values,
/// direct CSR, or interned sparse entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::cmd) struct DenseMatrix<F> {
    pub(super) num_rows: usize,
    pub(super) num_cols: usize,
    pub(super) values:   Vec<F>,
}

impl<F: Field> DenseMatrix<F> {
    pub(super) fn zeros(num_rows: usize, num_cols: usize) -> Self {
        Self {
            num_rows,
            num_cols,
            values: vec![F::ZERO; num_rows * num_cols],
        }
    }

    #[cfg(test)]
    pub(super) fn from_sparse(matrix: &SparseMatrix, interner: &Interner<F>) -> Self {
        let mut dense = Self::zeros(matrix.num_rows, matrix.num_cols);
        for ((row, column), value) in matrix.hydrate(interner).iter() {
            dense[(row, column)] = value;
        }
        dense
    }

    pub(super) fn stack(layer: &MbpLayer<F>, vertically: bool) -> Self {
        let num_rows = layer.matrices[0].num_rows();
        let num_cols = layer.matrices[0].num_cols();
        let mut dense = if vertically {
            Self::zeros(2 * num_rows, num_cols)
        } else {
            Self::zeros(num_rows, 2 * num_cols)
        };
        for (bit, matrix) in layer.matrices.iter().enumerate() {
            assert_eq!((matrix.num_rows(), matrix.num_cols()), (num_rows, num_cols));
            for ((row, column), value) in matrix.iter() {
                let row = row + if vertically { bit * num_rows } else { 0 };
                let column = column + if vertically { 0 } else { bit * num_cols };
                dense[(row, column)] = value;
            }
        }
        dense
    }

    pub(super) fn multiply_core(&self, rhs: &Core<F>) -> Self {
        match rhs {
            Core::Sparse { matrix, interner } => self.multiply_sparse(matrix, interner),
            Core::Direct(matrix) => {
                assert_eq!(self.num_cols, matrix.num_rows());
                let mut product = Self::zeros(self.num_rows, matrix.num_cols);
                let minus_one = -F::ONE;
                for row in 0..self.num_rows {
                    for inner in 0..self.num_cols {
                        let coefficient = self[(row, inner)];
                        if coefficient.is_zero() {
                            continue;
                        }
                        for (column, value) in matrix.iter_row(inner) {
                            product[(row, column)] += if value == F::ONE {
                                coefficient
                            } else if value == minus_one {
                                -coefficient
                            } else {
                                coefficient * value
                            };
                        }
                    }
                }
                product
            }
            Core::Dense(matrix) => self.multiply(matrix),
        }
    }

    pub(super) fn core_multiply(lhs: &Core<F>, rhs: &Self) -> Self {
        match lhs {
            Core::Sparse { matrix, interner } => Self::sparse_multiply(matrix, interner, rhs),
            Core::Direct(matrix) => {
                assert_eq!(matrix.num_cols, rhs.num_rows);
                let mut product = Self::zeros(matrix.num_rows(), rhs.num_cols);
                let minus_one = -F::ONE;
                for ((row, inner), coefficient) in matrix.iter() {
                    for column in 0..rhs.num_cols {
                        let value = rhs[(inner, column)];
                        product[(row, column)] += if coefficient == F::ONE {
                            value
                        } else if coefficient == minus_one {
                            -value
                        } else {
                            coefficient * value
                        };
                    }
                }
                product
            }
            Core::Dense(matrix) => matrix.multiply(rhs),
        }
    }

    pub(super) fn block(
        &self,
        row: usize,
        num_rows: usize,
        column: usize,
        num_cols: usize,
    ) -> Self {
        let mut block = Self::zeros(num_rows, num_cols);
        for i in 0..num_rows {
            for j in 0..num_cols {
                block[(i, j)] = self[(row + i, column + j)];
            }
        }
        block
    }

    /// Dense R times a sparse core: O(rows(R) * nnz(core)) field operations,
    /// allocating only the reduced output, not a dense copy of the sparse core.
    pub(super) fn multiply_sparse(&self, rhs: &SparseMatrix, interner: &Interner<F>) -> Self {
        assert_eq!(self.num_cols, rhs.num_rows);
        let mut product = Self::zeros(self.num_rows, rhs.num_cols);
        if self.num_rows == 0 || rhs.num_cols == 0 || rhs.num_entries() == 0 {
            return product;
        }
        let rhs = rhs.hydrate(interner);
        let minus_one = -F::ONE;
        for row in 0..self.num_rows {
            for inner in 0..self.num_cols {
                let coefficient = self[(row, inner)];
                if coefficient.is_zero() {
                    continue;
                }
                for (column, value) in rhs.iter_row(inner) {
                    // Original BDD transitions use only +/-1. Avoid general
                    // field multiplication for these common coefficients.
                    if value == F::ONE {
                        product[(row, column)] += coefficient;
                    } else if value == minus_one {
                        product[(row, column)] -= coefficient;
                    } else {
                        product[(row, column)] += coefficient * value;
                    }
                }
            }
        }
        product
    }

    /// Sparse core times dense L: O(nnz(core) * cols(L)) field operations.
    pub(super) fn sparse_multiply(lhs: &SparseMatrix, interner: &Interner<F>, rhs: &Self) -> Self {
        assert_eq!(lhs.num_cols, rhs.num_rows);
        let mut product = Self::zeros(lhs.num_rows, rhs.num_cols);
        if rhs.num_cols == 0 {
            return product;
        }
        let minus_one = -F::ONE;
        for ((row, inner), coefficient) in lhs.hydrate(interner).iter() {
            if coefficient.is_zero() {
                continue;
            }
            let target = &mut product.values[row * rhs.num_cols..(row + 1) * rhs.num_cols];
            let source = &rhs.values[inner * rhs.num_cols..(inner + 1) * rhs.num_cols];
            if coefficient == F::ONE {
                for (target, source) in target.iter_mut().zip(source) {
                    *target += source;
                }
            } else if coefficient == minus_one {
                for (target, source) in target.iter_mut().zip(source) {
                    *target -= source;
                }
            } else {
                for (target, source) in target.iter_mut().zip(source) {
                    *target += coefficient * source;
                }
            }
        }
        product
    }

    pub(super) fn multiply(&self, rhs: &Self) -> Self {
        assert_eq!(self.num_cols, rhs.num_rows);
        let mut product = Self::zeros(self.num_rows, rhs.num_cols);
        for row in 0..self.num_rows {
            for inner in 0..self.num_cols {
                let coefficient = self[(row, inner)];
                if coefficient.is_zero() {
                    continue;
                }
                for column in 0..rhs.num_cols {
                    product[(row, column)] += coefficient * rhs[(inner, column)];
                }
            }
        }
        product
    }

    /// A = L R: take the original pivot columns as L and the nonzero RREF
    /// rows as R. This also handles rank zero and zero-sized dimensions.
    pub(super) fn rank_factor(self) -> (Self, Self) {
        let mut reduced = self.clone();
        let mut pivots = Vec::new();
        for column in 0..self.num_cols {
            let rank = pivots.len();
            let Some(pivot) = (rank..self.num_rows).find(|&row| !reduced[(row, column)].is_zero())
            else {
                continue;
            };
            for j in 0..self.num_cols {
                reduced
                    .values
                    .swap(rank * self.num_cols + j, pivot * self.num_cols + j);
            }
            let inverse = reduced[(rank, column)].inverse().expect("nonzero pivot");
            for j in column..self.num_cols {
                reduced[(rank, j)] *= inverse;
            }
            for row in 0..self.num_rows {
                if row == rank {
                    continue;
                }
                let coefficient = reduced[(row, column)];
                if coefficient.is_zero() {
                    continue;
                }
                for j in column..self.num_cols {
                    let pivot_value = reduced[(rank, j)];
                    reduced[(row, j)] -= coefficient * pivot_value;
                }
            }
            pivots.push(column);
        }
        let mut left = Self::zeros(self.num_rows, pivots.len());
        for row in 0..self.num_rows {
            for (j, &column) in pivots.iter().enumerate() {
                left[(row, j)] = self[(row, column)];
            }
        }
        let right = reduced.block(0, pivots.len(), 0, self.num_cols);
        (left, right)
    }
}

impl<F> Index<(usize, usize)> for DenseMatrix<F> {
    type Output = F;

    fn index(&self, (row, column): (usize, usize)) -> &F {
        &self.values[row * self.num_cols + column]
    }
}

impl<F> IndexMut<(usize, usize)> for DenseMatrix<F> {
    fn index_mut(&mut self, (row, column): (usize, usize)) -> &mut F {
        &mut self.values[row * self.num_cols + column]
    }
}

#[cfg(test)]
mod tests {
    use {super::*, provekit_backend_bn254::FieldElement as F};

    fn sparse_values() -> DenseMatrix<F> {
        let mut dense = DenseMatrix::zeros(64, 128);
        for row in 0..64 {
            dense[(row, row)] = F::from(1u64);
            dense[(row, row + 64)] = F::from(-1i64);
        }
        dense
    }

    fn unique_values() -> DenseMatrix<F> {
        let mut dense = DenseMatrix::zeros(64, 128);
        for (index, value) in dense.values.iter_mut().enumerate() {
            *value = F::from((index + 1) as u64);
        }
        dense
    }

    fn assert_values(core: &Core<F>, expected: &DenseMatrix<F>) {
        assert_eq!(
            (core.num_rows(), core.num_cols()),
            (expected.num_rows, expected.num_cols)
        );
        let mut actual = DenseMatrix::zeros(core.num_rows(), core.num_cols());
        for ((row, column), value) in core.iter() {
            actual[(row, column)] = value;
        }
        assert_eq!(&actual, expected);
    }

    #[test]
    fn sparse_and_diverse_dense_cores_choose_different_storage() {
        let sparse = sparse_values();
        let core = Core::from_dense(sparse.clone());
        assert!(matches!(core, Core::Sparse { .. }));
        assert_values(&core, &sparse);

        let dense = unique_values();
        let expected = dense.clone();
        let pointer = dense.values.as_ptr();
        let core = Core::from_dense(dense);
        let Core::Dense(ref matrix) = core else {
            panic!("expected dense storage")
        };
        assert_eq!(
            matrix.values.as_ptr(),
            pointer,
            "retain the original dense buffer"
        );
        assert_values(&core, &expected);
    }

    #[test]
    fn diverse_sparse_values_use_direct_csr_without_a_dictionary() {
        let rows: Vec<_> = (0..128)
            .map(|row| {
                (0..64)
                    .map(|column| (column * 32, F::from((row * 64 + column + 1) as u64)))
                    .collect()
            })
            .collect();
        let core = Core::from_rows(4096, rows);
        assert!(matches!(core, Core::Direct(_)));
        assert_eq!(core.nnz(), 8192);
        assert_eq!(core.iter_row(127).count(), 64);
        let block = core.block(120, 8, 32, 128);
        assert_eq!(
            (block.num_rows(), block.num_cols(), block.nnz()),
            (8, 128, 32)
        );
        let mut expected = DenseMatrix::zeros(8, 128);
        for row in 0..8 {
            for column in 0..4 {
                expected[(row, column * 32)] = F::from(((row + 120) * 64 + column + 2) as u64);
            }
        }
        assert_values(&block, &expected);
    }

    #[test]
    fn coefficient_repetition_changes_the_choice_at_equal_occupancy() {
        let dense = unique_values();
        let mut repeated = dense.clone();
        repeated.values.fill(F::from(1u64));
        assert!(matches!(Core::from_dense(dense), Core::Dense(_)));
        let core = Core::from_dense(repeated.clone());
        assert!(matches!(core, Core::Sparse { .. }));
        assert_values(&core, &repeated);
    }

    #[test]
    fn mixed_layers_stack_correctly_in_both_directions() {
        let sparse = sparse_values();
        let dense = unique_values();
        let layer = MbpLayer::from_dense([sparse.clone(), dense.clone()]);
        assert!(matches!(layer.matrices[0], Core::Sparse { .. }));
        assert!(matches!(layer.matrices[1], Core::Dense(_)));
        for vertically in [false, true] {
            let stacked = DenseMatrix::stack(&layer, vertically);
            for row in 0..64 {
                for column in 0..128 {
                    assert_eq!(stacked[(row, column)], sparse[(row, column)]);
                    let index = if vertically {
                        (row + 64, column)
                    } else {
                        (row, column + 128)
                    };
                    assert_eq!(stacked[index], dense[(row, column)]);
                }
            }
        }
    }

    #[test]
    fn zero_shapes_and_all_zero_values_preserve_their_dimensions() {
        for rows in [0, 1, 64] {
            for columns in [0, 1, 128] {
                let dense = DenseMatrix::<F>::zeros(rows, columns);
                let core = Core::from_dense(dense.clone());
                assert_values(&core, &dense);
                assert!(core.iter().next().is_none());
            }
        }
    }

    #[test]
    fn sparse_assembly_splitting_and_products_avoid_dense_storage() {
        let rows: Vec<_> = (0..64)
            .map(|row| vec![(row, F::from(1u64)), (row + 64, F::from(-1i64))])
            .collect();
        let core = Core::from_rows(128, rows);
        let Core::Sparse { interner, .. } = &core else {
            panic!("expected sparse assembly")
        };
        let block = core.block(0, 64, 0, 64);
        let Core::Sparse {
            interner: block_interner,
            ..
        } = &block
        else {
            panic!("expected sparse block")
        };
        assert!(Arc::ptr_eq(interner, block_interner));
        assert_eq!(block.nnz(), 64);

        let rows: Vec<_> = (0..128)
            .map(|row| vec![(row, F::from(1u64)), (row + 128, F::from(1u64))])
            .collect();
        let rhs = Core::from_rows(4096, rows);
        let product = core.multiply(&rhs);
        assert!(matches!(product, Core::Sparse { .. }));
        assert_eq!(
            (product.num_rows(), product.num_cols(), product.nnz()),
            (64, 4096, 256)
        );
        for ((row, column), value) in product.iter() {
            assert_eq!(column % 64, row);
            assert_eq!(
                value,
                F::from(if (column / 64) % 2 == 0 { 1i64 } else { -1i64 })
            );
        }
    }

    #[test]
    fn sparse_product_removes_exact_cancellations() {
        let lhs = Core::from_rows(3, vec![vec![
            (0, F::from(1u64)),
            (1, F::from(1u64)),
            (2, F::from(1u64)),
        ]]);
        let rhs = Core::from_rows(2, vec![
            vec![(0, F::from(1u64)), (1, F::from(2u64))],
            vec![(0, F::from(-1i64)), (1, F::from(3u64))],
            vec![(0, F::from(1u64)), (1, F::from(-5i64))],
        ]);
        // Force sparse storage even for this deliberately tiny example.
        let to_sparse = |core: Core<F>| {
            let mut dense = DenseMatrix::zeros(core.num_rows(), core.num_cols());
            for ((row, column), value) in core.iter() {
                dense[(row, column)] = value;
            }
            Core::force_sparse(dense)
        };
        let product = to_sparse(lhs).multiply(&to_sparse(rhs));
        assert_eq!(product.iter().collect::<Vec<_>>(), [(
            (0, 0),
            F::from(1u64)
        )]);
    }

    #[test]
    #[ignore = "manual comparison of adaptive and forced core representations"]
    fn benchmark_adaptive_storage() {
        use std::{hint::black_box, time::Instant};

        let mut left = DenseMatrix::zeros(4, 64);
        let mut right = DenseMatrix::zeros(128, 4);
        left.values.fill(F::from(3u64));
        right.values.fill(F::from(5u64));
        for (name, dense) in [
            ("sparse +/-1", sparse_values()),
            ("dense distinct", unique_values()),
        ] {
            let start = Instant::now();
            let adaptive = Core::from_dense(dense.clone());
            let selection = start.elapsed();
            let sparse = Core::force_sparse(dense.clone());
            let dense = Core::Dense(dense);
            for (representation, core) in [
                ("adaptive", &adaptive),
                ("forced sparse", &sparse),
                ("forced dense", &dense),
            ] {
                let start = Instant::now();
                let mut product = DenseMatrix::zeros(0, 0);
                for _ in 0..100 {
                    product = black_box(&left).multiply_core(black_box(core));
                }
                let forward = start.elapsed();
                assert_eq!(product, left.multiply_core(&dense));
                let start = Instant::now();
                for _ in 0..100 {
                    product = DenseMatrix::core_multiply(black_box(core), black_box(&right));
                }
                let backward = start.elapsed();
                assert_eq!(product, DenseMatrix::core_multiply(&dense, &right));
                eprintln!(
                    "{name}, {representation}: 100 forward {forward:?}, 100 backward {backward:?}"
                );
            }
            eprintln!(
                "{name}: selection {selection:?}, chose {}",
                if matches!(adaptive, Core::Dense(_)) {
                    "dense"
                } else {
                    "sparse"
                }
            );
        }
    }
}
