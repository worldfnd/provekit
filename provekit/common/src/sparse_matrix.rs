use {
    crate::{FieldElement, InternedFieldElement, Interner},
    ark_std::Zero,
    rayon::{
        iter::{IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
        slice::ParallelSliceMut,
    },
    serde::{
        de::{SeqAccess, Visitor},
        ser::SerializeStruct,
        Deserialize, Deserializer, Serialize, Serializer,
    },
    std::{
        fmt::{self, Debug},
        ops::{Mul, Range},
    },
};

#[derive(Debug, Clone, Copy)]
pub struct DeltaEncodingStats {
    pub total_entries:  usize,
    pub absolute_bytes: usize,
    pub delta_bytes:    usize,
}

impl DeltaEncodingStats {
    pub const fn savings_bytes(&self) -> usize {
        self.absolute_bytes.saturating_sub(self.delta_bytes)
    }

    pub fn savings_percent(&self) -> f64 {
        if self.absolute_bytes == 0 {
            0.0
        } else {
            self.savings_bytes() as f64 / self.absolute_bytes as f64 * 100.0
        }
    }
}

const fn varint_size(value: u32) -> usize {
    match value {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        0x4000..=0x1f_ffff => 3,
        0x20_0000..=0xfff_ffff => 4,
        _ => 5,
    }
}

/// A sparse matrix with interned field elements.
///
/// Uses delta encoding for column indices during serialization to reduce size.
/// Within each row, the first column index is stored as absolute, and
/// subsequent columns are stored as deltas from the previous column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMatrix {
    /// The number of rows in the matrix.
    pub num_rows: usize,

    /// The number of columns in the matrix.
    pub num_cols: usize,

    // List of indices in `col_indices` such that the column index is the start of a new row.
    new_row_indices: Vec<u32>,

    /// List of column indices that have values (absolute values in memory).
    col_indices: Vec<u32>,

    /// List of values.
    values: Vec<InternedFieldElement>,
}

/// Convert absolute column indices to delta-encoded indices per row.
fn encode_col_deltas(
    col_indices: &[u32],
    new_row_indices: &[u32],
    total_entries: usize,
) -> Vec<u32> {
    let mut deltas = Vec::with_capacity(col_indices.len());
    let num_rows = new_row_indices.len();

    for row in 0..num_rows {
        let start = new_row_indices[row] as usize;
        let end = new_row_indices
            .get(row + 1)
            .map_or(total_entries, |&v| v as usize);

        let row_cols = &col_indices[start..end];
        if row_cols.is_empty() {
            continue;
        }

        debug_assert!(
            row_cols.windows(2).all(|w| w[0] <= w[1]),
            "Column indices must be sorted within each row"
        );

        // First column is stored as absolute
        deltas.push(row_cols[0]);

        // Subsequent columns stored as delta from previous
        for i in 1..row_cols.len() {
            deltas.push(row_cols[i] - row_cols[i - 1]);
        }
    }

    deltas
}

/// Convert delta-encoded column indices back to absolute indices per row.
fn decode_col_deltas(deltas: &[u32], new_row_indices: &[u32], total_entries: usize) -> Vec<u32> {
    let mut col_indices = Vec::with_capacity(deltas.len());
    let num_rows = new_row_indices.len();

    let mut delta_idx = 0;
    for row in 0..num_rows {
        let start = new_row_indices[row] as usize;
        let end = new_row_indices
            .get(row + 1)
            .map_or(total_entries, |&v| v as usize);

        let row_len = end - start;
        if row_len == 0 {
            continue;
        }

        // First column is absolute
        let first_col = deltas[delta_idx];
        col_indices.push(first_col);
        delta_idx += 1;

        // Subsequent columns are cumulative deltas
        let mut prev_col = first_col;
        for _ in 1..row_len {
            let col = prev_col + deltas[delta_idx];
            col_indices.push(col);
            prev_col = col;
            delta_idx += 1;
        }
    }

    col_indices
}

impl Serialize for SparseMatrix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let col_deltas =
            encode_col_deltas(&self.col_indices, &self.new_row_indices, self.values.len());

        let mut state = serializer.serialize_struct("SparseMatrix", 5)?;
        state.serialize_field("num_rows", &self.num_rows)?;
        state.serialize_field("num_cols", &self.num_cols)?;
        state.serialize_field("new_row_indices", &self.new_row_indices)?;
        state.serialize_field("col_deltas", &col_deltas)?;
        state.serialize_field("values", &self.values)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SparseMatrix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            NumRows,
            NumCols,
            NewRowIndices,
            ColDeltas,
            Values,
        }

        struct SparseMatrixVisitor;

        impl<'de> Visitor<'de> for SparseMatrixVisitor {
            type Value = SparseMatrix;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SparseMatrix")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<SparseMatrix, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let num_rows = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let num_cols = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let new_row_indices: Vec<u32> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let col_deltas: Vec<u32> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let values: Vec<InternedFieldElement> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;

                let col_indices = decode_col_deltas(&col_deltas, &new_row_indices, values.len());

                Ok(SparseMatrix {
                    num_rows,
                    num_cols,
                    new_row_indices,
                    col_indices,
                    values,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<SparseMatrix, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut num_rows = None;
                let mut num_cols = None;
                let mut new_row_indices: Option<Vec<u32>> = None;
                let mut col_deltas: Option<Vec<u32>> = None;
                let mut values: Option<Vec<InternedFieldElement>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::NumRows => {
                            if num_rows.is_some() {
                                return Err(serde::de::Error::duplicate_field("num_rows"));
                            }
                            num_rows = Some(map.next_value()?);
                        }
                        Field::NumCols => {
                            if num_cols.is_some() {
                                return Err(serde::de::Error::duplicate_field("num_cols"));
                            }
                            num_cols = Some(map.next_value()?);
                        }
                        Field::NewRowIndices => {
                            if new_row_indices.is_some() {
                                return Err(serde::de::Error::duplicate_field("new_row_indices"));
                            }
                            new_row_indices = Some(map.next_value()?);
                        }
                        Field::ColDeltas => {
                            if col_deltas.is_some() {
                                return Err(serde::de::Error::duplicate_field("col_deltas"));
                            }
                            col_deltas = Some(map.next_value()?);
                        }
                        Field::Values => {
                            if values.is_some() {
                                return Err(serde::de::Error::duplicate_field("values"));
                            }
                            values = Some(map.next_value()?);
                        }
                    }
                }

                let num_rows =
                    num_rows.ok_or_else(|| serde::de::Error::missing_field("num_rows"))?;
                let num_cols =
                    num_cols.ok_or_else(|| serde::de::Error::missing_field("num_cols"))?;
                let new_row_indices = new_row_indices
                    .ok_or_else(|| serde::de::Error::missing_field("new_row_indices"))?;
                let col_deltas =
                    col_deltas.ok_or_else(|| serde::de::Error::missing_field("col_deltas"))?;
                let values = values.ok_or_else(|| serde::de::Error::missing_field("values"))?;

                let col_indices = decode_col_deltas(&col_deltas, &new_row_indices, values.len());

                Ok(SparseMatrix {
                    num_rows,
                    num_cols,
                    new_row_indices,
                    col_indices,
                    values,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "num_rows",
            "num_cols",
            "new_row_indices",
            "col_deltas",
            "values",
        ];
        deserializer.deserialize_struct("SparseMatrix", FIELDS, SparseMatrixVisitor)
    }
}

/// A hydrated sparse matrix with uninterned field elements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydratedSparseMatrix<'a> {
    pub matrix: &'a SparseMatrix,
    interner:   &'a Interner,
}

impl SparseMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            num_rows:        rows,
            num_cols:        cols,
            new_row_indices: vec![0; rows],
            col_indices:     Vec::new(),
            values:          Vec::new(),
        }
    }

    pub const fn hydrate<'a>(&'a self, interner: &'a Interner) -> HydratedSparseMatrix<'a> {
        HydratedSparseMatrix {
            matrix: self,
            interner,
        }
    }

    pub fn num_entries(&self) -> usize {
        self.values.len()
    }

    pub fn delta_encoding_stats(&self) -> DeltaEncodingStats {
        let deltas = encode_col_deltas(&self.col_indices, &self.new_row_indices, self.values.len());

        let absolute_bytes: usize = self.col_indices.iter().map(|&v| varint_size(v)).sum();
        let delta_bytes: usize = deltas.iter().map(|&v| varint_size(v)).sum();

        DeltaEncodingStats {
            total_entries: self.col_indices.len(),
            absolute_bytes,
            delta_bytes,
        }
    }

    pub fn grow(&mut self, rows: usize, cols: usize) {
        // TODO: Make it default infinite size instead.
        assert!(rows >= self.num_rows);
        assert!(cols >= self.num_cols);
        self.num_rows = rows;
        self.num_cols = cols;
        self.new_row_indices.resize(rows, self.values.len() as u32);
    }

    /// Set the value at the given row and column.
    pub fn set(&mut self, row: usize, col: usize, value: InternedFieldElement) {
        assert!(row < self.num_rows, "row index out of bounds");
        assert!(col < self.num_cols, "column index out of bounds");

        // Find the row
        let row_range = self.row_range(row);
        let cols = &self.col_indices[row_range.clone()];

        // Find the column
        match cols.binary_search(&(col as u32)) {
            Ok(i) => {
                // Column already exists
                self.values[row_range][i] = value;
            }
            Err(i) => {
                // Need to insert column at i
                let i = i + row_range.start;
                self.col_indices.insert(i, col as u32);
                self.values.insert(i, value);
                for index in &mut self.new_row_indices[row + 1..] {
                    *index += 1;
                }
            }
        }
    }

    /// Iterate over the non-default entries of a row of the matrix.
    pub fn iter_row(
        &self,
        row: usize,
    ) -> impl Iterator<Item = (usize, InternedFieldElement)> + use<'_> {
        let row_range = self.row_range(row);
        let cols = self.col_indices[row_range.clone()].iter().copied();
        let values = self.values[row_range].iter().copied();
        cols.zip(values).map(|(col, value)| (col as usize, value))
    }

    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), InternedFieldElement)> + use<'_> {
        (0..self.new_row_indices.len()).flat_map(|row| {
            self.iter_row(row)
                .map(move |(col, value)| ((row, col), value))
        })
    }

    pub fn row_range(&self, row: usize) -> Range<usize> {
        let start = *self
            .new_row_indices
            .get(row)
            .expect("Row index out of bounds") as usize;
        let end = self
            .new_row_indices
            .get(row + 1)
            .map_or(self.values.len(), |&v| v as usize);
        start..end
    }

    /// Transpose the matrix, swapping rows and columns.
    ///
    /// Returns a new `SparseMatrix` where entry (i, j) in the original
    /// becomes (j, i) in the result. The interned values are preserved
    /// and remain valid for the same `Interner`.
    pub fn transpose(&self) -> SparseMatrix {
        let nnz = self.values.len();

        let mut entries: Vec<(u32, u32, InternedFieldElement)> = Vec::with_capacity(nnz);
        for row in 0..self.num_rows {
            let range = self.row_range(row);
            for i in range {
                entries.push((self.col_indices[i], row as u32, self.values[i]));
            }
        }

        entries.par_sort_unstable_by_key(|&(new_row, new_col, _)| (new_row, new_col));
        debug_assert!(
            entries
                .windows(2)
                .all(|w| (w[0].0, w[0].1) != (w[1].0, w[1].1)),
            "Duplicate (row, col) entries in sparse matrix transpose"
        );

        let mut new_row_indices = Vec::with_capacity(self.num_cols);
        let mut col_indices = Vec::with_capacity(nnz);
        let mut values = Vec::with_capacity(nnz);

        let mut entry_idx = 0;
        for row in 0..self.num_cols {
            new_row_indices.push(entry_idx as u32);
            while entry_idx < entries.len() && entries[entry_idx].0 == row as u32 {
                col_indices.push(entries[entry_idx].1);
                values.push(entries[entry_idx].2);
                entry_idx += 1;
            }
        }

        SparseMatrix {
            num_rows: self.num_cols,
            num_cols: self.num_rows,
            new_row_indices,
            col_indices,
            values,
        }
    }

    /// Remap column indices using provided mapping function - in-place and
    /// parallel
    pub fn remap_columns<F>(&mut self, remap_fn: F)
    where
        F: Fn(usize) -> usize + Send + Sync,
    {
        // Step 1: Remap all column indices in parallel
        self.col_indices.par_iter_mut().for_each(|col| {
            *col = remap_fn(*col as usize) as u32;
        });

        // Step 2: Re-sort each row sequentially (fast enough, avoids unsafe)
        for row in 0..self.num_rows {
            let start = self.new_row_indices[row] as usize;
            let end = self
                .new_row_indices
                .get(row + 1)
                .map_or(self.col_indices.len(), |&v| v as usize);

            let row_cols = &mut self.col_indices[start..end];
            let row_vals = &mut self.values[start..end];

            let mut pairs: Vec<_> = row_cols
                .iter()
                .zip(row_vals.iter())
                .map(|(&c, &v)| (c, v))
                .collect();
            pairs.sort_unstable_by_key(|(c, _)| *c);

            for (i, (c, v)) in pairs.into_iter().enumerate() {
                row_cols[i] = c;
                row_vals[i] = v;
            }
        }
    }

    pub fn reserve(&mut self, additional_rows: usize, additional_entries: usize) {
        self.new_row_indices.reserve(additional_rows);
        self.col_indices.reserve(additional_entries);
        self.values.reserve(additional_entries);
    }

    #[inline]
    pub fn push_row(&mut self, entries: impl Iterator<Item = (u32, InternedFieldElement)>) {
        self.new_row_indices.push(self.values.len() as u32);
        self.num_rows += 1;
        for (col, value) in entries {
            debug_assert!((col as usize) < self.num_cols, "column index out of bounds");
            self.col_indices.push(col);
            self.values.push(value);
        }
    }

    /// Get the value at (row, col), or None if not present.
    pub fn get(&self, row: usize, col: usize) -> Option<InternedFieldElement> {
        let range = self.row_range(row);
        let cols = &self.col_indices[range.clone()];
        match cols.binary_search(&(col as u32)) {
            Ok(i) => Some(self.values[range.start + i]),
            Err(_) => None,
        }
    }

    /// Get all (col, value) entries for a row as a Vec.
    pub fn get_row_entries(&self, row: usize) -> Vec<(usize, InternedFieldElement)> {
        self.iter_row(row).collect()
    }

    /// Replace a row's entries entirely. The new entries must be sorted by
    /// column.
    pub fn replace_row(&mut self, row: usize, entries: &[(usize, InternedFieldElement)]) {
        let range = self.row_range(row);
        let old_len = range.len();
        let new_len = entries.len();

        let new_cols: Vec<u32> = entries.iter().map(|(c, _)| *c as u32).collect();
        let new_vals: Vec<InternedFieldElement> = entries.iter().map(|(_, v)| *v).collect();

        self.col_indices.splice(range.clone(), new_cols);
        self.values.splice(range.clone(), new_vals);

        let diff = new_len as i64 - old_len as i64;
        if diff != 0 {
            for index in &mut self.new_row_indices[row + 1..] {
                *index = (*index as i64 + diff) as u32;
            }
        }
    }

    /// Remove rows at the given indices. Returns a new matrix.
    pub fn remove_rows(&self, rows_to_remove: &[usize]) -> SparseMatrix {
        let remove_set: std::collections::HashSet<usize> = rows_to_remove.iter().copied().collect();
        let new_num_rows = self.num_rows - rows_to_remove.len();

        let mut new_row_indices = Vec::with_capacity(new_num_rows);
        let mut new_col_indices = Vec::new();
        let mut new_values = Vec::new();

        for row in 0..self.num_rows {
            if remove_set.contains(&row) {
                continue;
            }
            new_row_indices.push(new_col_indices.len() as u32);
            let range = self.row_range(row);
            new_col_indices.extend_from_slice(&self.col_indices[range.clone()]);
            new_values.extend_from_slice(&self.values[range]);
        }

        SparseMatrix {
            num_rows: new_num_rows,
            num_cols: self.num_cols,
            new_row_indices,
            col_indices: new_col_indices,
            values: new_values,
        }
    }

    /// Count how many rows reference each column. Returns a Vec of length
    /// num_cols.
    pub fn column_occurrence_count(&self) -> Vec<usize> {
        let mut counts = vec![0usize; self.num_cols];
        for &col in &self.col_indices {
            counts[col as usize] += 1;
        }
        counts
    }
}

impl HydratedSparseMatrix<'_> {
    /// Iterate over the non-default entries of a row of the matrix.
    pub fn iter_row(&self, row: usize) -> impl Iterator<Item = (usize, FieldElement)> + use<'_> {
        self.matrix.iter_row(row).map(|(col, value)| {
            (
                col,
                self.interner.get(value).expect("Value not in interner."),
            )
        })
    }

    /// Iterate over the non-default entries of the matrix.
    pub fn iter(&self) -> impl Iterator<Item = ((usize, usize), FieldElement)> + use<'_> {
        self.matrix.iter().map(|((i, j), v)| {
            (
                (i, j),
                self.interner.get(v).expect("Value not in interner."),
            )
        })
    }
}

/// Right multiplication by vector (parallel over rows).
impl Mul<&[FieldElement]> for HydratedSparseMatrix<'_> {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: &[FieldElement]) -> Self::Output {
        assert_eq!(
            self.matrix.num_cols,
            rhs.len(),
            "Vector length does not match number of columns."
        );
        (0..self.matrix.num_rows)
            .into_par_iter()
            .map(|row| {
                self.iter_row(row)
                    .map(|(col, value)| value * rhs[col])
                    .fold(FieldElement::zero(), |acc, x| acc + x)
            })
            .collect()
    }
}

/// Left multiplication by vector (sequential scatter pattern).
///
/// The primary call site (`calculate_external_row_of_r1cs_matrices`)
/// now uses transpose + parallel right-multiply instead.
impl Mul<HydratedSparseMatrix<'_>> for &[FieldElement] {
    type Output = Vec<FieldElement>;

    fn mul(self, rhs: HydratedSparseMatrix<'_>) -> Self::Output {
        assert_eq!(
            self.len(),
            rhs.matrix.num_rows,
            "Vector length does not match number of rows."
        );
        let mut result = vec![FieldElement::zero(); rhs.matrix.num_cols];
        for ((i, j), value) in rhs.iter() {
            result[j] += value * self[i];
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_encoding_roundtrip() {
        let col_indices = vec![3, 15, 100, 5, 50, 200];
        let new_row_indices = vec![0, 3];
        let total_entries = 6;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);

        assert_eq!(col_indices, decoded);
    }

    #[test]
    fn test_delta_encoding_values() {
        let col_indices = vec![3, 15, 100];
        let new_row_indices = vec![0];
        let total_entries = 3;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);

        assert_eq!(deltas, vec![3, 12, 85]);
    }

    #[test]
    fn test_delta_encoding_multiple_rows() {
        let col_indices = vec![0, 10, 20, 5, 15];
        let new_row_indices = vec![0, 3];
        let total_entries = 5;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        assert_eq!(deltas, vec![0, 10, 10, 5, 10]);

        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);
        assert_eq!(col_indices, decoded);
    }

    #[test]
    fn test_delta_encoding_empty_row() {
        let col_indices = vec![5, 10];
        let new_row_indices = vec![0, 0, 2];
        let total_entries = 2;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);

        assert_eq!(col_indices, decoded);
    }

    /// Single non-zero in the whole matrix: one row, one column.
    #[test]
    fn test_delta_encoding_single_entry() {
        let col_indices = vec![42];
        let new_row_indices = vec![0];
        let total_entries = 1;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        assert_eq!(deltas, vec![42]);

        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);
        assert_eq!(col_indices, decoded);
    }

    /// Each row has exactly one column; all deltas are absolute (no within-row
    /// deltas).
    #[test]
    fn test_delta_encoding_single_column_per_row() {
        let col_indices = vec![0, 5, 100];
        let new_row_indices = vec![0, 1, 2];
        let total_entries = 3;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        assert_eq!(deltas, vec![0, 5, 100]);

        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);
        assert_eq!(col_indices, decoded);
    }

    /// Consecutive column indices (deltas of 1).
    #[test]
    fn test_delta_encoding_consecutive_columns() {
        let col_indices = vec![10, 11, 12, 13];
        let new_row_indices = vec![0];
        let total_entries = 4;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        assert_eq!(deltas, vec![10, 1, 1, 1]);

        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);
        assert_eq!(col_indices, decoded);
    }

    /// All rows empty: no column indices, only row boundaries.
    #[test]
    fn test_delta_encoding_all_rows_empty() {
        let col_indices: Vec<u32> = vec![];
        let new_row_indices = vec![0, 0, 0];
        let total_entries = 0;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        assert!(deltas.is_empty());

        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);
        assert!(decoded.is_empty());
    }

    /// Last row empty; only earlier rows have entries.
    #[test]
    fn test_delta_encoding_last_row_empty() {
        let col_indices = vec![1, 2, 7];
        let new_row_indices = vec![0, 2, 3];
        let total_entries = 3;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);

        assert_eq!(col_indices, decoded);
    }

    /// Only one row has entries (row 2); rows 0, 1, 3 are empty. Roundtrip
    /// still works.
    #[test]
    fn test_delta_encoding_only_last_row_non_empty() {
        let col_indices = vec![3, 8];
        let new_row_indices = vec![0, 0, 0, 2];
        let total_entries = 2;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        assert_eq!(deltas, vec![3, 5]);

        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);
        assert_eq!(col_indices, decoded);
    }

    /// Large column indices; deltas stay small (no u32 overflow in encoding).
    #[test]
    fn test_delta_encoding_large_column_indices() {
        let col_indices = vec![1_000_000, 1_000_001, 2_000_000];
        let new_row_indices = vec![0];
        let total_entries = 3;

        let deltas = encode_col_deltas(&col_indices, &new_row_indices, total_entries);
        assert_eq!(deltas, vec![1_000_000, 1, 999_999]);

        let decoded = decode_col_deltas(&deltas, &new_row_indices, total_entries);
        assert_eq!(col_indices, decoded);
    }

    #[test]
    fn test_sparse_matrix_serde_roundtrip() {
        let mut interner = Interner::new();
        let val1 = interner.intern(FieldElement::from(1u64));
        let val2 = interner.intern(FieldElement::from(2u64));
        let val3 = interner.intern(FieldElement::from(3u64));

        let mut matrix = SparseMatrix::new(3, 100);
        matrix.grow(3, 100);
        matrix.set(0, 5, val1);
        matrix.set(0, 20, val2);
        matrix.set(1, 50, val3);

        let serialized = postcard::to_allocvec(&matrix).expect("serialization failed");
        let deserialized: SparseMatrix =
            postcard::from_bytes(&serialized).expect("deserialization failed");

        assert_eq!(matrix, deserialized);
    }

    #[test]
    fn test_delta_encoding_size_reduction() {
        let mut interner = Interner::new();
        let val = interner.intern(FieldElement::from(1u64));

        let mut matrix = SparseMatrix::new(10, 1000);
        matrix.grow(10, 1000);

        for row in 0..10 {
            for col_offset in 0..20 {
                matrix.set(row, row * 50 + col_offset, val);
            }
        }

        let serialized = postcard::to_allocvec(&matrix).expect("serialization failed");

        let col_count = matrix.col_indices.len();
        let naive_col_bytes = col_count * 4;
        let actual_bytes = serialized.len();

        assert!(
            actual_bytes < naive_col_bytes,
            "delta encoding should reduce size: actual {} vs naive col bytes {}",
            actual_bytes,
            naive_col_bytes
        );
    }
}
