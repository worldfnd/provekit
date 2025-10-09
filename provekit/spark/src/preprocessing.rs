use {
    crate::types::{COOMatrix, EValuesForMatrix, Memory, SparkMatrix, TimeStamps},
    anyhow::Result,
    ark_ff::AdditiveGroup,
    provekit_common::{utils::next_power_of_two, FieldElement, R1CS},
    std::collections::BTreeMap,
};

/// Preprocesses R1CS matrices into SPARK's memory-checkable COO format.
///
/// Combines A, B, C matrix coordinates, pads to power-of-2, and generates
/// read/write timestamps for the memory checking protocol.
pub struct MatrixPreprocessor {
    pub row:                  Vec<FieldElement>,
    pub col:                  Vec<FieldElement>,
    pub val_a:                Vec<FieldElement>,
    pub val_b:                Vec<FieldElement>,
    pub val_c:                Vec<FieldElement>,
    pub read_row:             Vec<FieldElement>,
    pub read_col:             Vec<FieldElement>,
    pub final_row:            Vec<FieldElement>,
    pub final_col:            Vec<FieldElement>,
    pub original_num_entries: usize,
    pub padded_num_entries:   usize,
    /// Union of all non-zero coordinates across A, B, C
    combined_matrix_map:      BTreeMap<(usize, usize), FieldElement>,
}

impl MatrixPreprocessor {
    /// Constructs preprocessor from R1CS, computing union of matrix
    /// coordinates.
    ///
    /// This one-time preprocessing:
    /// - Merges coordinates from A, B, C matrices (some entries may be zero)
    /// - Pads to power-of-2 for efficient polynomial operations
    /// - Generates memory access timestamps for GPA protocol
    pub fn from_r1cs(r1cs: &R1CS) -> Result<Self> {
        // Union of all non-zero coordinates
        let mut combined_matrix_map: BTreeMap<(usize, usize), FieldElement> = r1cs
            .a()
            .iter()
            .map(|(coordinate, _)| (coordinate, FieldElement::ZERO))
            .collect();

        for (coordinate, _) in r1cs.b().iter() {
            combined_matrix_map
                .entry(coordinate)
                .or_insert(FieldElement::ZERO);
        }

        for (coordinate, _) in r1cs.c().iter() {
            combined_matrix_map
                .entry(coordinate)
                .or_insert(FieldElement::ZERO);
        }

        let original_num_entries = combined_matrix_map.keys().count();
        let padded_num_entries = 1 << next_power_of_two(original_num_entries);

        let mut row = Vec::with_capacity(padded_num_entries);
        let mut col = Vec::with_capacity(padded_num_entries);

        for (r, c) in combined_matrix_map.keys() {
            row.push(FieldElement::from(*r as u64));
            col.push(FieldElement::from(*c as u64));
        }

        let to_fill = padded_num_entries - original_num_entries;
        row.extend(std::iter::repeat(FieldElement::ZERO).take(to_fill));
        col.extend(std::iter::repeat(FieldElement::ZERO).take(to_fill));

        let mut val_a = vec![FieldElement::ZERO; padded_num_entries];
        let mut val_b = vec![FieldElement::ZERO; padded_num_entries];
        let mut val_c = vec![FieldElement::ZERO; padded_num_entries];

        // Merge-scan to populate individual matrix values
        let a_binding = r1cs.a();
        let b_binding = r1cs.b();
        let c_binding = r1cs.c();

        let mut a_iter = a_binding.iter();
        let mut b_iter = b_binding.iter();
        let mut c_iter = c_binding.iter();

        let mut a_cur = a_iter.next();
        let mut b_cur = b_iter.next();
        let mut c_cur = c_iter.next();

        for (index, coordinate) in combined_matrix_map.keys().enumerate() {
            if let Some((coord, value)) = a_cur {
                if coord == *coordinate {
                    val_a[index] = value;
                    a_cur = a_iter.next();
                }
            }

            if let Some((coord, value)) = b_cur {
                if coord == *coordinate {
                    val_b[index] = value;
                    b_cur = b_iter.next();
                }
            }

            if let Some((coord, value)) = c_cur {
                if coord == *coordinate {
                    val_c[index] = value;
                    c_cur = c_iter.next();
                }
            }
        }

        // Memory timestamps track access order for GPA protocol
        let mut read_row_counters = vec![0; r1cs.num_constraints()];
        let mut read_col_counters = vec![0; r1cs.num_witnesses()];
        let mut read_row = Vec::with_capacity(padded_num_entries);
        let mut read_col = Vec::with_capacity(padded_num_entries);

        for (r, c) in combined_matrix_map.keys() {
            read_row.push(FieldElement::from(read_row_counters[*r] as u64));
            read_col.push(FieldElement::from(read_col_counters[*c] as u64));
            read_row_counters[*r] += 1;
            read_col_counters[*c] += 1;
        }

        // Padding entries all access row[0], col[0]
        for _ in 0..to_fill {
            read_row.push(FieldElement::from(read_row_counters[0] as u64));
            read_col.push(FieldElement::from(read_col_counters[0] as u64));
            read_row_counters[0] += 1;
            read_col_counters[0] += 1;
        }

        let final_row = read_row_counters
            .iter()
            .map(|&x| FieldElement::from(x as u64))
            .collect::<Vec<_>>();

        let final_col = read_col_counters
            .iter()
            .map(|&x| FieldElement::from(x as u64))
            .collect::<Vec<_>>();

        Ok(Self {
            row,
            col,
            val_a,
            val_b,
            val_c,
            read_row,
            read_col,
            final_row,
            final_col,
            original_num_entries,
            padded_num_entries,
            combined_matrix_map,
        })
    }

    /// Combines A + α·B + α²·C into single SPARK matrix using batching
    /// randomness.
    pub fn to_spark_matrix(
        &self,
        r1cs: &R1CS,
        matrix_batching_randomness: FieldElement,
    ) -> SparkMatrix {
        let matrix_batching_randomness_sq = matrix_batching_randomness * matrix_batching_randomness;

        let mut combined_matrix_map = self.combined_matrix_map.clone();

        for (coordinate, value) in r1cs.a().iter() {
            combined_matrix_map.entry(coordinate).and_modify(|cur| {
                *cur += value;
            });
        }

        for (coordinate, value) in r1cs.b().iter() {
            combined_matrix_map.entry(coordinate).and_modify(|cur| {
                *cur += value * matrix_batching_randomness;
            });
        }

        for (coordinate, value) in r1cs.c().iter() {
            combined_matrix_map.entry(coordinate).and_modify(|cur| {
                *cur += value * matrix_batching_randomness_sq;
            });
        }

        let mut val = Vec::with_capacity(self.padded_num_entries);
        for value in combined_matrix_map.values() {
            val.push(*value);
        }
        let to_fill = self.padded_num_entries - self.original_num_entries;
        val.extend(std::iter::repeat(FieldElement::ZERO).take(to_fill));

        SparkMatrix {
            coo:        COOMatrix {
                row: self.row.clone(),
                col: self.col.clone(),
                val,
                val_a: self.val_a.clone(),
                val_b: self.val_b.clone(),
                val_c: self.val_c.clone(),
            },
            timestamps: TimeStamps {
                read_row:  self.read_row.clone(),
                read_col:  self.read_col.clone(),
                final_row: self.final_row.clone(),
                final_col: self.final_col.clone(),
            },
        }
    }

    /// Computes row and column evaluation vectors for the combined coordinates.
    ///
    /// For each entry at (r, c), stores eq(point_row, r) and eq(point_col, c).
    pub fn compute_e_values(&self, memory: &Memory) -> EValuesForMatrix {
        let mut e_rx = Vec::with_capacity(self.padded_num_entries);
        let mut e_ry = Vec::with_capacity(self.padded_num_entries);

        for (r, c) in self.combined_matrix_map.keys() {
            e_rx.push(memory.eq_rx[*r]);
            e_ry.push(memory.eq_ry[*c]);
        }

        let to_fill = self.padded_num_entries - self.original_num_entries;
        e_rx.extend(std::iter::repeat(memory.eq_rx[0]).take(to_fill));
        e_ry.extend(std::iter::repeat(memory.eq_ry[0]).take(to_fill));

        EValuesForMatrix { e_rx, e_ry }
    }
}
