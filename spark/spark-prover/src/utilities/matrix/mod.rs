use noir_r1cs::{FieldElement, HydratedSparseMatrix, SparseMatrix, R1CS};

#[derive(Debug)]
pub struct SparkR1CS {
    pub a: SparkMatrix,
    pub b: SparkMatrix,
    pub c: SparkMatrix,
}
#[derive(Debug)]
pub struct SparkMatrix {
    pub coo:        COOMatrix,
    pub timestamps: TimeStamps,
}
#[derive(Debug)]
pub struct COOMatrix {
    pub row: Vec<FieldElement>,
    pub col: Vec<FieldElement>,
    pub val: Vec<FieldElement>,
}
#[derive(Debug)]
pub struct TimeStamps {
    pub read_row:  Vec<FieldElement>,
    pub read_col:  Vec<FieldElement>,
    pub final_row: Vec<FieldElement>,
    pub final_col: Vec<FieldElement>,
}

pub fn get_spark_r1cs(r1cs: R1CS) -> SparkR1CS {
    SparkR1CS {
        a: get_spark_matrix(&r1cs.a()),
        b: get_spark_matrix(&r1cs.b()),
        c: get_spark_matrix(&r1cs.c()),
    }
}

pub fn get_spark_matrix(matrix: &HydratedSparseMatrix) -> SparkMatrix {
    SparkMatrix {
        coo:        get_coordinate_rep_of_a_matrix(matrix),
        timestamps: calculate_timestamps(matrix),
    }
}

pub fn get_coordinate_rep_of_a_matrix(matrix: &HydratedSparseMatrix) -> COOMatrix {
    let mut row = Vec::<FieldElement>::new();
    let mut col = Vec::<FieldElement>::new();
    let mut val = Vec::<FieldElement>::new();

    for ((r, c), value) in matrix.iter() {
        row.push(FieldElement::from(r as u64));
        col.push(FieldElement::from(c as u64));
        val.push(value.clone());
    }

    COOMatrix { row, col, val }
}

pub fn calculate_timestamps(matrix: &HydratedSparseMatrix) -> TimeStamps {
    let mut read_row_counters = vec![0; matrix.matrix.num_rows];
    let mut read_row = Vec::<FieldElement>::new();
    let mut read_col_counters = vec![0; matrix.matrix.num_cols];
    let mut read_col = Vec::<FieldElement>::new();

    for ((r, c), _) in matrix.iter() {
        read_row.push(FieldElement::from(read_row_counters[r] as u64));
        read_row_counters[r] += 1;
        read_col.push(FieldElement::from(read_col_counters[c] as u64));
        read_col_counters[c] += 1;
    }

    let final_row = read_row_counters
        .iter()
        .map(|&x| FieldElement::from(x as u64))
        .collect::<Vec<_>>();

    let final_col = read_col_counters
        .iter()
        .map(|&x| FieldElement::from(x as u64))
        .collect::<Vec<_>>();

    TimeStamps {
        read_row,
        read_col,
        final_row,
        final_col,
    }
}
