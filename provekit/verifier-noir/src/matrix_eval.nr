// R1CS Matrix MLE Evaluation
//
// Implements the EQ polynomial precomputation and sparse matrix x EQ evaluation.
//
// Reference:
//   provekit/common/src/utils/sumcheck.rs (multiply_transposed_by_eq_alpha)
//   recursive-verifier/app/circuit/matrix_evaluation.go (calculateEQOverBooleanHypercube)

use crate::types::MatrixCell;

// Compute EQ(r, x) over the boolean hypercube {0,1}^k.
//
// EQ(r, x) = prod_i (r_i * x_i + (1 - r_i) * (1 - x_i))
//
// Returns an array of 2^k values, one for each x in {0,1}^k.
//
// Algorithm (from gnark calculateEQOverBooleanHypercube):
//   Start with [1]
//   For each challenge r_i:
//     Double the table:
//       first_half[j] *= (1 - r_i)
//       second_half[j] = old[j] * r_i
pub fn eq_over_hypercube<let K: u32, let SIZE: u32>(
    challenges: [Field; K],
) -> [Field; SIZE] {
    // SIZE should be 2^K -- the caller must ensure this.
    let mut table: [Field; SIZE] = [0; SIZE];
    table[0] = 1;
    let mut len: u32 = 1;

    for i in 0..K {
        let r = challenges[i];
        let one_minus_r = 1 - r;
        // Double the table
        for j in 0..SIZE {
            if (j as u32) < len {
                let old = table[j];
                table[j] = old * one_minus_r;
                table[len + j] = old * r;
            }
        }
        len *= 2;
    }

    table
}

// Compute the scalar EQ(a, b) for two equal-length point vectors.
//
//   EQ(a, b) = prod_i (a_i * b_i + (1 - a_i) * (1 - b_i))
pub fn calculate_eq<let K: u32>(a: [Field; K], b: [Field; K]) -> Field {
    let mut result: Field = 1;
    for i in 0..K {
        result *= a[i] * b[i] + (1 - a[i]) * (1 - b[i]);
    }
    result
}

// Evaluate the R1CS matrix extension at the given points.
//
// For each matrix M in {A, B, C}:
//   eval_M = sum_{(row, col, val) in M} val * eq_row[row] * eq_col[col]
pub fn evaluate_matrix_extension<let N_CELLS: u32, let ROW_SIZE: u32, let COL_SIZE: u32>(
    matrix: [MatrixCell; N_CELLS],
    n_cells: u32,
    eq_row: [Field; ROW_SIZE],
    eq_col: [Field; COL_SIZE],
) -> Field {
    let mut result: Field = 0;
    for i in 0..N_CELLS {
        if (i as u32) < n_cells {
            let cell = matrix[i];
            result += cell.val * eq_row[cell.row] * eq_col[cell.col];
        }
    }
    result
}

// Compute all three matrix evaluations at once.
pub fn evaluate_r1cs_matrices<let N_CELLS: u32, let ROW_SIZE: u32, let COL_SIZE: u32>(
    matrix_a: [MatrixCell; N_CELLS],
    a_len: u32,
    matrix_b: [MatrixCell; N_CELLS],
    b_len: u32,
    matrix_c: [MatrixCell; N_CELLS],
    c_len: u32,
    eq_row: [Field; ROW_SIZE],
    eq_col: [Field; COL_SIZE],
) -> [Field; 3] {
    let az = evaluate_matrix_extension(matrix_a, a_len, eq_row, eq_col);
    let bz = evaluate_matrix_extension(matrix_b, b_len, eq_row, eq_col);
    let cz = evaluate_matrix_extension(matrix_c, c_len, eq_row, eq_col);
    [az, bz, cz]
}
