pub use crate::types::Memory;
use {
    crate::types::{MatrixDimensions, SparkMatrix},
    ark_ff::Zero,
    provekit_common::{
        utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq, FieldElement,
    },
};

#[tracing::instrument(skip_all)]
pub fn alphas_from_spark(
    spark: &SparkMatrix,
    dims: &MatrixDimensions,
    alpha: &[FieldElement],
) -> [Vec<FieldElement>; 3] {
    let row_cnt = dims.num_rows / 2;
    let col_cnt = dims.num_cols / 2;

    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(alpha, row_cnt);

    let mut a = vec![FieldElement::zero(); col_cnt];
    let mut b = vec![FieldElement::zero(); col_cnt];
    let mut c = vec![FieldElement::zero(); col_cnt];

    for i in 0..spark.coo.val.len() {
        let v = spark.coo.val[i];
        if v.is_zero() {
            continue;
        }
        let r = spark.coo.row[i];
        let col = spark.coo.col[i];
        if r < row_cnt && col < col_cnt {
            a[col] += v * eq_alpha[r];
        } else if r < row_cnt {
            b[col - col_cnt] += v * eq_alpha[r];
        } else {
            c[col - col_cnt] += v * eq_alpha[r - row_cnt];
        }
    }

    [a, b, c]
}

#[tracing::instrument(skip_all)]
pub fn calculate_memory(
    b: FieldElement,
    point_row: &[FieldElement],
    point_col: &[FieldElement],
) -> Memory {
    let row_point: Vec<_> = std::iter::once(b)
        .chain(point_row.iter().copied())
        .collect();
    let col_point: Vec<_> = std::iter::once(b)
        .chain(point_col.iter().copied())
        .collect();
    Memory {
        eq_rx: calculate_evaluations_over_boolean_hypercube_for_eq(
            &row_point,
            1 << row_point.len(),
        ),
        eq_ry: calculate_evaluations_over_boolean_hypercube_for_eq(
            &col_point,
            1 << col_point.len(),
        ),
    }
}
