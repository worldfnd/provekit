pub use crate::types::Memory;
use provekit_common::{
    utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq, FieldElement,
};

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
