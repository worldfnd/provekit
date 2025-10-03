use provekit_common::{
    spark::Point, utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq,
    FieldElement,
};

#[derive(Debug)]
pub struct Memory {
    pub eq_rx: Vec<FieldElement>,
    pub eq_ry: Vec<FieldElement>,
}

#[derive(Debug)]
pub struct EValuesForMatrix {
    pub e_rx: Vec<FieldElement>,
    pub e_ry: Vec<FieldElement>,
}

#[derive(Debug)]
pub struct EValues {
    pub a: EValuesForMatrix,
    pub b: EValuesForMatrix,
    pub c: EValuesForMatrix,
}

pub fn calculate_memory(point_to_evaluate: Point) -> Memory {
    Memory {
        eq_rx: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.row),
        eq_ry: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.col[1..])
            .iter()
            .map(|x| *x * (FieldElement::from(1) - point_to_evaluate.col[0]))
            .collect(),
    }
}
