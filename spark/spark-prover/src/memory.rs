use {
    crate::utilities::Point,
    noir_r1cs::{
        utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq, FieldElement,
        HydratedSparseMatrix, R1CS,
    },
};

#[derive(Debug)]
pub struct Memory {
    eq_rx: Vec<FieldElement>,
    eq_ry: Vec<FieldElement>,
}

#[derive(Debug)]
pub struct EValuesForMatrix {
    e_rx: Vec<FieldElement>,
    e_ry: Vec<FieldElement>,
}

#[derive(Debug)]
pub struct EValues {
    a: EValuesForMatrix,
    b: EValuesForMatrix,
    c: EValuesForMatrix,
}

pub fn calculate_memory(point_to_evaluate: Point) -> Memory {
    Memory {
        eq_rx: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.row),
        eq_ry: calculate_evaluations_over_boolean_hypercube_for_eq(&point_to_evaluate.col),
    }
}

pub fn calculate_e_values_for_r1cs(memory: &Memory, r1cs: &R1CS) -> EValues {
    EValues {
        a: calculate_e_values_for_matrix(memory, &r1cs.a()),
        b: calculate_e_values_for_matrix(memory, &r1cs.b()),
        c: calculate_e_values_for_matrix(memory, &r1cs.c()),
    }
}

pub fn calculate_e_values_for_matrix(
    memory: &Memory,
    matrix: &HydratedSparseMatrix,
) -> EValuesForMatrix {
    let mut e_rx = Vec::<FieldElement>::new();
    let mut e_ry = Vec::<FieldElement>::new();

    for ((r, c), _) in matrix.iter() {
        e_rx.push(memory.eq_rx[r]);
        e_ry.push(memory.eq_ry[c]);
    }
    EValuesForMatrix { e_rx, e_ry }
}
