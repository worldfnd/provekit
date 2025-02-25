#[allow(missing_docs)]
use whir::crypto::fields::Field256;
use ark_std::str::FromStr;
use serde::Deserialize;
use ark_std::ops::{Add, Mul};
use ruint_macro::uint;
use crate::skyscraper::skyscraper::uint_to_field;
use ark_std::{Zero, One};
use std::fs::File;


/// Convert vector string to vector field
pub fn stringvec_to_fieldvec(witness: &Vec<String>) -> Vec<Field256> {
    witness.iter().map(|x|{Field256::from_str(x).expect("Failed to create Field256 value from a string")}).collect()
}

fn matrix_cell_string_vec_to_matrix_cell_vec(arr: &Vec<MatrixCellWithStringValue>) -> Vec<MatrixCell> {
    arr.into_iter().map(|cell| {
        MatrixCell {
            signal: cell.signal,
            constraint: cell.constraint,
            value: Field256::from_str(&cell.value).expect("Failed to create Field256 value from a string"),
        }
    }).collect()
}

/// Calculates the degree of the next smallest power of two
pub fn next_power_of_two(n: usize) -> usize {
    let mut power = 1;
    let mut ans = 0;
    while power < n {
        power <<= 1;
        ans += 1;
    }
    ans
}

/// Pads the vector with 0 so that the number of elements in the vector is a power of 2
pub fn pad_to_power_of_two(mut witness: Vec<Field256>) -> Vec<Field256> {
    let target_len = next_power_of_two(witness.len());
    while witness.len() < 1<<target_len {
        witness.push(Field256::zero()); // Pad with zeros
    }
    witness
}

/// Calculates matrix-vector product 
pub fn calculate_matrix_vector_product(matrix_cells: &Vec<MatrixCell>, witness: &Vec<Field256>, num_constraints: usize)->Vec<Field256> {
    let mut witness_bound = vec![Field256::zero(); num_constraints as usize];
    for x in matrix_cells {
        let witness_cell = witness[x.signal as usize];
        witness_bound[x.constraint as usize] = witness_bound[x.constraint as usize].add(x.value.mul(witness_cell));
    }
    witness_bound
}

/// List of evaluations for eq(r, x) over the boolean hypercube
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(r: &Vec<Field256>) -> Vec<Field256> {
    let mut ans = vec![Field256::from(1)];
    for x in r.iter().rev() {
        let mut left: Vec<Field256> = ans.clone().into_iter().map(|y| {y * (Field256::one() - x)}).collect();
        let right: Vec<Field256> = ans.into_iter().map(|y| {y * x}).collect();
        left.extend(right);
        ans = left;
    }
    ans
}

/// 1/2 for the BN254
pub const HALF: Field256 = uint_to_field(uint!(10944121435919637611123202872628637544274182200208017171849102093287904247809_U256));

/// Matrix cell for sparse-representation. 
#[derive(Deserialize)]
pub struct MatrixCellWithStringValue {
    /// A constraint can be thought as a row of the matrix
    pub constraint: usize,

    /// A signal can be thought as a column of the matrix
    pub signal: usize,
    
    /// A numerical value of the cell of the matrix
    pub value: String,
}

/// Struct used to deserialize a JSON representation of R1CS
#[derive(Deserialize)]
pub struct R1CSWithWitnessWithStringValue {
    /// Number of public inputs
    pub num_public: usize,

    /// Number of variables
    pub num_variables: usize,

    /// Number of constraints 
    pub num_constraints: usize,

    /// A sparse representation of the matrix A of R1CS
    pub a: Vec<MatrixCellWithStringValue>,

    /// A sparse representation of the matrix B of R1CS
    pub b: Vec<MatrixCellWithStringValue>,

    /// A sparse representation of the matrix C of R1CS
    pub c: Vec<MatrixCellWithStringValue>,

    /// List of witnesses for the R1CS
    pub witnesses: Vec<Vec<String>>,
}

/// Matrix Cell where value is Field256 instead of a string
pub struct MatrixCell {
    /// A constraint can be thought as a row of the matrix
    pub constraint: usize,

    /// A signal can be thought as a column of the matrix
    pub signal: usize,
    
    /// A numerical value of the cell of the matrix
    pub value: Field256,
}

/// R1CS where Matrix Cell values are Field256 elements instead of strings
pub struct R1CS {
    /// Number of public inputs
    pub num_public: usize,

    /// Number of variables
    pub num_variables: usize,

    /// Number of constraints 
    pub num_constraints: usize,

    /// A sparse representation of the matrix A of R1CS
    pub a: Vec<MatrixCell>,

    /// A sparse representation of the matrix B of R1CS
    pub b: Vec<MatrixCell>,

    /// A sparse representation of the matrix C of R1CS
    pub c: Vec<MatrixCell>,
}


/// Evaluates a qubic polynomial on a value
pub fn eval_qubic_poly(poly: &Vec<Field256>, point: &Field256) -> Field256 {
    poly[0] + *point * (poly[1] + *point * (poly[2] + *point * poly[3]))
}

/// Parse R1CS matrices and the witness from a given file
pub fn parse_matrices_and_witness (file_path: &str) -> (R1CS, Vec<Field256>) {
    let file = File::open(file_path).expect("Failed to open file");
    let r1cs_with_witness_string: R1CSWithWitnessWithStringValue = serde_json::from_reader(file).expect("Failed to parse JSON with Serde");
    let r1cs = R1CS {
        num_constraints: r1cs_with_witness_string.num_constraints,
        num_public: r1cs_with_witness_string.num_public,
        num_variables: r1cs_with_witness_string.num_variables,
        a: matrix_cell_string_vec_to_matrix_cell_vec(&r1cs_with_witness_string.a),
        b: matrix_cell_string_vec_to_matrix_cell_vec(&r1cs_with_witness_string.b),
        c: matrix_cell_string_vec_to_matrix_cell_vec(&r1cs_with_witness_string.c),
    }; 
    let witness = stringvec_to_fieldvec(&r1cs_with_witness_string.witnesses[0]);
    (r1cs, witness)
}

/// Given a path to JSON file with sparce matrices and a witness, calculates matrix-vector multiplication and returns them
pub fn calculate_witness_bounds (r1cs: &R1CS, witness: Vec<Field256>) -> (Vec<Field256>, Vec<Field256>, Vec<Field256>, Vec<Field256>, usize) {
    let witness_bound_a = pad_to_power_of_two(calculate_matrix_vector_product(&r1cs.a, &witness, r1cs.num_constraints));
    let witness_bound_b = pad_to_power_of_two(calculate_matrix_vector_product(&r1cs.b, &witness, r1cs.num_constraints));
    let witness_bound_c = pad_to_power_of_two(calculate_matrix_vector_product(& r1cs.c, &witness, r1cs.num_constraints));
    // let witness = pad_to_power_of_two(witness);
    let m = next_power_of_two(witness_bound_a.len());
    (witness_bound_a, witness_bound_b, witness_bound_c, witness, m)
}

/// Calculates a dot product of two Field256 vectors
pub fn calculate_dot_product(a: &Vec<Field256>, b: &Vec<Field256>) -> Field256 {
    a.iter().zip(b.iter()).map(|(&a, &b)| (a * b)).sum()
}

/// Calculates eq(r, alpha)
pub fn calculate_eq(r: &Vec<Field256>, alpha: &Vec<Field256>) -> Field256 {
    r.iter().zip(alpha.iter()).fold(Field256::from(1), |acc, (&r, &alpha)|{
        acc * (r * alpha + (Field256::from(1) - r) * (Field256::from(1)-alpha))
    })
}